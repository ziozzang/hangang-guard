//! Source adapter predicates. No API collection or enforcement activation yet.
use anyhow::{Result, ensure};
use guard_core::selector::{LabelSelector, Operator, Requirement};
use serde::Deserialize;
use std::collections::BTreeMap;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Selector {
    #[serde(default)]
    match_labels: BTreeMap<String, String>,
    #[serde(default)]
    match_expressions: Vec<Expression>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Expression {
    key: String,
    operator: String,
    #[serde(default)]
    values: Vec<String>,
}
fn label_value(value: &str) -> bool {
    value.is_empty() || qualified_name(value)
}
fn qualified_name(value: &str) -> bool {
    let bytes = value.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= 63
        && bytes[0].is_ascii_alphanumeric()
        && bytes[bytes.len() - 1].is_ascii_alphanumeric()
        && bytes
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(b))
}
fn label_key(value: &str) -> bool {
    match value.split_once('/') {
        None => qualified_name(value),
        Some((prefix, name)) => {
            !prefix.is_empty()
                && prefix.len() <= 253
                && qualified_name(name)
                && prefix.split('.').all(|part| {
                    let bytes = part.as_bytes();
                    !bytes.is_empty()
                        && (bytes[0].is_ascii_lowercase() || bytes[0].is_ascii_digit())
                        && (bytes[bytes.len() - 1].is_ascii_lowercase()
                            || bytes[bytes.len() - 1].is_ascii_digit())
                        && bytes
                            .iter()
                            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'-')
                })
        }
    }
}
pub(crate) fn compile_selector(bytes: &[u8]) -> Result<LabelSelector> {
    ensure!(bytes.len() <= 65536, "selector document too large");
    let input: Selector = serde_json::from_slice(bytes)?;
    ensure!(
        input.match_labels.len() + input.match_expressions.len() <= 256,
        "selector too large"
    );
    let mut requirements = Vec::new();
    for (key, value) in input.match_labels {
        ensure!(
            label_key(&key) && label_value(&value),
            "invalid Kubernetes label syntax"
        );
        requirements.push(Requirement::new(key, Operator::In, vec![value])?);
    }
    for expression in input.match_expressions {
        ensure!(
            label_key(&expression.key) && expression.values.iter().all(|v| label_value(v)),
            "invalid Kubernetes label syntax"
        );
        let operator = match expression.operator.as_str() {
            "In" => Operator::In,
            "NotIn" => Operator::NotIn,
            "Exists" => Operator::Exists,
            "DoesNotExist" => Operator::DoesNotExist,
            _ => anyhow::bail!("unsupported label selector operator"),
        };
        requirements.push(Requirement::new(
            expression.key,
            operator,
            expression.values,
        )?);
    }
    LabelSelector::compile(requirements)
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct OfflineEvaluation {
    policy: serde_json::Value,
    namespace: String,
    labels: BTreeMap<String, String>,
    direction: String,
    peer: String,
    protocol: String,
    port: u16,
}
use guard_core::network_policy::{NetworkDecision, SelectedDirection, Transport};

#[derive(Clone)]
struct CompiledPolicy {
    namespace: String,
    target: LabelSelector,
    incoming: SelectedDirection,
    outgoing: SelectedDirection,
}
#[derive(Clone, Copy)]
enum Direction {
    Ingress,
    Egress,
}
impl CompiledPolicy {
    /// Caller supplies authoritative target labels; no parsing or I/O occurs here.
    fn decide(
        &self,
        namespace: &str,
        labels: &BTreeMap<String, String>,
        direction: Direction,
        peer: std::net::IpAddr,
        protocol: Transport,
        port: u16,
    ) -> &'static str {
        if self.namespace != namespace || !self.target.matches(labels) {
            return "not_selected";
        }
        let view = match direction {
            Direction::Ingress => &self.incoming,
            Direction::Egress => &self.outgoing,
        };
        match view.decide(peer, protocol, port) {
            NetworkDecision::NotIsolated => "not_isolated",
            NetworkDecision::Allowed => "allowed",
            NetworkDecision::Denied => "denied",
        }
    }
}
#[derive(Clone)]
struct CompiledPolicySet {
    policies: Vec<CompiledPolicy>,
}
impl CompiledPolicySet {
    fn compile(source: &serde_json::Value) -> Result<Self> {
        if source["kind"] != "NetworkPolicyList" {
            return Ok(Self {
                policies: vec![compile_policy(source)?],
            });
        }
        ensure!(
            source["apiVersion"] == "networking.k8s.io/v1",
            "wrong policy list version"
        );
        if let Some(continuation) = source["metadata"].get("continue") {
            ensure!(
                continuation.as_str() == Some(""),
                "partial policy list cannot be authoritative"
            );
        }
        let items = source["items"]
            .as_array()
            .ok_or_else(|| anyhow::anyhow!("policy list items required"))?;
        ensure!(items.len() <= 4096, "too many network policies");
        let mut policies = Vec::with_capacity(items.len());
        for item in items {
            policies.push(compile_policy(item)?);
        }
        Ok(Self { policies })
    }
    fn decide(
        &self,
        namespace: &str,
        labels: &BTreeMap<String, String>,
        direction: Direction,
        peer: std::net::IpAddr,
        protocol: Transport,
        port: u16,
    ) -> &'static str {
        let mut selected = false;
        let mut isolated = false;
        for policy in &self.policies {
            match policy.decide(namespace, labels, direction, peer, protocol, port) {
                "allowed" => return "allowed",
                "denied" => {
                    selected = true;
                    isolated = true;
                }
                "not_isolated" => selected = true,
                "not_selected" => {}
                _ => unreachable!("compiled policy decision"),
            }
        }
        if isolated {
            "denied"
        } else if selected {
            "not_isolated"
        } else {
            "not_selected"
        }
    }
}
fn transport(value: &str) -> Result<Transport> {
    match value {
        "TCP" => Ok(Transport::Tcp),
        "UDP" => Ok(Transport::Udp),
        "SCTP" => Ok(Transport::Sctp),
        _ => anyhow::bail!("unsupported transport"),
    }
}
/// Compile off the request path. Selector peers and named ports remain refused.
fn compile_policy(policy: &serde_json::Value) -> Result<CompiledPolicy> {
    use guard_core::network_policy::{IpBlock, NetworkRule, PortRange};
    use serde_json::Value;
    ensure!(
        policy["apiVersion"] == "networking.k8s.io/v1" && policy["kind"] == "NetworkPolicy",
        "wrong policy kind/version"
    );
    let namespace = policy["metadata"]["namespace"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("policy namespace required"))?;
    let spec = policy["spec"]
        .as_object()
        .ok_or_else(|| anyhow::anyhow!("policy spec required"))?;
    ensure!(
        spec.keys()
            .all(|k| ["podSelector", "policyTypes", "ingress", "egress"].contains(&k.as_str())),
        "unsupported policy field"
    );
    let target = compile_selector(&serde_json::to_vec(
        spec.get("podSelector")
            .ok_or_else(|| anyhow::anyhow!("podSelector required"))?,
    )?)?;
    let list = |key: &str| -> Result<Vec<Value>> {
        match spec.get(key) {
            None => Ok(vec![]),
            Some(Value::Array(values)) => {
                ensure!(values.len() <= 4096, "too many policy rules");
                Ok(values.clone())
            }
            _ => anyhow::bail!("policy rule list required"),
        }
    };
    let ingress = list("ingress")?;
    let egress = list("egress")?;
    let (isolate_ingress, isolate_egress) = match spec.get("policyTypes") {
        None => (true, !egress.is_empty()),
        Some(Value::Array(types)) if types.is_empty() => (true, !egress.is_empty()),
        Some(Value::Array(types)) => {
            ensure!(
                types.len() <= 2 && types.iter().all(|t| t == "Ingress" || t == "Egress"),
                "invalid policyTypes"
            );
            ensure!(
                types.len() != 2 || types[0] != types[1],
                "duplicate policyTypes"
            );
            (
                types.iter().any(|t| t == "Ingress"),
                types.iter().any(|t| t == "Egress"),
            )
        }
        _ => anyhow::bail!("invalid policyTypes"),
    };
    let compile_rules = |rules: Vec<Value>, peer_key: &str| -> Result<Vec<NetworkRule>> {
        let mut compiled = Vec::new();
        for rule in rules {
            let rule = rule
                .as_object()
                .ok_or_else(|| anyhow::anyhow!("rule must be object"))?;
            ensure!(
                rule.keys().all(|k| k == peer_key || k == "ports"),
                "unsupported rule field"
            );
            let mut peers = Vec::new();
            if let Some(values) = rule.get(peer_key) {
                let values = values
                    .as_array()
                    .ok_or_else(|| anyhow::anyhow!("peer list required"))?;
                ensure!(values.len() <= 4096, "too many peers");
                for peer in values {
                    let peer = peer
                        .as_object()
                        .ok_or_else(|| anyhow::anyhow!("peer object required"))?;
                    ensure!(
                        peer.len() == 1 && peer.contains_key("ipBlock"),
                        "selector/all peers require explicit resolution"
                    );
                    let block = peer["ipBlock"]
                        .as_object()
                        .ok_or_else(|| anyhow::anyhow!("ipBlock required"))?;
                    ensure!(
                        block.keys().all(|k| k == "cidr" || k == "except"),
                        "unsupported ipBlock field"
                    );
                    let cidr = block
                        .get("cidr")
                        .and_then(Value::as_str)
                        .ok_or_else(|| anyhow::anyhow!("CIDR required"))?;
                    let except: Vec<String> = match block.get("except") {
                        None => vec![],
                        Some(v) => serde_json::from_value(v.clone())?,
                    };
                    peers.push(IpBlock::compile(cidr, &except)?);
                }
            }
            let mut ports = Vec::new();
            if let Some(values) = rule.get("ports") {
                let values = values
                    .as_array()
                    .ok_or_else(|| anyhow::anyhow!("ports list required"))?;
                ensure!(values.len() <= 4096, "too many ports");
                for port in values {
                    let port = port
                        .as_object()
                        .ok_or_else(|| anyhow::anyhow!("port object required"))?;
                    ensure!(
                        port.keys()
                            .all(|k| ["protocol", "port", "endPort"].contains(&k.as_str())),
                        "unsupported port field"
                    );
                    let protocol = transport(match port.get("protocol") {
                        None => "TCP",
                        Some(v) => v
                            .as_str()
                            .ok_or_else(|| anyhow::anyhow!("invalid protocol"))?,
                    })?;
                    let number = |v: &Value| -> Result<u16> {
                        Ok(u16::try_from(v.as_u64().ok_or_else(|| {
                            anyhow::anyhow!("numeric port required")
                        })?)?)
                    };
                    let (first, last) = match port.get("port") {
                        None => {
                            ensure!(!port.contains_key("endPort"), "endPort without port");
                            (1, 65535)
                        }
                        Some(v) => {
                            let first = number(v)?;
                            let last = match port.get("endPort") {
                                None => first,
                                Some(v) => number(v)?,
                            };
                            (first, last)
                        }
                    };
                    ports.push(PortRange::new(protocol, first, last)?);
                }
            }
            compiled.push(NetworkRule::new(peers, ports)?);
        }
        Ok(compiled)
    };
    let incoming = compile_rules(ingress, "from")?;
    let outgoing = compile_rules(egress, "to")?;
    ensure!(
        isolate_ingress || incoming.is_empty(),
        "ingress rules without ingress policy type"
    );
    ensure!(
        isolate_egress || outgoing.is_empty(),
        "egress rules without egress policy type"
    );
    let incoming = SelectedDirection::compile(isolate_ingress, incoming)?;
    let outgoing = SelectedDirection::compile(isolate_egress, outgoing)?;
    Ok(CompiledPolicy {
        namespace: namespace.to_owned(),
        target,
        incoming,
        outgoing,
    })
}

pub(crate) fn evaluate_policy(bytes: &[u8]) -> Result<&'static str> {
    ensure!(
        bytes.len() <= 1024 * 1024,
        "policy evaluation document too large"
    );
    let query: OfflineEvaluation = serde_json::from_slice(bytes)?;
    let compiled = CompiledPolicySet::compile(&query.policy)?;
    let direction = match query.direction.as_str() {
        "Ingress" => Direction::Ingress,
        "Egress" => Direction::Egress,
        _ => anyhow::bail!("invalid direction"),
    };
    Ok(compiled.decide(
        &query.namespace,
        &query.labels,
        direction,
        guard_core::canonical_ip(&query.peer)?,
        transport(&query.protocol)?,
        query.port,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    fn query(spec: serde_json::Value) -> serde_json::Value {
        serde_json::json!({"policy":{"apiVersion":"networking.k8s.io/v1","kind":"NetworkPolicy","metadata":{"namespace":"blue"},"spec":spec},"namespace":"blue","labels":{"role":"client"},"direction":"Ingress","peer":"192.0.2.70","protocol":"TCP","port":443})
    }
    fn evaluate(value: &serde_json::Value) -> Result<&'static str> {
        evaluate_policy(&serde_json::to_vec(value)?)
    }
    #[test]
    fn late_synchronous_compilation_cannot_create_source_snapshot() {
        let source = query(serde_json::json!({"podSelector":{},"ingress":[{}]}));
        let compile = || CompiledPolicySet::compile(&source["policy"]).unwrap();
        let now = std::time::Instant::now();
        assert!(SourceSnapshot::from_collection(compile(), "opaque".into(), now).is_ok());
        let old = now.checked_sub(std::time::Duration::from_secs(2)).unwrap();
        assert!(SourceSnapshot::from_collection(compile(), "opaque".into(), old).is_err());
    }
    #[test]
    fn source_snapshot_expiry_fences_retained_candidate() {
        let source = query(serde_json::json!({"podSelector":{},"ingress":[{}]}));
        let mut snapshot = SourceSnapshot {
            compiled: CompiledPolicySet::compile(&source["policy"]).unwrap(),
            revision: "opaque".into(),
            expires: std::time::Instant::now() + std::time::Duration::from_secs(1),
        };
        let q = || SourceQuery {
            namespace: "blue".into(),
            labels: BTreeMap::new(),
            direction: "Ingress".into(),
            peer: "192.0.2.1".into(),
            protocol: "TCP".into(),
            port: 443,
        };
        assert_eq!(snapshot.evaluate(q()).unwrap()["decision"], "allowed");
        snapshot.expires = std::time::Instant::now();
        assert!(snapshot.evaluate(q()).is_err());
        assert_eq!(snapshot.report()["fresh"], false);
    }
    #[tokio::test]
    async fn stopped_source_follower_withdraws_existing_snapshot() {
        let source = query(serde_json::json!({"podSelector":{},"ingress":[{}]}));
        let snapshot = SourceSnapshot {
            compiled: CompiledPolicySet::compile(&source["policy"]).unwrap(),
            revision: "opaque".into(),
            expires: std::time::Instant::now() + std::time::Duration::from_secs(1),
        };
        let snapshots = std::sync::Arc::new(arc_swap::ArcSwapOption::new(Some(
            std::sync::Arc::new(snapshot),
        )));
        let (_stop, rx) = tokio::sync::watch::channel(true);
        follow_source(
            std::path::PathBuf::from("/unused"),
            snapshots.clone(),
            std::sync::Arc::new(std::sync::atomic::AtomicU8::new(0)),
            rx,
        )
        .await;
        assert!(snapshots.load_full().is_none());
    }
    #[test]
    fn policy_list_is_additive_without_unselected_or_opposite_direction_bypass() {
        let deny = query(serde_json::json!({"podSelector":{},"policyTypes":["Ingress"]}))["policy"]
            .clone();
        let allow = query(
            serde_json::json!({"podSelector":{},"ingress":[{"ports":[{"port":443}]}]}),
        )["policy"]
            .clone();
        let other = query(
            serde_json::json!({"podSelector":{"matchLabels":{"role":"other"}},"ingress":[{}]}),
        )["policy"]
            .clone();
        let egress = query(
            serde_json::json!({"podSelector":{},"policyTypes":["Egress"],"egress":[{}]}),
        )["policy"]
            .clone();
        let mut q = query(serde_json::json!({"podSelector":{}}));
        q["policy"] = serde_json::json!({"apiVersion":"networking.k8s.io/v1","kind":"NetworkPolicyList","items":[deny,other,egress]});
        assert_eq!(evaluate(&q).unwrap(), "denied");
        q["policy"]["items"].as_array_mut().unwrap().push(allow);
        assert_eq!(evaluate(&q).unwrap(), "allowed");
        q["port"] = 444.into();
        assert_eq!(evaluate(&q).unwrap(), "denied");
        q["policy"]["metadata"] = serde_json::json!({"continue":"next-page"});
        assert!(evaluate(&q).is_err());
        q["policy"]["metadata"] = serde_json::json!({"continue":""});
        q["policy"]["items"] = serde_json::json!([]);
        assert_eq!(evaluate(&q).unwrap(), "not_selected");
        q["policy"]["items"] = serde_json::json!([{"kind":"Other"}]);
        assert!(evaluate(&q).is_err());
    }
    #[test]
    fn compiled_policy_owns_immutable_candidate_and_reuses_decisions() {
        let mut source =
            query(serde_json::json!({"podSelector":{},"ingress":[{"ports":[{"port":443}]}]}));
        let old = compile_policy(&source["policy"]).unwrap();
        source["policy"]["spec"]["ingress"] = serde_json::json!([]);
        let next = compile_policy(&source["policy"]).unwrap();
        let labels = BTreeMap::new();
        let peer = "192.0.2.1".parse().unwrap();
        for _ in 0..1000 {
            assert_eq!(
                old.decide(
                    "blue",
                    &labels,
                    Direction::Ingress,
                    peer,
                    Transport::Tcp,
                    443
                ),
                "allowed"
            );
            assert_eq!(
                next.decide(
                    "blue",
                    &labels,
                    Direction::Ingress,
                    peer,
                    Transport::Tcp,
                    443
                ),
                "denied"
            );
        }
        source["policy"]["spec"]["ingress"] = serde_json::json!([{"unsupported":true}]);
        assert!(compile_policy(&source["policy"]).is_err());
        assert_eq!(
            old.decide(
                "blue",
                &labels,
                Direction::Ingress,
                peer,
                Transport::Tcp,
                444
            ),
            "denied"
        );
    }
    #[test]
    fn policy_direction_defaults_and_empty_rules() {
        let mut q = query(serde_json::json!({"podSelector":{}}));
        assert_eq!(evaluate(&q).unwrap(), "denied");
        q["direction"] = "Egress".into();
        assert_eq!(evaluate(&q).unwrap(), "not_isolated");
        q["policy"]["spec"]["egress"] = serde_json::json!([{}]);
        assert_eq!(evaluate(&q).unwrap(), "allowed");
        q["policy"]["spec"]["egress"] = serde_json::json!([]);
        q["policy"]["spec"]["policyTypes"] = serde_json::json!(["Egress"]);
        assert_eq!(evaluate(&q).unwrap(), "denied");
        q["namespace"] = "other".into();
        assert_eq!(evaluate(&q).unwrap(), "not_selected");
    }
    #[test]
    fn policy_ipblock_and_ports_are_evaluated_together() {
        let mut q = query(
            serde_json::json!({"podSelector":{"matchLabels":{"role":"client"}},"ingress":[{"from":[{"ipBlock":{"cidr":"192.0.2.0/24","except":["192.0.2.64/26"]}}]},{"from":[{"ipBlock":{"cidr":"192.0.2.64/26"}}],"ports":[{"port":443,"endPort":444}]}]}),
        );
        assert_eq!(evaluate(&q).unwrap(), "allowed");
        q["port"] = 445.into();
        assert_eq!(evaluate(&q).unwrap(), "denied");
        q["port"] = 443.into();
        q["protocol"] = "UDP".into();
        assert_eq!(evaluate(&q).unwrap(), "denied");
        q["peer"] = "192.0.2.1".into();
        assert_eq!(evaluate(&q).unwrap(), "allowed");
        q["labels"]["role"] = "server".into();
        assert_eq!(evaluate(&q).unwrap(), "not_selected");
    }
    #[test]
    fn unsupported_policy_never_becomes_wildcard() {
        for rule in [
            serde_json::json!({"from":[{"podSelector":{}}]}),
            serde_json::json!({"from":[{}]}),
            serde_json::json!({"ports":[{"port":"https"}]}),
            serde_json::json!({"ports":[{"endPort":443}]}),
            serde_json::json!({"ports":[{"port":0}]}),
            serde_json::json!({"unknown":true}),
        ] {
            assert!(
                evaluate(&query(
                    serde_json::json!({"podSelector":{},"ingress":[rule]})
                ))
                .is_err()
            );
        }
    }
    #[test]
    fn kubernetes_label_syntax_boundaries() {
        for key in [
            "app",
            "app.example.test/Role_1",
            "kubernetes.io/metadata.name",
            "A",
        ] {
            assert!(label_key(key));
        }
        for key in [
            "",
            "-app",
            "app/",
            "/app",
            "UPPER.test/app",
            "a..test/app",
            "a/b/c",
            "é",
            "a.test/-app",
        ] {
            assert!(!label_key(key));
        }
        assert!(label_key(&format!("{}/role", "a".repeat(64))));
        assert!(label_key(&format!("{}/role", "a".repeat(253))));
        assert!(!label_key(&format!("{}/role", "a".repeat(254))));
        assert!(label_key(&"a".repeat(63)));
        assert!(!label_key(&"a".repeat(64)));
        for value in ["", "Client_1", "a.b-c"] {
            assert!(label_value(value));
        }
        for value in ["-a", "a_", "a b", "é"] {
            assert!(!label_value(value));
        }
        assert!(!label_value(&"a".repeat(64)));
        assert!(compile_selector(br#"{"matchLabels":{"bad/key/extra":"value"}}"#).is_err());
        assert!(
            compile_selector(
                br#"{"matchExpressions":[{"key":"app","operator":"In","values":["bad value"]}]}"#
            )
            .is_err()
        );
    }
    #[test]
    fn source_shape_is_not_silently_broadened() {
        let selector=compile_selector(br#"{"matchLabels":{"role":"client"},"matchExpressions":[{"key":"disabled","operator":"DoesNotExist"}]}"#).unwrap();
        let mut labels = BTreeMap::from([("role".into(), "client".into())]);
        assert!(selector.matches(&labels));
        labels.insert("disabled".into(), "".into());
        assert!(!selector.matches(&labels));
        for invalid in [
            br#"{"matchExpression":[]}"#.as_slice(),
            br#"{"matchExpressions":[{"key":"role","operator":"Gt","values":["1"]}]}"#,
            br#"{"matchExpressions":[{"key":"role","operator":"Exists","values":["x"]}]}"#,
            br#"{"matchLabels":null}"#,
        ] {
            assert!(compile_selector(invalid).is_err());
        }
        assert!(compile_selector(&vec![b' '; 65537]).is_err());
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SourceConfig {
    api: String,
    namespace: String,
    ca: std::path::PathBuf,
    token_env: String,
}
struct CachedTransport {
    ca: Vec<u8>,
    credential: reqwest::header::HeaderValue,
    origin: String,
    client: reqwest::Client,
}
#[derive(Default)]
struct SourceTransport {
    cached: Option<CachedTransport>,
}
impl SourceTransport {
    fn client(
        &mut self,
        ca: &[u8],
        credential: &reqwest::header::HeaderValue,
        origin: &str,
    ) -> Result<reqwest::Client> {
        if let Some(cached) = &self.cached
            && cached.ca == ca
            && cached.credential == *credential
            && cached.origin == origin
        {
            return Ok(cached.client.clone());
        }
        // Drop old authority material before constructing its replacement.
        self.cached = None;
        let client = reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .tls_built_in_root_certs(false)
            .add_root_certificate(reqwest::Certificate::from_pem(ca)?)
            .timeout(std::time::Duration::from_millis(1000))
            .pool_max_idle_per_host(2)
            .pool_idle_timeout(std::time::Duration::from_secs(10))
            .build()?;
        let mut credential = credential.clone();
        credential.set_sensitive(true);
        self.cached = Some(CachedTransport {
            ca: ca.to_vec(),
            credential,
            origin: origin.to_owned(),
            client: client.clone(),
        });
        Ok(client)
    }
}
/// Read-only collection. Publication and request-time authority are separate gates.
async fn collect_source(bytes: &[u8], transport: &mut SourceTransport) -> Result<SourceSnapshot> {
    let started = std::time::Instant::now();
    use std::time::Duration;
    let source: SourceConfig = serde_json::from_slice(bytes)?;
    let mut url = reqwest::Url::parse(&source.api)?;
    ensure!(
        url.scheme() == "https"
            && url.host_str().is_some()
            && url.username().is_empty()
            && url.password().is_none()
            && url.query().is_none()
            && url.fragment().is_none()
            && url.path() == "/",
        "API must be an HTTPS origin"
    );
    ensure!(
        !source.namespace.is_empty()
            && source.namespace.len() <= 63
            && source
                .namespace
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
            && !source.namespace.starts_with('-')
            && !source.namespace.ends_with('-'),
        "invalid source namespace"
    );
    ensure!(
        !source.token_env.is_empty()
            && source.token_env.len() <= 128
            && source
                .token_env
                .bytes()
                .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_'),
        "invalid token environment reference"
    );
    let secret = std::env::var(&source.token_env)
        .map_err(|_| anyhow::anyhow!("source token unavailable"))?;
    ensure!(
        !secret.is_empty() && secret.len() <= 16384 && !secret.chars().any(char::is_whitespace),
        "invalid source token"
    );
    let mut authorization = reqwest::header::HeaderValue::from_str(&format!("Bearer {secret}"))?;
    authorization.set_sensitive(true);
    let ca = crate::read_bounded(&source.ca, 128 * 1024)?;
    let client = transport.client(&ca, &authorization, url.as_str())?;
    url.set_path(&format!(
        "/apis/networking.k8s.io/v1/namespaces/{}/networkpolicies",
        source.namespace
    ));
    let collection = async {
        let mut items = Vec::new();
        let mut continuation = String::new();
        let mut seen = std::collections::BTreeSet::new();
        let mut revision = None;
        let mut total = 0usize;
        for _ in 0..32 {
            url.set_query(None);
            url.query_pairs_mut().append_pair("limit", "128");
            if !continuation.is_empty() {
                url.query_pairs_mut().append_pair("continue", &continuation);
            }
            let mut response = client
                .get(url.clone())
                .header(reqwest::header::AUTHORIZATION, authorization.clone())
                .send()
                .await
                .map_err(|_| anyhow::anyhow!("source request unavailable"))?;
            ensure!(response.status().is_success(), "source refused collection");
            let mut body = Vec::new();
            while let Some(chunk) = response
                .chunk()
                .await
                .map_err(|_| anyhow::anyhow!("source body unavailable"))?
            {
                total = total
                    .checked_add(chunk.len())
                    .ok_or_else(|| anyhow::anyhow!("source size overflow"))?;
                ensure!(total <= 1024 * 1024, "source collection too large");
                body.extend_from_slice(&chunk);
            }
            let page: serde_json::Value = serde_json::from_slice(&body)?;
            ensure!(
                page["kind"] == "NetworkPolicyList" && page["apiVersion"] == "networking.k8s.io/v1",
                "wrong source collection kind"
            );
            let rv = page["metadata"]["resourceVersion"]
                .as_str()
                .filter(|s| !s.is_empty() && s.len() <= 1024)
                .ok_or_else(|| anyhow::anyhow!("source revision missing"))?;
            if let Some(previous) = &revision {
                ensure!(previous == rv, "source revision changed between pages");
            } else {
                revision = Some(rv.to_owned());
            }
            let entries = page["items"]
                .as_array()
                .ok_or_else(|| anyhow::anyhow!("source items missing"))?;
            ensure!(
                items.len() + entries.len() <= 4096,
                "too many source policies"
            );
            for entry in entries {
                let mut item = entry.clone();
                ensure!(
                    item["metadata"]["namespace"] == source.namespace,
                    "source namespace mismatch"
                );
                let uid = item["metadata"]["uid"]
                    .as_str()
                    .filter(|v| !v.is_empty() && v.len() <= 128)
                    .ok_or_else(|| anyhow::anyhow!("source UID missing or oversized"))?;
                ensure!(seen.insert(format!("uid:{uid}")), "duplicate source UID");
                let name = item["metadata"]["name"]
                    .as_str()
                    .filter(|v| !v.is_empty() && v.len() <= 253)
                    .ok_or_else(|| anyhow::anyhow!("source object name missing or oversized"))?;
                ensure!(
                    seen.insert(format!("name:{name}")),
                    "duplicate source object name"
                );
                ensure!(
                    item["metadata"]["resourceVersion"]
                        .as_str()
                        .is_some_and(|v| !v.is_empty() && v.len() <= 1024),
                    "source object revision missing or oversized"
                );
                if item.get("kind").is_none() {
                    item["kind"] = "NetworkPolicy".into();
                }
                if item.get("apiVersion").is_none() {
                    item["apiVersion"] = "networking.k8s.io/v1".into();
                }
                items.push(item);
            }
            continuation = match page["metadata"].get("continue") {
                None => String::new(),
                Some(v) => v
                    .as_str()
                    .ok_or_else(|| anyhow::anyhow!("invalid source continuation"))?
                    .to_owned(),
            };
            ensure!(continuation.len() <= 8192, "source continuation too long");
            if continuation.is_empty() {
                let list = serde_json::json!({"kind":"NetworkPolicyList","apiVersion":"networking.k8s.io/v1","metadata":{"resourceVersion":revision,"continue":""},"items":items});
                let compiled = CompiledPolicySet::compile(&list)?;
                return SourceSnapshot::from_collection(compiled, revision.unwrap(), started);
            }
            ensure!(
                seen.insert(format!("page:{continuation}")),
                "source continuation cycle"
            );
        }
        anyhow::bail!("source page bound exceeded")
    };
    tokio::time::timeout(Duration::from_millis(1000), collection)
        .await
        .map_err(|_| anyhow::anyhow!("source collection deadline"))?
}

pub(crate) struct SourceSnapshot {
    compiled: CompiledPolicySet,
    revision: String,
    expires: std::time::Instant,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SourceQuery {
    namespace: String,
    labels: BTreeMap<String, String>,
    direction: String,
    peer: String,
    protocol: String,
    port: u16,
}
impl SourceSnapshot {
    fn from_collection(
        compiled: CompiledPolicySet,
        revision: String,
        started: std::time::Instant,
    ) -> Result<Self> {
        let expires = started
            .checked_add(std::time::Duration::from_millis(1000))
            .ok_or_else(|| anyhow::anyhow!("source deadline overflow"))?;
        ensure!(
            std::time::Instant::now() < expires,
            "source compilation exceeded freshness deadline"
        );
        Ok(Self {
            compiled,
            revision,
            expires,
        })
    }
    pub(crate) fn report(&self) -> serde_json::Value {
        serde_json::json!({"mode":"observe","policies":self.compiled.policies.len(),"resource_version":self.revision,"activated":false,"fresh":std::time::Instant::now()<self.expires})
    }
    pub(crate) fn evaluate(&self, query: SourceQuery) -> Result<serde_json::Value> {
        ensure!(
            std::time::Instant::now() < self.expires,
            "source snapshot expired"
        );
        ensure!(
            query.labels.len() <= 256
                && query
                    .labels
                    .iter()
                    .all(|(k, v)| label_key(k) && label_value(v)),
            "invalid target labels"
        );
        let direction = match query.direction.as_str() {
            "Ingress" => Direction::Ingress,
            "Egress" => Direction::Egress,
            _ => anyhow::bail!("invalid direction"),
        };
        let decision = self.compiled.decide(
            &query.namespace,
            &query.labels,
            direction,
            guard_core::canonical_ip(&query.peer)?,
            transport(&query.protocol)?,
            query.port,
        );
        ensure!(
            std::time::Instant::now() < self.expires,
            "source snapshot expired"
        );
        Ok(
            serde_json::json!({"decision":decision,"resource_version":self.revision,"activated":false}),
        )
    }
}
pub(crate) async fn observe_source(bytes: &[u8]) -> Result<serde_json::Value> {
    let mut transport = SourceTransport::default();
    Ok(collect_source(bytes, &mut transport).await?.report())
}
pub(crate) async fn follow_source(
    path: std::path::PathBuf,
    snapshots: std::sync::Arc<arc_swap::ArcSwapOption<SourceSnapshot>>,
    phase: std::sync::Arc<std::sync::atomic::AtomicU8>,
    mut stop: tokio::sync::watch::Receiver<bool>,
) {
    let mut transport = SourceTransport::default();
    loop {
        if *stop.borrow() {
            break;
        }
        // Conservative uncertainty fencing while a complete list is assembled.
        phase.store(1, std::sync::atomic::Ordering::Release);
        snapshots.store(None);
        let result = async {
            let bytes = crate::read_bounded(&path, 16384)?;
            collect_source(&bytes, &mut transport).await
        };
        tokio::select! {
            value=result => {
                if let Ok(snapshot)=value && std::time::Instant::now()<snapshot.expires {
                    snapshots.store(Some(std::sync::Arc::new(snapshot)));
                    phase.store(2,std::sync::atomic::Ordering::Release);
                } else {
                    transport.cached=None;
                    phase.store(3,std::sync::atomic::Ordering::Release);
                }
            },
            _=stop.changed()=>break,
        }
        tokio::select! { _=tokio::time::sleep(std::time::Duration::from_millis(500))=>{}, _=stop.changed()=>break }
    }
    snapshots.store(None);
    phase.store(4, std::sync::atomic::Ordering::Release);
}
