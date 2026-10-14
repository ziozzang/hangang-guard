//! Offline source parsing. Cross-resource coherence must be established separately.
use anyhow::{Result, ensure};
use guard_core::pod_peers::{NamespaceFact, PodFact};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};

fn text<'a>(value: &'a Value, key: &str, max: usize) -> Result<&'a str> {
    value[key]
        .as_str()
        .filter(|v| !v.is_empty() && v.len() <= max)
        .ok_or_else(|| anyhow::anyhow!("required bounded source field missing"))
}
fn labels(metadata: &Value) -> Result<BTreeMap<String, String>> {
    let labels = match metadata.get("labels") {
        None => BTreeMap::new(),
        Some(v) => serde_json::from_value::<BTreeMap<String, String>>(v.clone())?,
    };
    ensure!(
        labels.len() <= 256
            && labels
                .iter()
                .all(|(k, v)| super::label_key(k) && super::label_value(v)),
        "invalid source labels"
    );
    Ok(labels)
}
fn items<'a>(list: &'a Value, kind: &str) -> Result<&'a Vec<Value>> {
    ensure!(
        list["apiVersion"] == "v1" && list["kind"] == kind,
        "wrong fact collection kind/version"
    );
    text(&list["metadata"], "resourceVersion", 1024)?;
    ensure!(
        list["metadata"]
            .get("continue")
            .is_none_or(|v| v.as_str() == Some("")),
        "incomplete fact collection"
    );
    let items = list["items"]
        .as_array()
        .ok_or_else(|| anyhow::anyhow!("fact items missing"))?;
    ensure!(items.len() <= 4096, "too many source facts");
    Ok(items)
}
fn metadata<'a>(item: &'a Value, kind: &str) -> Result<&'a Value> {
    ensure!(
        item.get("kind").is_none_or(|v| v == kind)
            && item.get("apiVersion").is_none_or(|v| v == "v1"),
        "contradictory fact kind/version"
    );
    let metadata = &item["metadata"];
    text(metadata, "uid", 128)?;
    text(metadata, "resourceVersion", 1024)?;
    text(metadata, "name", 253)?;
    Ok(metadata)
}
pub(super) fn parse(bytes: &[u8]) -> Result<(Vec<NamespaceFact>, Vec<PodFact>)> {
    ensure!(bytes.len() <= 1024 * 1024, "fact document too large");
    let input: Value = serde_json::from_slice(bytes)?;
    let mut namespaces = Vec::new();
    let mut namespace_uids = BTreeMap::new();
    let mut uids = BTreeSet::new();
    for item in items(&input["namespaces"], "NamespaceList")? {
        let m = metadata(item, "Namespace")?;
        let name = text(m, "name", 63)?;
        let uid = text(m, "uid", 128)?;
        ensure!(
            m.get("deletionTimestamp").is_none_or(Value::is_null),
            "deleting namespace is unavailable"
        );
        ensure!(
            namespace_uids
                .insert(name.to_owned(), uid.to_owned())
                .is_none()
                && uids.insert(uid.to_owned()),
            "duplicate namespace identity"
        );
        namespaces.push(NamespaceFact {
            name: name.into(),
            uid: uid.into(),
            labels: labels(m)?,
        });
    }
    let mut pods = Vec::new();
    let mut names = BTreeSet::new();
    uids.clear();
    for item in items(&input["pods"], "PodList")? {
        let m = metadata(item, "Pod")?;
        let namespace = text(m, "namespace", 63)?;
        let name = text(m, "name", 253)?;
        let uid = text(m, "uid", 128)?;
        let namespace_uid = namespace_uids
            .get(namespace)
            .ok_or_else(|| anyhow::anyhow!("Pod namespace absent from supplied collection"))?
            .clone();
        ensure!(
            names.insert((namespace.to_owned(), name.to_owned())) && uids.insert(uid.to_owned()),
            "duplicate Pod identity"
        );
        let mut addresses = Vec::new();
        if let Some(values) = item["status"].get("podIPs") {
            let values = values
                .as_array()
                .ok_or_else(|| anyhow::anyhow!("invalid Pod address list"))?;
            ensure!(values.len() <= 2, "too many Pod addresses");
            for entry in values {
                addresses.push(guard_core::canonical_ip(text(entry, "ip", 64)?)?);
            }
        }
        if let Some(value) = item["status"].get("podIP") {
            let value = value
                .as_str()
                .ok_or_else(|| anyhow::anyhow!("invalid primary Pod address"))?;
            if !value.is_empty() {
                let ip = guard_core::canonical_ip(value)?;
                if addresses.is_empty() {
                    addresses.push(ip);
                } else {
                    ensure!(addresses[0] == ip, "primary Pod address mismatch");
                }
            }
        }
        let host_network = match item["spec"].get("hostNetwork") {
            None => false,
            Some(v) => v
                .as_bool()
                .ok_or_else(|| anyhow::anyhow!("invalid hostNetwork"))?,
        };
        let deleting = m.get("deletionTimestamp").is_some_and(|v| !v.is_null());
        pods.push(PodFact {
            namespace: namespace.into(),
            namespace_uid,
            name: name.into(),
            uid: uid.into(),
            labels: labels(m)?,
            addresses,
            deleting,
            host_network,
        });
    }
    Ok((namespaces, pods))
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn returned_api_shapes_and_partial_facts() {
        let mut source = serde_json::json!({"namespaces":{"apiVersion":"v1","kind":"NamespaceList","metadata":{"resourceVersion":"ns-rv"},"items":[{"metadata":{"name":"blue","uid":"ns-1","resourceVersion":"1"}}]},"pods":{"apiVersion":"v1","kind":"PodList","metadata":{"resourceVersion":"pod-rv"},"items":[{"metadata":{"name":"worker","namespace":"blue","uid":"pod-1","resourceVersion":"2"},"spec":{},"status":{"podIP":"192.0.2.1","podIPs":[{"ip":"192.0.2.1"}]}}]}});
        let parse_value = |v: &Value| parse(&serde_json::to_vec(v).unwrap());
        let (ns, pods) = parse_value(&source).unwrap();
        assert_eq!(ns.len(), 1);
        assert_eq!(pods[0].namespace_uid, "ns-1");
        source["pods"]["metadata"]["continue"] = "next".into();
        assert!(parse_value(&source).is_err());
        source["pods"]["metadata"]["continue"] = "".into();
        source["pods"]["items"][0]["status"]["podIP"] = "192.0.2.2".into();
        assert!(parse_value(&source).is_err());
        source["pods"]["items"][0]["status"]["podIP"] = "192.0.2.1".into();
        source["pods"]["items"][0]["metadata"]["namespace"] = "missing".into();
        assert!(parse_value(&source).is_err());
        source["pods"]["items"][0]["metadata"]["namespace"] = "blue".into();
        source["namespaces"]["items"][0]["metadata"]["deletionTimestamp"] =
            "2026-01-01T00:00:00Z".into();
        assert!(parse_value(&source).is_err());
    }
}
