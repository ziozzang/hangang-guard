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
#[cfg(test)]
mod tests {
    use super::*;
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
