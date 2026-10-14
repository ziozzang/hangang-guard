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
pub(crate) fn compile_selector(bytes: &[u8]) -> Result<LabelSelector> {
    ensure!(bytes.len() <= 65536, "selector document too large");
    let input: Selector = serde_json::from_slice(bytes)?;
    ensure!(
        input.match_labels.len() + input.match_expressions.len() <= 256,
        "selector too large"
    );
    let mut requirements = Vec::new();
    for (key, value) in input.match_labels {
        requirements.push(Requirement::new(key, Operator::In, vec![value])?);
    }
    for expression in input.match_expressions {
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
