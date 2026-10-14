//! Bounded label predicates; apply to authoritative object labels only.
use anyhow::{Result, ensure};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Copy)]
pub enum Operator {
    In,
    NotIn,
    Exists,
    DoesNotExist,
}
#[derive(Clone)]
pub struct Requirement {
    key: String,
    operator: Operator,
    values: BTreeSet<String>,
}
impl Requirement {
    pub fn new(key: String, operator: Operator, values: Vec<String>) -> Result<Self> {
        ensure!(
            !key.is_empty() && key.len() <= 317,
            "invalid label key size"
        );
        ensure!(
            values.len() <= 256 && values.iter().all(|v| v.len() <= 63),
            "label values exceed bounds"
        );
        match operator {
            Operator::In | Operator::NotIn => {
                ensure!(!values.is_empty(), "set predicate requires values")
            }
            Operator::Exists | Operator::DoesNotExist => {
                ensure!(values.is_empty(), "existence predicate forbids values")
            }
        }
        Ok(Self {
            key,
            operator,
            values: values.into_iter().collect(),
        })
    }
    fn matches(&self, labels: &BTreeMap<String, String>) -> bool {
        let value = labels.get(&self.key);
        match self.operator {
            Operator::In => value.is_some_and(|v| self.values.contains(v)),
            Operator::NotIn => value.is_none_or(|v| !self.values.contains(v)),
            Operator::Exists => value.is_some(),
            Operator::DoesNotExist => value.is_none(),
        }
    }
}
#[derive(Clone)]
pub struct LabelSelector {
    requirements: Vec<Requirement>,
}
impl LabelSelector {
    /// matchLabels entries must be converted into singleton In requirements.
    /// The API adapter remains responsible for Kubernetes key/value syntax.
    pub fn compile(requirements: Vec<Requirement>) -> Result<Self> {
        ensure!(requirements.len() <= 256, "too many label requirements");
        Ok(Self { requirements })
    }
    pub fn matches(&self, labels: &BTreeMap<String, String>) -> bool {
        self.requirements.iter().all(|r| r.matches(labels))
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn absent_labels_and_empty_values_are_distinct() {
        let absent = BTreeMap::new();
        let empty = BTreeMap::from([("app".into(), "".into())]);
        for (operator, a, e) in [
            (Operator::In, false, false),
            (Operator::NotIn, true, true),
            (Operator::Exists, false, true),
            (Operator::DoesNotExist, true, false),
        ] {
            let values = match operator {
                Operator::In | Operator::NotIn => vec!["worker".into()],
                _ => vec![],
            };
            let selector = LabelSelector::compile(vec![
                Requirement::new("app".into(), operator, values).unwrap(),
            ])
            .unwrap();
            assert_eq!(selector.matches(&absent), a);
            assert_eq!(selector.matches(&empty), e);
        }
        let selector = LabelSelector::compile(vec![
            Requirement::new("app".into(), Operator::In, vec!["".into()]).unwrap(),
        ])
        .unwrap();
        assert!(selector.matches(&empty));
        assert!(!selector.matches(&absent));
    }
    #[test]
    fn conjunction_and_validation() {
        let a = Requirement::new("app".into(), Operator::In, vec!["worker".into()]).unwrap();
        let b = Requirement::new("disabled".into(), Operator::DoesNotExist, vec![]).unwrap();
        let selector = LabelSelector::compile(vec![a.clone(), b]).unwrap();
        let mut labels = BTreeMap::from([("app".into(), "worker".into())]);
        assert!(selector.matches(&labels));
        labels.insert("disabled".into(), "".into());
        assert!(!selector.matches(&labels));
        assert!(LabelSelector::compile(vec![]).unwrap().matches(&labels));
        assert!(Requirement::new("app".into(), Operator::In, vec![]).is_err());
        assert!(Requirement::new("app".into(), Operator::Exists, vec!["x".into()]).is_err());
        assert!(LabelSelector::compile(vec![a; 257]).is_err());
    }
}
