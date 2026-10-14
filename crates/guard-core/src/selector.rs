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
/// One NetworkPolicy peer containing selectors. An empty peer is represented
/// separately as all peers; it must not be mistaken for an empty podSelector.
#[derive(Clone)]
pub struct PodPeerSelector {
    policy_namespace: String,
    namespace: Option<LabelSelector>,
    pod: Option<LabelSelector>,
}
impl PodPeerSelector {
    pub fn compile(
        policy_namespace: String,
        namespace: Option<LabelSelector>,
        pod: Option<LabelSelector>,
    ) -> Result<Self> {
        ensure!(
            !policy_namespace.is_empty() && policy_namespace.len() <= 63,
            "invalid policy namespace size"
        );
        ensure!(
            namespace.is_some() || pod.is_some(),
            "empty peer requires explicit all-peer representation"
        );
        Ok(Self {
            policy_namespace,
            namespace,
            pod,
        })
    }
    /// Call only for a live, UID-bound Pod and its authoritative Namespace.
    pub fn matches(
        &self,
        pod_namespace: &str,
        namespace_labels: &BTreeMap<String, String>,
        pod_labels: &BTreeMap<String, String>,
    ) -> bool {
        let namespace_matches = match &self.namespace {
            Some(selector) => selector.matches(namespace_labels),
            None => pod_namespace == self.policy_namespace,
        };
        namespace_matches && self.pod.as_ref().is_none_or(|s| s.matches(pod_labels))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn namespace_and_pod_selectors_intersect_with_local_namespace_default() {
        let ns = LabelSelector::compile(vec![
            Requirement::new("team".into(), Operator::In, vec!["blue".into()]).unwrap(),
        ])
        .unwrap();
        let pod = LabelSelector::compile(vec![
            Requirement::new("role".into(), Operator::In, vec!["client".into()]).unwrap(),
        ])
        .unwrap();
        let blue = BTreeMap::from([("team".into(), "blue".into())]);
        let client = BTreeMap::from([("role".into(), "client".into())]);
        let empty = BTreeMap::new();
        let both =
            PodPeerSelector::compile("local".into(), Some(ns.clone()), Some(pod.clone())).unwrap();
        assert!(both.matches("remote", &blue, &client));
        assert!(!both.matches("remote", &blue, &empty));
        assert!(!both.matches("local", &empty, &client));
        let local = PodPeerSelector::compile("local".into(), None, Some(pod)).unwrap();
        assert!(local.matches("local", &empty, &client));
        assert!(!local.matches("remote", &blue, &client));
        let namespace = PodPeerSelector::compile("local".into(), Some(ns), None).unwrap();
        assert!(namespace.matches("remote", &blue, &empty));
        let all = LabelSelector::compile(vec![]).unwrap();
        let local_all = PodPeerSelector::compile("local".into(), None, Some(all.clone())).unwrap();
        assert!(!local_all.matches("remote", &blue, &client));
        let global_all = PodPeerSelector::compile("local".into(), Some(all), None).unwrap();
        assert!(global_all.matches("remote", &empty, &empty));
        assert!(PodPeerSelector::compile("local".into(), None, None).is_err());
    }

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
