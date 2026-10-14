//! Pure materialization from trusted, complete, freshness-fenced source facts.
//! These facts are not authentication evidence and must never come from headers.
use crate::{network_policy::NetworkPeers, selector::PodPeerSelector};
use anyhow::{Result, ensure};
use std::{
    collections::{BTreeMap, BTreeSet},
    net::IpAddr,
};

pub struct NamespaceFact {
    pub name: String,
    pub uid: String,
    pub labels: BTreeMap<String, String>,
}
pub struct PodFact {
    pub namespace: String,
    /// Association supplied by the source assembler; Kubernetes Pods do not
    /// directly carry a Namespace UID field.
    pub namespace_uid: String,
    pub name: String,
    pub uid: String,
    pub labels: BTreeMap<String, String>,
    pub addresses: Vec<IpAddr>,
    pub deleting: bool,
    pub host_network: bool,
}
fn bounded_labels(labels: &BTreeMap<String, String>) -> bool {
    labels.len() <= 256
        && labels
            .iter()
            .all(|(k, v)| !k.is_empty() && k.len() <= 317 && v.len() <= 63)
}
pub fn resolve(
    selector: &PodPeerSelector,
    namespaces: &[NamespaceFact],
    pods: &[PodFact],
) -> Result<NetworkPeers> {
    ensure!(
        namespaces.len() <= 4096 && pods.len() <= 4096,
        "source fact capacity exceeded"
    );
    let mut namespace_index = BTreeMap::new();
    let mut namespace_uids = BTreeSet::new();
    for namespace in namespaces {
        ensure!(
            !namespace.name.is_empty()
                && namespace.name.len() <= 63
                && !namespace.uid.is_empty()
                && namespace.uid.len() <= 128
                && bounded_labels(&namespace.labels),
            "invalid namespace fact"
        );
        ensure!(
            namespace_index
                .insert(namespace.name.as_str(), namespace)
                .is_none()
                && namespace_uids.insert(namespace.uid.as_str()),
            "duplicate namespace identity"
        );
    }
    let mut names = BTreeSet::new();
    let mut uids = BTreeSet::new();
    let mut addresses = BTreeSet::new();
    let mut selected = Vec::new();
    for pod in pods {
        ensure!(
            !pod.name.is_empty()
                && pod.name.len() <= 253
                && !pod.uid.is_empty()
                && pod.uid.len() <= 128
                && pod.addresses.len() <= 2
                && bounded_labels(&pod.labels),
            "invalid pod fact"
        );
        ensure!(
            names.insert((pod.namespace.as_str(), pod.name.as_str()))
                && uids.insert(pod.uid.as_str()),
            "duplicate pod identity"
        );
        let namespace = namespace_index
            .get(pod.namespace.as_str())
            .ok_or_else(|| anyhow::anyhow!("pod namespace missing"))?;
        ensure!(
            namespace.uid == pod.namespace_uid,
            "namespace UID association changed"
        );
        if pod.deleting {
            continue;
        }
        let matches = selector.matches(&pod.namespace, &namespace.labels, &pod.labels);
        if pod.host_network {
            ensure!(
                !matches,
                "selected hostNetwork Pod requires explicit network semantics"
            );
            continue;
        }
        for address in &pod.addresses {
            let address = match address {
                IpAddr::V6(v) => v.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(*address),
                _ => *address,
            };
            ensure!(addresses.insert(address), "ambiguous Pod address");
            // Validate even unselected normal-Pod addresses.
            NetworkPeers::hosts(&[address])?;
            if matches {
                selected.push(address);
            }
        }
    }
    NetworkPeers::hosts(&selected)
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        network_policy::{NetworkDecision, NetworkRule, SelectedDirection, Transport},
        selector::LabelSelector,
    };
    fn namespace() -> NamespaceFact {
        NamespaceFact {
            name: "blue".into(),
            uid: "ns-1".into(),
            labels: BTreeMap::new(),
        }
    }
    fn pod() -> PodFact {
        PodFact {
            namespace: "blue".into(),
            namespace_uid: "ns-1".into(),
            name: "worker".into(),
            uid: "pod-1".into(),
            labels: BTreeMap::new(),
            addresses: vec!["192.0.2.1".parse().unwrap()],
            deleting: false,
            host_network: false,
        }
    }
    #[test]
    fn ambiguous_addresses_and_duplicate_identity_refuse_materialization() {
        let selector = PodPeerSelector::compile(
            "blue".into(),
            None,
            Some(LabelSelector::compile(vec![]).unwrap()),
        )
        .unwrap();
        let namespaces = vec![namespace()];
        let mut second = pod();
        second.name = "other".into();
        second.uid = "pod-2".into();
        assert!(resolve(&selector, &namespaces, &[pod(), second]).is_err());
        let mut second = pod();
        second.name = "other".into();
        second.addresses = vec!["192.0.2.2".parse().unwrap()];
        assert!(resolve(&selector, &namespaces, &[pod(), second]).is_err());
        assert!(resolve(&selector, &[], &[pod()]).is_err());
    }
    #[test]
    fn deletion_and_namespace_recreation_do_not_keep_peer_grants() {
        let selector = PodPeerSelector::compile(
            "blue".into(),
            None,
            Some(LabelSelector::compile(vec![]).unwrap()),
        )
        .unwrap();
        let mut pods = vec![pod()];
        let namespaces = vec![namespace()];
        let peers = resolve(&selector, &namespaces, &pods).unwrap();
        let view =
            SelectedDirection::compile(true, vec![NetworkRule::with_peers(peers, vec![]).unwrap()])
                .unwrap();
        assert_eq!(
            view.decide("192.0.2.1".parse().unwrap(), Transport::Tcp, 443),
            NetworkDecision::Allowed
        );
        pods[0].deleting = true;
        let view = SelectedDirection::compile(
            true,
            vec![
                NetworkRule::with_peers(resolve(&selector, &namespaces, &pods).unwrap(), vec![])
                    .unwrap(),
            ],
        )
        .unwrap();
        assert_eq!(
            view.decide("192.0.2.1".parse().unwrap(), Transport::Tcp, 443),
            NetworkDecision::Denied
        );
        pods[0].deleting = false;
        pods[0].namespace_uid = "ns-recreated".into();
        assert!(resolve(&selector, &namespaces, &pods).is_err());
        pods[0].namespace_uid = "ns-1".into();
        pods[0].host_network = true;
        assert!(resolve(&selector, &namespaces, &pods).is_err());
    }
}
