//! Kubernetes ipBlock primitive. This alone is not NetworkPolicy enforcement.
use crate::{canonical_ip, canonical_network, prefix::PrefixTrie};
use anyhow::{Result, ensure};
use ipnet::IpNet;
use std::net::IpAddr;

/// One peer's CIDR minus exceptions. Exceptions do not deny other allowed peers.
#[derive(Clone)]
pub struct IpBlock {
    network: IpNet,
    except: PrefixTrie<()>,
}

impl IpBlock {
    pub fn compile(cidr: &str, except: &[String]) -> Result<Self> {
        ensure!(except.len() <= 4096, "too many ipBlock exceptions");
        let network = canonical_network(cidr)?;
        let mut exclusions = PrefixTrie::default();
        for value in except {
            let exclusion = canonical_network(value)?;
            ensure!(
                exclusion.prefix_len() > network.prefix_len()
                    && network.contains(&exclusion.addr()),
                "ipBlock exception must be a strict subnet of its CIDR"
            );
            exclusions.insert(exclusion, ());
        }
        Ok(Self {
            network,
            except: exclusions,
        })
    }

    pub fn contains(&self, ip: IpAddr) -> bool {
        let ip = match ip {
            IpAddr::V6(v) => v.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(ip),
            _ => ip,
        };
        self.network.contains(&ip) && self.except.longest(ip).is_none()
    }

    pub fn contains_text(&self, ip: &str) -> Result<bool> {
        Ok(self.contains(canonical_ip(ip)?))
    }
}

/// Transport protocol from trusted connection context, not an HTTP header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transport {
    Tcp,
    Udp,
    Sctp,
}

#[derive(Clone)]
pub struct PortRange {
    protocol: Transport,
    first: u16,
    last: u16,
}
impl PortRange {
    pub fn new(protocol: Transport, first: u16, last: u16) -> Result<Self> {
        ensure!(first > 0 && first <= last, "invalid destination port range");
        Ok(Self {
            protocol,
            first,
            last,
        })
    }
}

/// Explicit peer scope. An empty resolved set matches nobody, never everybody.
#[derive(Clone)]
pub enum NetworkPeers {
    All,
    Resolved(Vec<IpBlock>),
    Hosts(HostAddresses),
}
/// Exact addresses materialized by a trusted source adapter, not an identity proof.
#[derive(Clone)]
pub struct HostAddresses {
    index: PrefixTrie<()>,
}
impl NetworkPeers {
    pub fn hosts(addresses: &[IpAddr]) -> Result<Self> {
        ensure!(addresses.len() <= 4096, "too many resolved host addresses");
        let mut index = PrefixTrie::default();
        for address in addresses {
            let address = match address {
                IpAddr::V6(v) => v.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(*address),
                _ => *address,
            };
            ensure!(
                !address.is_unspecified() && !address.is_multicast() && !address.is_loopback(),
                "invalid resolved host address"
            );
            let bits = if address.is_ipv4() { 32 } else { 128 };
            index.insert(IpNet::new(address, bits)?, ());
        }
        Ok(Self::Hosts(HostAddresses { index }))
    }

    fn len(&self) -> usize {
        match self {
            Self::All => 0,
            Self::Resolved(peers) => peers.len(),
            Self::Hosts(hosts) => hosts.index.len(),
        }
    }
    fn contains(&self, peer: IpAddr) -> bool {
        match self {
            Self::All => true,
            Self::Resolved(peers) => peers.iter().any(|p| p.contains(peer)),
            Self::Hosts(hosts) => hosts.index.longest(peer).is_some(),
        }
    }
}
/// Empty ports mean all ports. Peer wildcard must be represented explicitly.
#[derive(Clone)]
pub struct NetworkRule {
    peers: NetworkPeers,
    ports: Vec<PortRange>,
}
impl NetworkRule {
    /// Compatibility constructor for API rules with omitted/empty peer arrays.
    pub fn new(peers: Vec<IpBlock>, ports: Vec<PortRange>) -> Result<Self> {
        let peers = if peers.is_empty() {
            NetworkPeers::All
        } else {
            NetworkPeers::Resolved(peers)
        };
        Self::with_peers(peers, ports)
    }
    pub fn with_peers(peers: NetworkPeers, ports: Vec<PortRange>) -> Result<Self> {
        ensure!(
            peers.len() <= 4096 && ports.len() <= 4096,
            "network rule exceeds bound"
        );
        Ok(Self { peers, ports })
    }
    fn permits(&self, peer: IpAddr, protocol: Transport, port: u16) -> bool {
        self.peers.contains(peer)
            && (self.ports.is_empty()
                || self
                    .ports
                    .iter()
                    .any(|p| p.protocol == protocol && (p.first..=p.last).contains(&port)))
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum NetworkDecision {
    NotIsolated,
    Allowed,
    Denied,
}

/// One target and one direction, after authoritative selector resolution.
/// Ingress and egress must be resolved independently. Named ports must be
/// resolved by the source adapter; this core accepts only numeric ports.
#[derive(Clone)]
pub struct SelectedDirection {
    isolated: bool,
    rules: Vec<NetworkRule>,
}
impl SelectedDirection {
    pub fn compile(isolated: bool, rules: Vec<NetworkRule>) -> Result<Self> {
        ensure!(rules.len() <= 4096, "too many network rules");
        ensure!(
            isolated || rules.is_empty(),
            "rules without selected policy"
        );
        let mut total = 0usize;
        for rule in &rules {
            total = total
                .checked_add(rule.peers.len() + rule.ports.len() + 1)
                .ok_or_else(|| anyhow::anyhow!("network policy capacity overflow"))?;
        }
        ensure!(total <= 16384, "network policy exceeds total capacity");
        Ok(Self { isolated, rules })
    }
    pub fn decide(&self, peer: IpAddr, protocol: Transport, port: u16) -> NetworkDecision {
        if !self.isolated {
            return NetworkDecision::NotIsolated;
        }
        if port != 0 && self.rules.iter().any(|r| r.permits(peer, protocol, port)) {
            NetworkDecision::Allowed
        } else {
            NetworkDecision::Denied
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolved_hosts_are_exact_deduplicated_and_empty_means_none() {
        let addresses =
            ["192.0.2.1", "::ffff:192.0.2.1", "2001:db8::1"].map(|s| s.parse().unwrap());
        let peers = NetworkPeers::hosts(&addresses).unwrap();
        assert_eq!(peers.len(), 2);
        let view =
            SelectedDirection::compile(true, vec![NetworkRule::with_peers(peers, vec![]).unwrap()])
                .unwrap();
        for address in addresses {
            assert_eq!(
                view.decide(address, Transport::Tcp, 443),
                NetworkDecision::Allowed
            );
        }
        for address in ["192.0.2.2", "2001:db8::2"] {
            assert_eq!(
                view.decide(address.parse().unwrap(), Transport::Tcp, 443),
                NetworkDecision::Denied
            );
        }
        let empty = NetworkPeers::hosts(&[]).unwrap();
        assert!(!empty.contains("192.0.2.1".parse().unwrap()));
        for address in [
            "0.0.0.0",
            "::",
            "127.0.0.1",
            "::1",
            "224.0.0.1",
            "ff02::1",
            "::ffff:127.0.0.1",
        ] {
            assert!(NetworkPeers::hosts(&[address.parse().unwrap()]).is_err());
        }
        assert!(NetworkPeers::hosts(&vec!["192.0.2.1".parse().unwrap(); 4097]).is_err());
    }
    #[test]
    fn empty_resolved_peer_set_never_becomes_a_wildcard() {
        let none = NetworkRule::with_peers(NetworkPeers::Resolved(vec![]), vec![]).unwrap();
        let all = NetworkRule::with_peers(NetworkPeers::All, vec![]).unwrap();
        let none = SelectedDirection::compile(true, vec![none]).unwrap();
        let all = SelectedDirection::compile(true, vec![all]).unwrap();
        for ip in ["192.0.2.1", "2001:db8::1", "::ffff:192.0.2.1"] {
            let ip = ip.parse().unwrap();
            assert_eq!(
                none.decide(ip, Transport::Tcp, 443),
                NetworkDecision::Denied
            );
            assert_eq!(
                all.decide(ip, Transport::Tcp, 443),
                NetworkDecision::Allowed
            );
        }
    }
    #[test]
    fn selected_direction_distinguishes_default_deny_and_additive_allow() {
        let ip = "192.0.2.70".parse().unwrap();
        assert_eq!(
            SelectedDirection::compile(false, vec![])
                .unwrap()
                .decide(ip, Transport::Tcp, 443),
            NetworkDecision::NotIsolated
        );
        assert_eq!(
            SelectedDirection::compile(true, vec![])
                .unwrap()
                .decide(ip, Transport::Tcp, 443),
            NetworkDecision::Denied
        );
        let a = NetworkRule::new(
            vec![IpBlock::compile("192.0.2.0/24", &["192.0.2.64/26".into()]).unwrap()],
            vec![],
        )
        .unwrap();
        let b = NetworkRule::new(
            vec![IpBlock::compile("192.0.2.64/26", &[]).unwrap()],
            vec![PortRange::new(Transport::Tcp, 443, 444).unwrap()],
        )
        .unwrap();
        let view = SelectedDirection::compile(true, vec![a, b]).unwrap();
        assert_eq!(
            view.decide(ip, Transport::Tcp, 443),
            NetworkDecision::Allowed
        );
        assert_eq!(
            view.decide(ip, Transport::Tcp, 444),
            NetworkDecision::Allowed
        );
        assert_eq!(
            view.decide(ip, Transport::Tcp, 445),
            NetworkDecision::Denied
        );
        assert_eq!(
            view.decide(ip, Transport::Udp, 443),
            NetworkDecision::Denied
        );
        assert_eq!(
            view.decide("192.0.2.1".parse().unwrap(), Transport::Udp, 53),
            NetworkDecision::Allowed
        );
    }

    #[test]
    fn wildcard_rule_and_bounds_are_explicit() {
        let ip = "2001:db8::1".parse().unwrap();
        let view =
            SelectedDirection::compile(true, vec![NetworkRule::new(vec![], vec![]).unwrap()])
                .unwrap();
        assert_eq!(
            view.decide(ip, Transport::Sctp, 9000),
            NetworkDecision::Allowed
        );
        assert_eq!(view.decide(ip, Transport::Tcp, 0), NetworkDecision::Denied);
        assert!(PortRange::new(Transport::Tcp, 0, 80).is_err());
        assert!(PortRange::new(Transport::Tcp, 90, 80).is_err());
        assert!(
            SelectedDirection::compile(false, vec![NetworkRule::new(vec![], vec![]).unwrap()])
                .is_err()
        );
        let rule = NetworkRule::new(
            vec![],
            vec![PortRange::new(Transport::Tcp, 1, 65535).unwrap(); 4096],
        )
        .unwrap();
        assert!(SelectedDirection::compile(true, vec![rule; 4]).is_err());
    }

    #[test]
    fn exceptions_are_local_to_one_additive_peer() {
        let a = IpBlock::compile("192.0.2.0/24", &["192.0.2.64/26".into()]).unwrap();
        let b = IpBlock::compile("192.0.2.64/26", &[]).unwrap();
        assert!(a.contains_text("192.0.2.63").unwrap());
        assert!(!a.contains_text("192.0.2.64").unwrap());
        assert!(!a.contains_text("192.0.2.127").unwrap());
        assert!(a.contains_text("192.0.2.128").unwrap());
        assert!(b.contains_text("192.0.2.64").unwrap());
        assert!(!a.contains_text("198.51.100.1").unwrap());
        assert!(!a.contains_text("::ffff:192.0.2.64").unwrap());
    }

    #[test]
    fn invalid_exceptions_never_compile() {
        for value in [
            "192.0.2.0/24",
            "192.0.0.0/16",
            "198.51.100.0/25",
            "2001:db8::/64",
            "bad",
        ] {
            assert!(IpBlock::compile("192.0.2.0/24", &[value.into()]).is_err());
        }
        assert!(IpBlock::compile("192.0.2.0/24", &vec!["192.0.2.0/25".into(); 4097]).is_err());
    }

    #[test]
    fn ipv6_and_mapped_networks_preserve_exceptions() {
        let v6 = IpBlock::compile("2001:db8::/32", &["2001:db8:1::/48".into()]).unwrap();
        assert!(!v6.contains_text("2001:db8:1::1").unwrap());
        assert!(v6.contains_text("2001:db8:2::1").unwrap());
        let mapped =
            IpBlock::compile("::ffff:192.0.2.0/120", &["::ffff:192.0.2.0/121".into()]).unwrap();
        assert!(!mapped.contains_text("192.0.2.1").unwrap());
        assert!(mapped.contains_text("::ffff:192.0.2.200").unwrap());
    }
}
