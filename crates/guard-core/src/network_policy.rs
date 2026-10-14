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

#[cfg(test)]
mod tests {
    use super::*;

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
