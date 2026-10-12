use anyhow::{Result, ensure};
use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, HashMap, HashSet},
    net::IpAddr,
};

pub const MAX_CANDIDATES: usize = 10_000;
pub const MAX_BLOCKS: usize = 100_000;
pub const MAX_BATCH: usize = 256;
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum Mode {
    #[default]
    Observe,
    Enforce,
}
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventKind {
    Honeypot,
    Scanner,
    AuthFailure,
    InvalidRequest,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Event {
    pub ip: String,
    pub kind: EventKind,
    pub observed_at: u64,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EventBatch {
    pub source_id: String,
    pub events: Vec<Event>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Block {
    pub network: String,
    pub expires_at: u64,
    pub reason: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Snapshot {
    pub version: u32,
    pub revision: u64,
    pub generated_at: u64,
    pub valid_until: u64,
    pub mode: Mode,
    pub allow: Vec<String>,
    pub blocks: Vec<Block>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Weights {
    pub honeypot: u32,
    pub scanner: u32,
    pub auth_failure: u32,
    pub invalid_request: u32,
}
impl Default for Weights {
    fn default() -> Self {
        Self {
            honeypot: 10,
            scanner: 5,
            auth_failure: 1,
            invalid_request: 2,
        }
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Policy {
    pub mode: Mode,
    pub auto_block: bool,
    pub window_secs: u64,
    pub threshold: u64,
    pub block_ttl_secs: u64,
    pub allow: Vec<String>,
    pub weights: Weights,
}
impl Default for Policy {
    fn default() -> Self {
        Self {
            mode: Mode::Observe,
            auto_block: false,
            window_secs: 60,
            threshold: 10,
            block_ttl_secs: 900,
            allow: vec![],
            weights: Weights::default(),
        }
    }
}
pub fn canonical_ip(value: &str) -> Result<IpAddr> {
    let ip: IpAddr = value.parse()?;
    Ok(match ip {
        IpAddr::V6(v) => v.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(ip),
        _ => ip,
    })
}
pub fn canonical_network(value: &str) -> Result<IpNet> {
    let net: IpNet = value.parse()?;
    if let IpNet::V6(v) = net
        && let Some(ip) = v.addr().to_ipv4_mapped()
    {
        ensure!(v.prefix_len() >= 96, "mapped prefix must be at least /96");
        return Ok(IpNet::new(IpAddr::V4(ip), v.prefix_len() - 96)?.trunc());
    }
    Ok(net.trunc())
}
impl Policy {
    pub fn validate(&mut self) -> Result<()> {
        ensure!(
            (1..=3600).contains(&self.window_secs),
            "window outside 1..3600"
        );
        ensure!(
            (1..=1_000_000).contains(&self.threshold),
            "invalid threshold"
        );
        ensure!(
            (1..=604800).contains(&self.block_ttl_secs),
            "invalid block TTL"
        );
        ensure!(self.allow.len() <= MAX_BLOCKS, "too many allow rules");
        for w in [
            self.weights.honeypot,
            self.weights.scanner,
            self.weights.auth_failure,
            self.weights.invalid_request,
        ] {
            ensure!(w <= 1000, "weight exceeds 1000");
        }
        let mut seen = HashSet::new();
        for n in &mut self.allow {
            *n = canonical_network(n)?.to_string();
            ensure!(seen.insert(n.clone()), "duplicate allow rule");
        }
        Ok(())
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Candidate {
    pub ip: String,
    pub score: u64,
    pub eligible: bool,
    pub events: u64,
    pub first_seen: u64,
    pub last_seen: u64,
    pub asn: Option<u32>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Aggregate {
    pub ip: String,
    pub buckets: BTreeMap<u64, (u64, u64)>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct State {
    pub policy: Policy,
    pub revision: u64,
    pub blocks: Vec<Block>,
    pub aggregates: Vec<Aggregate>,
    pub stats: Stats,
}
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Stats {
    pub accepted: u64,
    pub dropped_capacity: u64,
    pub block_capacity_rejections: u64,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IngestResult {
    pub accepted: usize,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AsnPrefix {
    pub network: String,
    pub asn: u32,
}
#[derive(Clone)]
pub struct Engine {
    policy: Policy,
    revision: u64,
    blocks: BTreeMap<String, Block>,
    aggregates: BTreeMap<String, Aggregate>,
    stats: Stats,
    asns: HashMap<IpNet, u32>,
    allow_index: HashSet<IpNet>,
    block_index: HashMap<IpNet, Block>,
    last_pruned: Option<u64>,
    snapshot_bytes: usize,
}
impl Engine {
    pub fn new(mut policy: Policy) -> Result<Self> {
        policy.validate()?;
        ensure!(
            snapshot_budget(&policy, std::iter::empty()) <= 4_000_000,
            "policy snapshot byte budget exceeded"
        );
        let allow_index = policy
            .allow
            .iter()
            .map(|s| canonical_network(s))
            .collect::<Result<_>>()?;
        let snapshot_bytes = snapshot_budget(&policy, std::iter::empty());
        Ok(Self {
            policy,
            revision: 1,
            blocks: BTreeMap::new(),
            aggregates: BTreeMap::new(),
            stats: Stats::default(),
            asns: HashMap::new(),
            allow_index,
            block_index: HashMap::new(),
            last_pruned: None,
            snapshot_bytes,
        })
    }
    pub fn policy(&self) -> &Policy {
        &self.policy
    }
    pub fn stats(&self) -> Stats {
        self.stats.clone()
    }
    pub fn set_policy(&mut self, mut policy: Policy) -> Result<()> {
        policy.validate()?;
        let allow_index = policy
            .allow
            .iter()
            .map(|s| canonical_network(s))
            .collect::<Result<_>>()?;
        ensure!(
            snapshot_budget(&policy, self.blocks.values()) <= 4_000_000,
            "snapshot byte budget exceeded"
        );
        self.snapshot_bytes = snapshot_budget(&policy, self.blocks.values());
        self.allow_index = allow_index;
        self.policy = policy;
        self.aggregates.clear();
        self.last_pruned = None;
        self.revision = self.revision.saturating_add(1);
        Ok(())
    }
    pub fn capacity(&self) -> (usize, usize) {
        (self.aggregates.len(), self.blocks.len())
    }
    fn prune(&mut self, now: u64) {
        if self.last_pruned == Some(now) {
            return;
        }
        self.last_pruned = Some(now);
        let window = self.policy.window_secs;
        self.aggregates.retain(|_, a| {
            a.buckets.retain(|t, _| *t <= now && now - *t < window);
            !a.buckets.is_empty()
        });
        self.blocks.retain(|_, b| {
            if b.expires_at <= now {
                self.snapshot_bytes = self.snapshot_bytes.saturating_sub(block_cost(b));
                false
            } else {
                true
            }
        });
        self.block_index.retain(|_, b| b.expires_at > now);
    }
    fn allowed(&self, ip: IpAddr) -> bool {
        let max = if ip.is_ipv4() { 32 } else { 128 };
        (0..=max).any(|prefix| {
            IpNet::new(ip, prefix).is_ok_and(|n| self.allow_index.contains(&n.trunc()))
        })
    }
    pub fn ingest(&mut self, batch: EventBatch, now: u64) -> Result<IngestResult> {
        ensure!(
            !batch.source_id.is_empty() && batch.source_id.len() <= 64,
            "invalid source ID"
        );
        ensure!(batch.events.len() <= MAX_BATCH, "batch exceeds 256");
        let parsed: Vec<_> = batch
            .events
            .iter()
            .map(|e| {
                ensure!(
                    e.observed_at.abs_diff(now) <= 300,
                    "timestamp outside receiver tolerance"
                );
                canonical_ip(&e.ip)
            })
            .collect::<Result<_>>()?;
        self.prune(now);
        let mut accepted = 0;
        for (e, ip) in batch.events.into_iter().zip(parsed) {
            if self.allowed(ip) || self.decision(&ip.to_string(), now)?.action == "deny" {
                continue;
            }
            let weight = match e.kind {
                EventKind::Honeypot => self.policy.weights.honeypot,
                EventKind::Scanner => self.policy.weights.scanner,
                EventKind::AuthFailure => self.policy.weights.auth_failure,
                EventKind::InvalidRequest => self.policy.weights.invalid_request,
            } as u64;
            if weight == 0 {
                continue;
            }
            let key = ip.to_string();
            if !self.aggregates.contains_key(&key) && self.aggregates.len() >= MAX_CANDIDATES {
                self.stats.dropped_capacity = self.stats.dropped_capacity.saturating_add(1);
                continue;
            }
            let a = self
                .aggregates
                .entry(key.clone())
                .or_insert_with(|| Aggregate {
                    ip: key.clone(),
                    buckets: BTreeMap::new(),
                });
            let b = a
                .buckets
                .entry(
                    now / self.policy.window_secs.div_ceil(64)
                        * self.policy.window_secs.div_ceil(64),
                )
                .or_default();
            b.0 = b.0.saturating_add(weight);
            b.1 = b.1.saturating_add(1);
            let score = a.buckets.values().fold(0u64, |s, b| s.saturating_add(b.0));
            accepted += 1;
            if score >= self.policy.threshold
                && self.policy.mode == Mode::Enforce
                && self.policy.auto_block
                && !self.blocks.contains_key(&exact(ip))
            {
                if self.blocks.len() < MAX_BLOCKS {
                    let block_result = self.add_block(
                        Block {
                            network: exact(ip),
                            expires_at: now.saturating_add(self.policy.block_ttl_secs),
                            reason: "automatic threshold".into(),
                        },
                        now,
                    );
                    if block_result.is_err() {
                        self.stats.block_capacity_rejections =
                            self.stats.block_capacity_rejections.saturating_add(1);
                    }
                } else {
                    self.stats.block_capacity_rejections =
                        self.stats.block_capacity_rejections.saturating_add(1);
                }
            }
        }
        self.stats.accepted = self.stats.accepted.saturating_add(accepted as u64);
        Ok(IngestResult { accepted })
    }
    pub fn snapshot(&mut self, now: u64) -> Snapshot {
        self.prune(now);
        Snapshot {
            version: 1,
            revision: self.revision,
            generated_at: now,
            valid_until: now.saturating_add(30),
            mode: self.policy.mode,
            allow: self.policy.allow.clone(),
            blocks: self.blocks.values().cloned().collect(),
        }
    }
    pub fn candidates(&mut self, now: u64) -> Vec<Candidate> {
        self.prune(now);
        self.aggregates
            .values()
            .map(|a| {
                let ip = canonical_ip(&a.ip).ok();
                Candidate {
                    ip: a.ip.clone(),
                    score: a.buckets.values().fold(0u64, |s, b| s.saturating_add(b.0)),
                    eligible: a.buckets.values().fold(0u64, |s, b| s.saturating_add(b.0))
                        >= self.policy.threshold,
                    events: a.buckets.values().fold(0u64, |s, b| s.saturating_add(b.1)),
                    first_seen: a.buckets.first_key_value().map_or(now, |(t, _)| *t),
                    last_seen: a.buckets.last_key_value().map_or(now, |(t, _)| *t),
                    asn: ip.and_then(|ip| {
                        let max = if ip.is_ipv4() { 32 } else { 128 };
                        (0..=max).rev().find_map(|prefix| {
                            IpNet::new(ip, prefix)
                                .ok()
                                .and_then(|n| self.asns.get(&n.trunc()).copied())
                        })
                    }),
                }
            })
            .collect()
    }
    pub fn add_block(&mut self, mut block: Block, now: u64) -> Result<()> {
        self.prune(now);
        block.network = canonical_network(&block.network)?.to_string();
        ensure!(block.reason.len() <= 128, "reason exceeds 128 bytes");
        ensure!(
            block.expires_at > now && block.expires_at - now <= 604800,
            "invalid block expiry"
        );
        ensure!(
            self.blocks.contains_key(&block.network) || self.blocks.len() < MAX_BLOCKS,
            "block capacity reached"
        );
        let old_cost = self.blocks.get(&block.network).map_or(0, block_cost);
        ensure!(
            self.snapshot_bytes
                .saturating_sub(old_cost)
                .saturating_add(block_cost(&block))
                <= 4_000_000,
            "snapshot byte budget exceeded"
        );
        self.snapshot_bytes = self
            .snapshot_bytes
            .saturating_sub(old_cost)
            .saturating_add(block_cost(&block));
        self.block_index
            .insert(canonical_network(&block.network)?, block.clone());
        self.blocks.insert(block.network.clone(), block);
        self.revision = self.revision.saturating_add(1);
        Ok(())
    }
    pub fn remove_block(&mut self, network: &str) -> Result<bool> {
        let n = canonical_network(network)?.to_string();
        self.block_index.remove(&canonical_network(&n)?);
        let old = self.blocks.remove(&n);
        if let Some(b) = &old {
            self.snapshot_bytes = self.snapshot_bytes.saturating_sub(block_cost(b));
        }
        let removed = old.is_some();
        if removed {
            self.revision = self.revision.saturating_add(1);
        }
        Ok(removed)
    }
    pub fn approve(&mut self, ip: &str, now: u64) -> Result<Block> {
        self.prune(now);
        let ip = canonical_ip(ip)?;
        ensure!(
            self.aggregates.contains_key(&ip.to_string()),
            "candidate not found"
        );
        ensure!(!self.allowed(ip), "candidate is allowlisted");
        ensure!(
            self.aggregates[&ip.to_string()]
                .buckets
                .values()
                .fold(0u64, |s, b| s.saturating_add(b.0))
                >= self.policy.threshold,
            "candidate below threshold"
        );
        let block = Block {
            network: exact(ip),
            expires_at: now.saturating_add(self.policy.block_ttl_secs),
            reason: "manual candidate approval".into(),
        };
        self.add_block(block.clone(), now)?;
        Ok(block)
    }
    pub fn set_asn_catalog(&mut self, prefixes: Vec<AsnPrefix>) -> Result<()> {
        ensure!(prefixes.len() <= MAX_BLOCKS, "ASN catalog exceeds capacity");
        let mut values = HashMap::with_capacity(prefixes.len());
        for p in prefixes {
            ensure!(p.asn > 0, "invalid ASN");
            let network = canonical_network(&p.network)?;
            ensure!(
                values.insert(network, p.asn).is_none(),
                "duplicate ASN prefix"
            );
        }
        self.asns = values;
        Ok(())
    }
    pub fn state(&self) -> State {
        State {
            policy: self.policy.clone(),
            revision: self.revision,
            blocks: self.blocks.values().cloned().collect(),
            aggregates: self.aggregates.values().cloned().collect(),
            stats: self.stats.clone(),
        }
    }
    pub fn restore(state: State) -> Result<Self> {
        ensure!(
            state.blocks.len() <= MAX_BLOCKS && state.aggregates.len() <= MAX_CANDIDATES,
            "state exceeds capacity"
        );
        let mut engine = Self::new(state.policy)?;
        engine.revision = state.revision;
        engine.stats = state.stats;
        for mut b in state.blocks {
            b.network = canonical_network(&b.network)?.to_string();
            ensure!(b.reason.len() <= 128, "invalid reason");
            engine
                .block_index
                .insert(canonical_network(&b.network)?, b.clone());
            ensure!(
                engine.blocks.insert(b.network.clone(), b).is_none(),
                "duplicate block"
            );
        }
        for mut a in state.aggregates {
            a.ip = canonical_ip(&a.ip)?.to_string();
            ensure!(a.buckets.len() <= 64, "aggregate exceeds window capacity");
            ensure!(
                engine.aggregates.insert(a.ip.clone(), a).is_none(),
                "duplicate aggregate"
            );
        }
        ensure!(
            snapshot_budget(&engine.policy, engine.blocks.values()) <= 4_000_000,
            "state snapshot byte budget exceeded"
        );
        engine.snapshot_bytes = snapshot_budget(&engine.policy, engine.blocks.values());
        Ok(engine)
    }
}
fn exact(ip: IpAddr) -> String {
    format!("{ip}/{}", if ip.is_ipv4() { 32 } else { 128 })
}

/// Immutable bounded prefix lookup, with allow precedence and local expiration.
pub struct PrefixIndex {
    allow: HashSet<IpNet>,
    blocks: HashMap<IpNet, u64>,
    mode: Mode,
    valid_until: u64,
}
impl PrefixIndex {
    pub fn new(snapshot: &Snapshot, now: u64) -> Result<Self> {
        ensure!(snapshot.version == 1, "unsupported version");
        ensure!(
            snapshot.generated_at <= now.saturating_add(5)
                && snapshot.valid_until > now
                && snapshot.valid_until > snapshot.generated_at
                && snapshot.valid_until - snapshot.generated_at <= 300,
            "invalid validity"
        );
        ensure!(
            snapshot.allow.len() <= MAX_BLOCKS && snapshot.blocks.len() <= MAX_BLOCKS,
            "too many prefixes"
        );
        let mut allow = HashSet::new();
        for n in &snapshot.allow {
            ensure!(allow.insert(canonical_network(n)?), "duplicate allow");
        }
        let mut blocks = HashMap::new();
        for b in &snapshot.blocks {
            ensure!(b.reason.len() <= 128, "invalid reason");
            ensure!(
                blocks
                    .insert(canonical_network(&b.network)?, b.expires_at)
                    .is_none(),
                "duplicate block"
            );
        }
        Ok(Self {
            allow,
            blocks,
            mode: snapshot.mode,
            valid_until: snapshot.valid_until,
        })
    }
    pub fn is_blocked(&self, ip: IpAddr, now: u64) -> bool {
        if self.mode != Mode::Enforce || now >= self.valid_until {
            return false;
        }
        let ip = match ip {
            IpAddr::V6(v) => v.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(ip),
            _ => ip,
        };
        let max = if ip.is_ipv4() { 32 } else { 128 };
        for prefix in 0..=max {
            if let Ok(n) = IpNet::new(ip, prefix)
                && self.allow.contains(&n.trunc())
            {
                return false;
            }
        }
        for prefix in 0..=max {
            if let Ok(n) = IpNet::new(ip, prefix)
                && self
                    .blocks
                    .get(&n.trunc())
                    .is_some_and(|expiry| *expiry > now)
            {
                return true;
            }
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn batch(ip: &str, time: u64, kind: EventKind) -> EventBatch {
        EventBatch {
            source_id: "test".into(),
            events: vec![Event {
                ip: ip.into(),
                observed_at: time,
                kind,
            }],
        }
    }
    #[test]
    fn threshold_window_and_observe() {
        let mut e = Engine::new(Policy::default()).unwrap();
        e.ingest(batch("1.2.3.4", 100, EventKind::Honeypot), 100)
            .unwrap();
        assert_eq!(e.candidates(100)[0].score, 10);
        assert!(e.snapshot(100).blocks.is_empty());
        assert!(e.candidates(160).is_empty());
    }
    #[test]
    fn enforce_allow_and_mapped() {
        let mut p = Policy {
            mode: Mode::Enforce,
            auto_block: true,
            ..Policy::default()
        };
        p.allow = vec!["10.0.0.1/8".into()];
        let mut e = Engine::new(p).unwrap();
        e.ingest(batch("::ffff:10.0.0.1", 100, EventKind::Honeypot), 100)
            .unwrap();
        assert!(e.candidates(100).is_empty());
        e.ingest(batch("::ffff:1.2.3.4", 100, EventKind::Honeypot), 100)
            .unwrap();
        assert_eq!(e.snapshot(100).blocks[0].network, "1.2.3.4/32");
        assert_eq!(
            e.ingest(batch("1.2.3.4", 101, EventKind::Honeypot), 101)
                .unwrap()
                .accepted,
            0
        );
        assert_eq!(e.candidates(101)[0].score, 10);
        let idx = PrefixIndex::new(&e.snapshot(100), 100).unwrap();
        assert!(idx.is_blocked("::ffff:1.2.3.4".parse().unwrap(), 100));
        assert!(!idx.is_blocked("1.2.3.4".parse().unwrap(), 130));
        assert!(e.snapshot(1000).blocks.is_empty());
    }
    #[test]
    fn validation_atomic_batch() {
        let mut e = Engine::new(Policy::default()).unwrap();
        let mut b = batch("1.2.3.4", 100, EventKind::Honeypot);
        b.events.push(Event {
            ip: "bad".into(),
            observed_at: 100,
            kind: EventKind::Scanner,
        });
        assert!(e.ingest(b, 100).is_err());
        assert!(e.candidates(100).is_empty());
        assert!(
            Engine::new(Policy {
                window_secs: 0,
                ..Policy::default()
            })
            .is_err()
        );
        assert!(
            e.ingest(batch("1.2.3.4", 0, EventKind::Scanner), 500)
                .is_err()
        );
    }
    #[test]
    fn manual_prefix_allow_and_restore_asn() {
        let mut e = Engine::new(Policy {
            mode: Mode::Enforce,
            allow: vec!["192.0.2.42/32".into()],
            ..Policy::default()
        })
        .unwrap();
        e.ingest(batch("192.0.2.1", 100, EventKind::Scanner), 100)
            .unwrap();
        e.add_block(
            Block {
                network: "192.0.2.19/24".into(),
                expires_at: 200,
                reason: "test".into(),
            },
            100,
        )
        .unwrap();
        e.set_asn_catalog(vec![
            AsnPrefix {
                network: "192.0.0.0/16".into(),
                asn: 1,
            },
            AsnPrefix {
                network: "192.0.2.0/24".into(),
                asn: 2,
            },
        ])
        .unwrap();
        assert_eq!(e.candidates(100)[0].asn, Some(2));
        let idx = PrefixIndex::new(&e.snapshot(100), 100).unwrap();
        assert!(idx.is_blocked("192.0.2.1".parse().unwrap(), 100));
        assert!(!idx.is_blocked("192.0.2.42".parse().unwrap(), 100));
        let mut restored = Engine::restore(e.state()).unwrap();
        assert_eq!(restored.candidates(100)[0].score, 5);
        assert_eq!(restored.snapshot(100).blocks.len(), 1);
        assert!(restored.remove_block("192.0.2.0/24").unwrap());
    }
    #[test]
    fn capacity_and_receiver_time() {
        let mut e = Engine::new(Policy::default()).unwrap();
        for i in 0..MAX_CANDIDATES {
            let ip = IpAddr::V4(std::net::Ipv4Addr::from((i as u32) + 1));
            e.ingest(batch(&ip.to_string(), 100, EventKind::Scanner), 100)
                .unwrap();
        }
        assert_eq!(
            e.ingest(batch("255.255.255.255", 100, EventKind::Scanner), 100)
                .unwrap()
                .accepted,
            0
        );
        assert_eq!(e.stats().dropped_capacity, 1);
        assert_eq!(
            e.ingest(batch("255.255.255.255", 100, EventKind::Scanner), 160)
                .unwrap()
                .accepted,
            1
        );
        assert_eq!(e.candidates(160)[0].first_seen, 160);
    }
    #[test]
    fn ipv6_prefix() {
        let mut e = Engine::new(Policy {
            mode: Mode::Enforce,
            ..Policy::default()
        })
        .unwrap();
        e.add_block(
            Block {
                network: "2001:db8::123/32".into(),
                expires_at: 200,
                reason: "ipv6".into(),
            },
            100,
        )
        .unwrap();
        let idx = PrefixIndex::new(&e.snapshot(100), 100).unwrap();
        assert!(idx.is_blocked("2001:db8:abcd::1".parse().unwrap(), 100));
        assert!(!idx.is_blocked("2001:db9::1".parse().unwrap(), 100));
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Decision {
    pub version: u32,
    pub revision: u64,
    pub action: String,
    pub mode: Mode,
    pub reason: Option<String>,
    pub ttl_ms: u64,
}
impl Engine {
    pub fn decision(&self, ip: &str, now: u64) -> Result<Decision> {
        let ip = canonical_ip(ip)?;
        let mut d = Decision {
            version: 1,
            revision: self.revision,
            action: "allow".into(),
            mode: self.policy.mode,
            reason: None,
            ttl_ms: 5000,
        };
        if self.policy.mode != Mode::Enforce {
            return Ok(d);
        }
        let max = if ip.is_ipv4() { 32 } else { 128 };
        for prefix in 0..=max {
            let n = IpNet::new(ip, prefix)?.trunc();
            if self.allow_index.contains(&n) {
                return Ok(d);
            }
        }
        for prefix in (0..=max).rev() {
            let n = IpNet::new(ip, prefix)?.trunc();
            if let Some(b) = self.block_index.get(&n)
                && b.expires_at > now
            {
                d.action = "deny".into();
                d.reason = Some(b.reason.clone());
                d.ttl_ms = b
                    .expires_at
                    .saturating_sub(now)
                    .saturating_sub(1)
                    .saturating_mul(1000)
                    .min(5000);
                return Ok(d);
            }
        }
        Ok(d)
    }
}

fn block_cost(b: &Block) -> usize {
    100 + b.network.len() + b.reason.len() * 6
}
fn snapshot_budget<'a>(p: &Policy, blocks: impl Iterator<Item = &'a Block>) -> usize {
    1024 + p.allow.iter().map(|s| s.len() + 4).sum::<usize>()
        + blocks.map(block_cost).sum::<usize>()
}
#[cfg(test)]
mod bounded_tests {
    use super::*;
    #[test]
    fn long_window_has_only_64_buckets() {
        let mut e = Engine::new(Policy {
            window_secs: 3600,
            ..Policy::default()
        })
        .unwrap();
        for now in 10000..13600 {
            e.ingest(
                EventBatch {
                    source_id: "test".into(),
                    events: vec![Event {
                        ip: "203.0.113.1".into(),
                        kind: EventKind::Scanner,
                        observed_at: now,
                    }],
                },
                now,
            )
            .unwrap();
        }
        assert!(e.state().aggregates[0].buckets.len() <= 64);
        assert!(e.candidates(17200).is_empty());
    }
    #[test]
    fn remote_decision_expiry_and_restore() {
        let mut e = Engine::new(Policy {
            mode: Mode::Enforce,
            ..Policy::default()
        })
        .unwrap();
        e.add_block(
            Block {
                network: "203.0.113.0/24".into(),
                expires_at: 103,
                reason: "manual".into(),
            },
            100,
        )
        .unwrap();
        let e = Engine::restore(e.state()).unwrap();
        let d = e.decision("::ffff:203.0.113.4", 100).unwrap();
        assert_eq!(d.action, "deny");
        assert_eq!(d.ttl_ms, 2000);
        assert_eq!(e.decision("203.0.113.4", 103).unwrap().action, "allow");
    }
    #[test]
    fn escaped_json_budget_is_conservative() {
        let b = Block {
            network: "203.0.113.4/32".into(),
            expires_at: 100,
            reason: "\0".repeat(128),
        };
        assert!(block_cost(&b) > 768);
    }
}

#[cfg(test)]
mod asn_index_tests {
    use super::*;
    #[test]
    fn duplicate_rejected_atomically_and_longest_ipv6_mapped_prefix() {
        let mut e = Engine::new(Policy::default()).unwrap();
        e.set_asn_catalog(vec![
            AsnPrefix {
                network: "2001:db8::/32".into(),
                asn: 1,
            },
            AsnPrefix {
                network: "2001:db8:1::/48".into(),
                asn: 2,
            },
            AsnPrefix {
                network: "::ffff:192.0.2.0/120".into(),
                asn: 3,
            },
        ])
        .unwrap();
        assert!(
            e.set_asn_catalog(vec![
                AsnPrefix {
                    network: "2001:db8::/32".into(),
                    asn: 9
                },
                AsnPrefix {
                    network: "2001:db8::123/32".into(),
                    asn: 10
                }
            ])
            .is_err()
        );
        assert!(
            e.set_asn_catalog(vec![
                AsnPrefix {
                    network: "192.0.2.0/24".into(),
                    asn: 3
                },
                AsnPrefix {
                    network: "::ffff:192.0.2.1/120".into(),
                    asn: 3
                }
            ])
            .is_err()
        );
        e.ingest(
            EventBatch {
                source_id: "test".into(),
                events: ["2001:db8:1::42", "2001:db8:2::42", "::ffff:192.0.2.42"]
                    .into_iter()
                    .map(|ip| Event {
                        ip: ip.into(),
                        kind: EventKind::Scanner,
                        observed_at: 100,
                    })
                    .collect(),
            },
            100,
        )
        .unwrap();
        let c = e.candidates(100);
        assert_eq!(
            c.iter().find(|c| c.ip == "2001:db8:1::42").unwrap().asn,
            Some(2)
        );
        assert_eq!(
            c.iter().find(|c| c.ip == "2001:db8:2::42").unwrap().asn,
            Some(1)
        );
        assert_eq!(
            c.iter().find(|c| c.ip == "192.0.2.42").unwrap().asn,
            Some(3)
        );
    }
}
