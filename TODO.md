# TODO

[한국어](TODO.ko.md) · [Documentation](docs/README.md)

## Original requirements

Build a security service for Hangang (`~/hangang`) that analyzes request signals
and blocks IPs in real time according to policy. Hangang's native zero-trust
mechanism should support first-class integration.

Example workflow:

1. Record explicit honeypot evidence.
2. Resolve the source IP's ASN.
3. Add IPs exceeding the threshold to the block candidate list (BCL).
4. Retrieve the IP prefix pool associated with a proposed ASN block.
5. Determine allowlists, possibly with reviewed LLM assistance.
6. Decide the scope of IP ranges to block.

Requirements: per-request queries or an embedded policy mechanism, dashboard
management, dynamic policies, extremely fast block-pool lookup, and consideration
of GeoIP in guard. Design thoroughly before implementation; use sub-agents for
independent implementation units and consider cost. Existing running servers may
be used for testing when deployment conditions are established.

Research similar tools, attack-pattern collection and updateable pattern feeds.
Implement in Rust with low resource use. Databases are for persistence/checkpoints,
not every decision; do not retain all request logs. The original working name
`hangang-flogging` was considered before choosing `hangang-guard`.

## Accepted direction — 2026-10-12

- Project: `hangang-guard`; retain workspace directory `hangang-safe`.
- Rust service with native first-class Hangang support; modifying Hangang is authorized.
- Hangang queries guard on every request by default. Cache is optional and strictly limited to a 1–5 second TTL.
- Procedure: design/review → independent sub-agent implementation → real-process integration verification → commit/push. Protect existing Hangang edits with a separate worktree.
- Initial implementation: observe/enforce policies, BCL and reviewed approval, CIDR allow/block/expiration, dashboard, bounded aggregation, SQLite checkpoints, per-request decisions and optional short cache.
- Next phases: online ASN prefix refresh, ASN proposal impact analysis, authenticated attack-pattern updates with provenance/version/rollback, and GeoIP operational policy.
- Guard is the IP/network policy and risk component of the zero-trust backbone.
  Hopae manages users/principals. Guard must not duplicate accounts or sessions;
  future scope expansion should preserve that responsibility boundary.
- English is the primary documentation language; Korean translations accompany it.

## Prompt-based request inspection and LLM queries

User-requested investigation: inspect request patterns according to operator
prompts and use LLM queries for analysis. Decide implementation after design.

- [ ] Design prompt policies defining inspection goals, criteria and output schemas.
- [ ] Compare synchronous per-request queries with asynchronous aggregate analysis:
      latency, cost, throughput, failure behavior, and interaction between optional
      1–5 second decision cache and policy changes.
- [ ] Select minimum inputs: method/path structure, status/frequency/time patterns,
      honeypot/scanner evidence. Decide header/body inclusion through explicit policy;
      remove or mask tokens, cookies and personal data. Bound input and aggregate sizes.
- [ ] Treat attacker-controlled request strings and prompt injection as untrusted
      data, separate from system prompts, operator policy and tool permissions.
      Validate structured output and retain decision provenance.
- [ ] Design provider/model/prompt versioning, cost budgets, timeouts, concurrency,
      circuit breakers, retries/deduplication and result expiration. Invalidate
      relevant cache entries when prompt policies change.
- [ ] First evaluate LLM results as candidates/explanations. Before automatic
      enforcement, design deterministic policy gates, false-positive validation,
      shadow evaluation and rollback. Do not grant allowlist mutation or ASN-wide
      blocking authority without separate review.
- [ ] Show prompt policies, results, rationale, cost, latency and approval status
      in the dashboard. Build reproducible benign/attack evaluation datasets and criteria.

## Performance, policy and management expansion — 2026-10-12

- [x] Compressed radix-tree IPv4/IPv6 pools and immutable lock-free decision views.
- [x] Qualify the 10,000–100,000 decisions/sec target with actual transport load tests.
- [x] Connection reuse, once-per-connection authentication, fixed 24-byte binary protocol and native integration.
- [x] Admin search/sort/pagination and structured policy/allowlist editing.
- [x] Offline GeoIP Country/City/ASN, admin lookup and last-good reload.
- [x] IP/CIDR scores, suspicion stages and matched rule explanations.
- [x] Similar-tool research, embedded Lua and JSON RuleSet validation/application.
- [ ] Sustained load, failures and distributed deployment qualification with full proxy/production traffic.
- [ ] Design prompt-based LLM inspection using the checklist above.
- [x] User confirmed that embedding means an embedded Lua runtime; implemented Lua 5.4.

## Native Hangang console
- [x] Trusted pinned Guard menu package, host authentication and native theme.
- [x] Reproducible generation and host credential/role/audit bounds.
- [ ] Coordinate verified package activation with runtime auto-updates; host pins remain explicit.
