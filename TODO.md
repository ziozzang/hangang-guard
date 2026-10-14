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

## Kubernetes ipBlock primitive

Implemented core-only `network_policy::IpBlock`: bounded exception input,
canonical IPv4/IPv6 and mapped addresses, strict subnet validation and per-peer
CIDR subtraction. Exceptions apply to their own peer, not a global deny list;
other peers/policies can still allow that address. This is not activated server
NetworkPolicy enforcement. Destination/port/direction and selector context, API
source ownership, snapshot freshness and CNI qualification remain required.

## Selected network direction core

`SelectedDirection` now evaluates a selector-resolved target/direction with TCP,
UDP or SCTP destination ports and ranges. It distinguishes no selected policy
from isolated default deny; matching rules are additive, with peer and port
conditions intersected within each rule. Empty peers/ports are unrestricted.
Zero destination port is refused for isolated targets. Capacity is bounded across
rules, peers and ports. The source adapter must resolve selectors and named ports,
and independently reconcile ingress/egress. Rule-level matching still scans
bounded candidates and needs a measured index before large-policy performance
claims. No server, native protocol or CNI activation is implied.

Semantics reference: [Kubernetes Network Policies](https://kubernetes.io/docs/concepts/services-networking/network-policies/).

## Label selector predicate core

Added bounded conjunctive `LabelSelector`/`Requirement` predicates: In, NotIn,
Exists and DoesNotExist. NotIn includes absent keys; present empty values remain
distinct from absence. Empty selectors match all objects. matchLabels can compile
into singleton In predicates. Constructors validate operator/value cardinality
and capacity; Kubernetes label syntax remains the API adapter's responsibility.
Apply only to authoritative labels, never request headers. Namespace scope,
combined namespace/Pod selector resolution, source snapshot consistency and server
integration remain open. Reference: [Kubernetes labels](https://kubernetes.io/docs/concepts/overview/working-with-objects/labels/).

## Namespace and Pod peer selector composition

`PodPeerSelector` composes namespaceSelector and podSelector with AND semantics.
Without namespaceSelector, podSelector stays in the policy namespace; an empty
namespaceSelector selects all namespaces, while an empty podSelector alone stays
local. Both selectors absent is rejected by this constructor: the adapter must
represent the all-peer case explicitly. Evaluate only authoritative live Pod and
Namespace facts, with source cluster/UID/freshness fencing still owned by the
adapter. API parsing, selector-to-address materialization and server enforcement
remain open. Core tests cover combined versus separate selectors and empty/absent
scope distinctions. Reference: [NetworkPolicy selectors](https://kubernetes.io/docs/concepts/services-networking/network-policies/#behavior-of-to-and-from-selectors).

## Server selector source adapter

The server now parses Kubernetes LabelSelector JSON with exact matchLabels and
matchExpressions fields and compiles it into the core. Unknown fields/operators,
null maps, invalid operator/value cardinality and oversized inputs are refused.
`sumunjang --check-kubernetes-selector FILE` runs offline without DB/listeners.
This validates shape and predicate bounds, not complete Kubernetes label syntax.
API collection, NetworkPolicy parsing, UID/freshness fencing and request-context
integration remain open; no production policy is activated by this command.

## Kubernetes selector label syntax

The server adapter now validates label names and values (ASCII alphanumeric
boundaries, internal dash/underscore/dot, 63-byte bounds, empty values allowed),
and optional lowercase DNS prefixes with total 253-byte bounds. It rejects invalid
syntax in both matchLabels and matchExpressions. The offline selector check now
includes syntax validation. Policy collection, address materialization and runtime
NetworkPolicy integration remain open. Earlier syntax-deferred notes describe
previous gates and are superseded by this adapter validation.

## Actual Kubernetes selector syntax compatibility

Owned Kubernetes v1.37 server dry-run exposed an overly strict DNS-component
length check in the adapter. Removed that check while retaining the API's total
253-byte prefix bound. The maintained `tools/kubernetes_selector_qualification.py`
compares 12 accepted/rejected syntax boundary cases against the actual API and the
real Sumunjang offline command; all agree. Kubernetes objects are dry-run only,
not persisted. Server selector tests and strict clippy pass. This qualification
covers selector syntax, not collection, reconciliation or NetworkPolicy execution.

## Offline NetworkPolicy evaluation adapter

The server now parses networking.k8s.io/v1 NetworkPolicy target selectors,
namespace scope, policyTypes defaults, ingress/egress rules, ipBlock exceptions,
numeric ports/ranges and TCP/UDP/SCTP into the core evaluator. An offline fixture
contains `policy`, `namespace`, `labels`, `direction`, `peer`, `protocol`, `port`;
`--evaluate-kubernetes-policy FILE` reports not_selected, not_isolated, allowed
or denied without DB/listeners. Inputs are bounded to 1 MiB. Unknown spec/rule
fields, selector peers, explicit empty peers, named ports and contradictory
rules/types are explicitly refused, not broadened. This is a supported subset,
not complete Kubernetes conformance or runtime enforcement. Actual API collection,
peer materialization, UID/source freshness and Hangang context remain open.

## Real API-defaulted NetworkPolicy adapter qualification

The maintained owned-cluster tool now passes actual server dry-run JSON responses
into the real Sumunjang offline policy evaluator. Eight evaluations cover ingress
and egress defaulting, explicit egress isolation, empty-rule allowance, default
TCP, protocol mismatch, CIDR exceptions and numeric endPort. All pass alongside
12 selector syntax acceptance comparisons. No objects are persisted and no CNI
packet enforcement is asserted. This bridges API-returned policy shape to the
implemented evaluator; collection/watch, source freshness and runtime integration
remain open. Run `python3 tools/kubernetes_selector_qualification.py --binary
/path/to/sumunjang` against an owned qualification container.

## Malformed peer API compatibility gate

Owned Kubernetes server dry-run rejects `from: [{}]` (a peer must be specified)
and a peer combining ipBlock with podSelector. The local evaluator's existing
rejections agree; the maintained tool now checks both alongside the 20 positive/
syntax cases. An empty ingress rule `{}` permits all peers, while an empty peer
object is invalid. No empty-peer wildcard support was committed or deployed.

## Compiled NetworkPolicy candidate separation

Server policy compilation now owns an immutable target selector and independently
compiled ingress/egress views. Typed decisions reuse that candidate without JSON
parsing, filesystem, database or API access. Offline evaluation compiles once then
calls the same decision method. Regression mutates the original source, compiles a
new deny candidate and proves repeated old/new decisions remain independent; an
invalid replacement cannot alter the old view. Six adapter tests, strict clippy
and the 22 actual owned-API qualification cases pass. No live publication/freshness
state machine is implemented yet; preserving an old candidate in this unit test is
not permission to serve stale authoritative policy. Production remains unchanged.

## Compiled NetworkPolicy sets

The offline adapter now accepts a bounded NetworkPolicyList and compiles every
item before returning a candidate. It rejects a nonempty list continuation token
and invalid members; an incomplete API page cannot silently become a policy set.
Decision evaluation combines selected policies additively: one applicable allow
wins, while unselected policies or policies isolating only the opposite direction
do not clear another policy's denial. Empty/unselected sets report not_selected;
callers must apply ordinary Kubernetes non-isolation semantics rather than treating
that as a zero-trust authorization grant. Seven adapter tests, strict clippy and
22 owned API regression cases pass. Lists currently scan bounded policy candidates;
large-policy indexing, actual pagination collection and runtime freshness remain
open. No production authority is activated.

## Authenticated Kubernetes source observer

`--observe-kubernetes-policy FILE` reads private source config fields api,
namespace, ca and token_env. It requires an HTTPS origin, pins the configured CA,
disables proxies/redirects and marks bearer headers sensitive. Namespaced list
collection is bounded to 32 pages, 4096 items, 1 MiB and one second across the full
collection/compilation. It validates opaque resourceVersion equality between pages,
namespace/UID facts and continuation cycles; fills only omitted item TypeMeta from
the validated collection. All policies must compile before a count/revision report.
It starts no listeners and changes no DB or policy authority.

`tools/kubernetes_source_smoke.py` qualifies the actual executable against an owned
Kubernetes API using a temporary namespace and list-only ServiceAccount. Successful
collection/compilation, invalid-token refusal and cross-namespace RBAC refusal pass;
cleanup deletes only its fixture namespace. Strict server clippy passes. Malicious
pagination/TLS/timeouts, source publication, watch recovery, rotation/pooling and
contextual enforcement remain open. This observer is not production activation.
