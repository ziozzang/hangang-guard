# Native Kubernetes policy authority

[한국어](ko/KUBERNETES_AUTHORITY.md)

This opt-in source makes one authenticated `SumunjangPolicy` object authoritative
for Sumunjang's existing native IP decision engine. It does not activate CNI or
translate standard Kubernetes NetworkPolicy into an IP-only `Network.Check`.
The existing `--kubernetes-policy-source` NetworkPolicy diagnostics remain separate.

Install the CRD, namespace and example object in
[deploy/sumunjang-native-policy.yaml](../deploy/sumunjang-native-policy.yaml).
Install the CRD first and wait for `Established` before creating the object.
The example includes a read-only ServiceAccount/Role limited to GET of one name.
Administrator write access to that object is policy authority; grant it separately.
Read its generated UID and configure an administrator-owned JSON file:

```json
{
  "api": "https://kubernetes.default.svc",
  "namespace": "hangang-security",
  "name": "native-ip-policy",
  "uid": "REPLACE-WITH-ACTUAL-OBJECT-UID",
  "ca": "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt",
  "token_env": "SUMUNJANG_KUBERNETES_TOKEN"
}
```

Set the referenced environment variable from the mounted ServiceAccount token
using your service's credential injection. The config stores a reference, never
a token value. Restart the source process when rotating environment credentials.
Alternatively configure `token_file` instead of `token_env` (exactly one is
required). A bounded projected token file and the CA file are reread each cycle,
so file rotation does not retain a previous credential pool. Use reviewed server/service identities and mTLS
for Sumunjang's own remote decision/management endpoints as usual.

```sh
sumunjang --kubernetes-authority /etc/sumunjang/native-source.json \
  --database /var/lib/sumunjang/policy.sqlite3
```

A [Deployment template](../deploy/sumunjang-native-authority-deployment.yaml)
uses a rotating projected token file, localhost-only HTTP administration, remote
mTLS binary/gRPC, and HTTPGet `/readyz` on a separate `--readiness-listen` port. Replace the image with
a separately qualified native-authority build and set the actual UID. Existing
public 0.3.5 artifacts do not include this feature. Precreate the distinct API
credential Secret and TLS Secret; the template does not generate or publish
credentials. A scratch image needs only the static executable; the probe needs no
shell, wget or TLS client utility. Config
identity is loaded once; restart after changing the source pin/config file.

`--check` validates config and clock capability without contacting the cluster;
it does not prove activation. Source mode conflicts with `--policy`,
`--bootstrap-policy` and `--asn-catalog`. Native source requires a suspend-inclusive
clock (currently Linux BOOTTIME); default local DB mode has no new clock requirement.

The CRD `spec` contains normal bounded native `policy`, optional `rules`, `blocks`
and `asn_catalog`. Existing validators, prefix trees, GeoIP matching, priorities,
allowlist and block semantics run unchanged in the same compiled DecisionView.
`auto_block` must be false: event aggregation and all competing policy/rule/block/
Lua/GeoIP reload writers are disabled. Startup GeoIP files remain an independently
configured, immutable process catalog for native geographic rules; they are not
Kubernetes Pod identities. There is no second policy overlay or per-query API call.
Malformed or unsupported native spec fields fail the entire observation.

The source performs an authenticated HTTPS GET of exactly the pinned namespaced
name, with pinned CA, no ambient proxy/roots or redirect following. The returned
kind, namespace, name and UID must match; deletionTimestamp, missing resourceVersion,
replacement UID, non-200, timeout, oversized response or compile/persist failure
withdraw authorization. ResourceVersion is opaque, not a numeric ordering claim.
The original one-second process-local BOOTTIME lease begins before credential,
TLS, transfer, decode, compile and durable publication work; all consume that
budget. Successful cycles wait 500ms before the next GET and withdraw the prior
publication before collection. A newly authenticated complete GET may renew an
unchanged resourceVersion; rereading a captured publication never renews it.

Every HTTP/binary/gRPC decision is gated by the exact native view and its source
publication generation, with TTL capped by the remaining original source lease.
Expiry, reversed clock observations or read failure irreversibly retire that
publication. A later fresh GET may create a new generation but cannot revive a
captured old view. Cancellation/task exit withdraws the source. Checkpoint state
cannot grant while a restarted source process awaits its first authenticated GET.
The process mode must remain configured across restarts; deliberately removing
`--kubernetes-authority` returns to the operator-selected local DB mode.
Native timed blocks/rules retain their documented UTC semantics; the BOOTTIME
source lease does not redefine those independent native policy conditions.

`--readiness-listen` is optional and absent by default. Its separate plain HTTP
listener accepts only exact GET `/healthz` and `/readyz`, with fixed empty status
replies; it exposes no policy, credentials, source identity or management routes.
It reuses the shared bounded connection owner (16 sockets, 2048-byte headers,
one-second request/write and drain bounds), refuses request bodies/ambiguous
framing, and closes after one request. The Linux supervisor owns/inherits that
listener through worker replacement and shutdown. Kubernetes HTTPGet can use it
with a scratch image while management remains mTLS.

`/healthz` is process liveness. Use `/readyz` for readiness: it returns 503 until a
current source is available, and again on expiry/withdrawal. Authenticated
`GET /v1/kubernetes/authority` exposes enabled/available, phase, opaque source
resource_version and remaining_ms without credentials. Those remaining values are
local observations, not transferable signed authorization. Manual mutation
requests are rejected before body/Lua decoding. Legacy reusable `/v1/snapshot`
is disabled in source mode because its format cannot carry the source lease.
The Hangang console plugin displays source authority/freshness and disables
manual mutations. Local DB behavior is retained when the source is absent.

Qualification must distinguish owned TLS fixture tests from a live Kubernetes
cluster. The independent live test below does not qualify API-server failover, long-term
ServiceAccount token expiry/rotation, watch/relist, or CNI.
This is bounded polling of one native policy object, not a watch controller.

## Live native-source qualification (2026-10-15)

The independent live K3s test passed at source
`60f19a50a0b29dd44c0d3656629978de0696e0f6`: actual ServiceAccount GET/CA,
mTLS native allow/deny and policy update, RBAC withdrawal/readiness, same-Pod
container restart with its existing checkpoint, deletion/replacement UID refusal,
and explicit repin/new-Pod recovery. Only the newly owned namespace and absent
CRD were created, then their identities were checked before cleanup. Existing
workloads, PVs, Services and DNS were preserved; both nodes and existing HTTP
services remained healthy. Source/core tests total 141 and strict Clippy and
actual Chromium plugin checks also passed.

The exact qualification static binary SHA256 is
`7078befe3d12a570ad597fa2a1babc7c1234d8c3440361d4376e58deacce0a61`.
Unique image ID is
`sha256:4305a666125b23ec2319d684578cf91e3d3e6597ab038232ed7975df0e1aeaac`,
using utility base
`alpine@sha256:d9e853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc`.
The utilities support wget exec readiness and same-Pod PID1 restart; a scratch
image without shell/wget cannot run that probe. No public artifact was replaced.
This proves the independent native source, not the new source's full four-service
or browser authorization chain, watch/CNI enforcement, long-term token rotation,
API-server failover or injected suspend. The separate 0.3.6 source version is being
prepared; signing, release and new-source chain qualification remain separate gates.

## Final 0.3.6 scratch and four-service qualification

The final embedded-dashboard fix and matching plugin at source
`d6fc1dec893df963c30f483ddf755421a98920b4` passed both real K3s modes:
exclusive Kubernetes native source and unchanged local DB ownership. Each run
used the actual four servers, independent observed SDK receipt verification,
paired credential projection and the real administrator browser. The source
run also proved scratch HTTPGet readiness, CRD-authored block403/unblock200,
manual mutation409, RBAC withdrawal/readiness503, checkpoint-preserving Pod
replacement without dispatch, UID replacement refusal, and explicit repin/new
source recovery. Refused protected requests did not increment the backend counter.
Only the newly owned namespaces and exact created CRD were removed; global CRD
cleanup uses UID/resourceVersion delete preconditions after instance absence
checks and assumes no concurrent native-source operator.

Final static Sumunjang SHA256:
`25a197f1c39bddf63fe4c168294536475ed2b4ba2aa16bcbe7ee4ac2dfec8654`.
The matching scratch image ID is
`sha256:9e945256233a035cad07910e6de977c53e8511e3d62d0f83df49c8dfc894df08`.
The previous candidate exposed a real default-mode UI bug: inputs disabled while
source status was unknown did not all unlock after local DB ownership was known.
The final fix restores input states while retaining credential/busy/CAS/data locks;
source or unknown/error status stays locked. Both actual browser modes passed
with the rebuilt embedded dashboard and matching plugin. Source tests total147,
strict Clippy, package8, standalone/plugin Chromium and final-static supervised
HUP/readiness/shutdown checks passed. No published 0.3.5 artifact was modified.

These functional results do not prove watch/CNI enforcement, API failover,
long-term token rotation, injected suspend or every legacy consumer cache clock.
Source BOOTTIME eligibility and the observed chain do not change the frozen
classic Hangang network cache's existing Instant-based timing contract. Signing,
release and operating adoption remain controlled separately.
