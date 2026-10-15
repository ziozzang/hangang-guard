# gRPC network decisions

Caller authentication also runs before generated protobuf decoding. Bearer
credentials belong in initial metadata; a credential supplied only in trailers
is refused without polling the body. Native handler checks and the 2,048-byte
message cap remain. A shared predecode budget admits at most
`min(max_http_requests, 256)` service futures across this listener's connections,
independently of handler admission. Exhaustion refuses before body polling.
The shared runtime accepts exactly one uncompressed unary frame and counts actual
DATA bytes, capped at 2,053 bytes including its prefix. Fragmentation is supported;
extra frames, truncation and excess bytes fail closed without custom protobuf
parsing. Prost and its existing per-message cap remain in place.

At the default cap, simultaneous accepted encoded input is at most 513.25 KiB
(256 × 2,053 bytes). This is a wire-data planning bound, not a process memory
bound: decoded objects, HTTP/2 buffers and response bodies have separate costs.
The permit lasts through decoding and handler completion/cancellation; it does
not cover response draining or preempt synchronous CPU work.

[한국어](ko/GRPC.md)

`--grpc-listen IP:port` adds `hangang.sumunjang.v1.Network/Check` alongside HGD1.
Configure `--decision-listen`, `--decision-tls-cert`, `--decision-tls-key` and
`--decision-client-ca`. Client certificates are mandatory, including on loopback.
RPC metadata must contain exactly one `authorization: Bearer <collector credential>`;
the admin credential is rejected. Keep keys outside command arguments and logs.

Requests contain a correlation ID, packed IPv4 (4 bytes) or IPv6 (16 bytes), and a
minimum revision. Responses distinguish allow, deny and unavailable, and observe
from enforce. A revision floor above the snapshot returns unavailable with zero
TTL. This endpoint uses the same network/GeoIP snapshot as HGD1; no request-time SQL.
Observe allow is not proof of enforced admission. Kubernetes collection remains
read-only diagnostics and is not promoted to runtime NetworkPolicy enforcement.

The pinned [Hangang runtime](https://github.com/ziozzang/hangang-runtime) caps
connections at 2,048, streams/concurrency at 64 per connection, headers at 8 KiB,
TLS files at 1 MiB and request timeout at 1 second. Decode/encode bounds are 2/1 KiB.
The gRPC decision quota is bounded independently from HTTP admission. Compression
is not enabled. Request timeout does not preempt blocking handler work.

Linux supervised mode retains the gRPC listener during HUP/update replacement.
Clients must tolerate reconnection; this does not guarantee interruption-free RPCs.

Build requires `protoc`. Qualification uses an isolated Python environment with
`grpcio` and `grpcio-tools`:

```sh
cargo build -p guard-server --bin sumunjang
python tools/grpc_smoke.py --binary target/debug/sumunjang
```

The owned fixture proves mTLS refusal, role isolation, malformed/oversized input,
native parity, revision fencing, immediate policy changes, and HUP listener handover.
Actual Kubernetes gRPC deployment, Hangang gRPC clients and public release artifacts
are separate unfinished gates.

## Final snapshot fence (unreleased)

Check captures the exact immutable policy view and, when required, GeoIP catalog
before evaluating. Before replying it rechecks their Arc identities. Policy
replacement at the same numeric revision and GeoIP replacement discard the
candidate and return unavailable/unspecified mode/zero TTL. TTL is capped at
five seconds. Tests exercise both owner replacements and existing caller/quota/
revision-floor gates. This is a local response fence, not a signed network receipt
or distributed owner lease. Pumgye receipt/permit integration remains separate.
