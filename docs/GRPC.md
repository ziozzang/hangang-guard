# gRPC network decisions

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
