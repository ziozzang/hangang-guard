# Decision performance qualification — 2026-10-12

[한국어](ko/PERFORMANCE.md) · [Documentation index](README.md)

Measured on AMD Ryzen 7 8745HS w/ Radeon 780M Graphics (16 logical CPUs), release builds,
loopback, Rust load client 8 threads, current guard 8 threads. Each case warms up 2 s
then measures 10 s. Other services share the host. All current cases exceed 100,000
decisions/sec with zero failed workers and zero latency histogram overflow.

| Case | Connections / pipeline | QPS | p99 upper ms | RSS MiB | Server CPU cores |
| --- | ---: | ---: | ---: | ---: | ---: |
| baseline-http-empty | 32 / 1 | 249,899 | 0.31 | 19.4 | 7.51 |
| baseline-http-pool-v4 | 32 / 1 | 214,288 | 0.42 | 42.2 | 7.68 |
| baseline-http-pool-v6 | 32 / 1 | 116,900 | 1.54 | 44.3 | 4.83 |
| http-empty | 32 / 1 | 345,510 | 0.29 | 9.4 | 6.58 |
| http-pool-v4-comparable | 32 / 1 | 308,672 | 0.32 | 26.8 | 6.11 |
| http-pool-v6-comparable | 32 / 1 | 328,179 | 0.30 | 28.3 | 6.30 |
| http-pool-v4 | 128 / 1 | 354,793 | 1.05 | 31.2 | 6.78 |
| http-pool-v4-pipeline | 128 / 16 | 492,497 | 10.15 | 29.4 | 7.94 |
| tcp-empty | 64 / 1 | 526,596 | 0.46 | 8.5 | 4.37 |
| tcp-pool-v4 | 128 / 1 | 647,103 | 0.78 | 26.8 | 5.41 |
| tcp-pool-v4-pipeline | 64 / 16 | 7,322,022 | 0.50 | 26.1 | 4.42 |
| tcp-pool-v6 | 128 / 1 | 647,247 | 0.77 | 27.4 | 5.55 |
| tcp-pool-v6-pipeline | 64 / 16 | 8,700,191 | 0.47 | 26.7 | 5.40 |
| http-geoip-rules | 32 / 1 | 318,992 | 0.31 | 17.6 | 6.40 |
| tcp-geoip-rules | 128 / 1 | 648,363 | 0.76 | 17.5 | 5.72 |

## What was tested

Pool cases use 20,000 exact IPv4/IPv6 host prefixes, enforce mode, 65,536 cycled
IPs and approximately 30.5% denied responses. Other IPs miss the block pool. No
decision cache is enabled. Prefix microbench also covers random mixed /24 and /48
networks with 100,000 prefixes and 50% hits; it is separate from transport measurements.

GeoIP cases load the existing 8,348,509 byte DBIP-Country-Lite offline database and
apply two country rules in enforce mode over 65,536 varied 8.8.x.x addresses. This
tests live local decoding/rule dispatch, not an online GeoIP provider. All ordinary
decisions use immutable read views; none issue DB queries or execute Lua.

Baseline is commit 81645cf (previous release), using 16 default runtime threads,
HashMap prefix probing, global engine mutex and per-query blocking dispatch.
Current changes also remove duplicate auth/JSON intermediate allocations and use
8 runtime threads; baseline comparisons measure the whole architecture change,
not only the tree. Equal 32 connection/one-query cases are provided for comparison.

The first HTTP pipeline sample exposed 40 ms Nagle/delayed-ACK waits (~45 kQPS).
Enabling TCP_NODELAY on accepted HTTP sockets removed that transport bottleneck.
Final pipeline case reaches ~492 kQPS; queueing 2048 in-flight requests naturally
raises p99 relative to one-request-per-connection. Native TCP currently uses one
outstanding query per pooled socket; its normal comparison is pipeline 1, not the
millions/sec pipelined standalone-client numbers.

## Reproduce

```sh
cargo build --release --workspace
cargo run --release -p guard-core --example prefix_bench
# Rebuild baseline in an isolated checkout at 81645cf, or save its release binary.
python3 tools/qualify_performance.py --baseline-bin /path/baseline/hangang-guard \
  --geoip-database /path/country.mmdb
```

[Raw results](performance-results.json) include counts, denial counts, CPU seconds,
RSS and histograms resolution/cap metadata. Latency buckets have 10 µs resolution;
samples ≥ 100 ms are counted separately rather than hidden. The generator checks
HTTP status/typed decision, or binary correlation/action/frame validity.

## Limits

This qualifies the decision service transport on this host. It does not establish
full Hangang proxy/origin throughput, remote TLS/WAN capacity, long-duration
production SLA, LLM per-request throughput or 100k state-changing evidence events/sec.
CIDR catalogue used here is synthetic and densely arranged. Real prefix layouts,
rule counts, MMDB providers, metadata hit/miss mixes, CPU pinning and durability
traffic should be profiled on the deployment hardware. Evidence ingestion and
frequent automatic block publication have different costs from read-only lookup.
The 100,000 entry numeric cap is also subject to 4,000,000 byte policy budget; standalone
100k-prefix microbench does not imply every 100k-entry policy fits that budget.
