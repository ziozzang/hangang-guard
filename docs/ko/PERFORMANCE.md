# 판단 성능 검증 — 2026-10-12

[English](../PERFORMANCE.md) · [문서 목록](README.md)

AMD Ryzen 7 8745HS/Radeon 780M, 16 logical CPU, release, loopback,
Rust client 8 threads/현재 guard 8 threads. 각 case 2초 warmup+10초 측정.
다른 서비스와 호스트를 공유합니다. 현재 case 모두 100,000 판단/초 초과이며
worker 실패와 latency histogram overflow는 0입니다.

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

## 검증한 부하

Pool은 IPv4/IPv6 정확한 host prefix 20,000개, enforce, 순회 IP 65,536개,
약 30.5% deny이며 나머지는 miss입니다. Cache 없음. 별도 prefix microbench는
혼합 /24·/48 prefix 100,000개와 50% hit를 사용하며 transport 측정과 다릅니다.

GeoIP는 로컬 8,348,509바이트 DBIP-Country-Lite, country 룰 2개, enforce,
서로 다른 8.8.x.x 주소 65,536개입니다. 실제 local decode/dispatch이며 온라인
provider를 측정하지 않습니다. 일반 판단은 immutable view를 사용하고 DB/Lua 호출이 없습니다.

Baseline은 이전 commit `81645cf`, 기본 runtime 16 threads, HashMap prefix probe,
global engine mutex, per-query blocking dispatch입니다. 현재는 중복 auth/JSON allocation
제거 및 runtime 8 threads도 포함하므로 tree만의 효과가 아닌 전체 구조 변경입니다.
같은 연결 32개/pipeline 1 비교를 함께 제공합니다.

첫 HTTP pipeline은 Nagle/delayed-ACK 40ms 대기로 약 45k QPS였습니다.
Accepted HTTP socket의 TCP_NODELAY가 병목을 제거했고 최종 약 492k QPS입니다.
2,048 in-flight queue는 p99를 높입니다. Native TCP는 pool 소켓마다 한 요청만
진행하므로 정상 비교는 pipeline 1이며 별도 client의 수백만 pipelined QPS가 아닙니다.

## 재현

```sh
cargo build --release --workspace
cargo run --release -p guard-core --example prefix_bench
# 별도 checkout에서 81645cf baseline을 빌드하거나 해당 release binary를 보관합니다.
python3 tools/qualify_performance.py --baseline-bin /path/baseline/hangang-guard \
  --geoip-database /path/country.mmdb
```

[원시 결과](../performance-results.json)는 count/deny/CPU/RSS/histogram 해상도와
상한을 포함합니다. Bucket 10µs이며 100ms 이상은 별도 계수합니다. 생성기는 HTTP
status/typed decision 또는 binary correlation/action/frame을 검증합니다.

## 한계

이 호스트의 서비스 transport를 검증했으며 전체 Hangang proxy/origin, 원격 TLS/WAN,
장시간 SLA, LLM per-request 또는 state-changing evidence 100k/sec를 보장하지 않습니다.
CIDR은 합성 dense layout입니다. 실제 prefix/rule/MMDB/hit mix/CPU pinning/durability
부하를 배포 하드웨어에서 검증해야 합니다. 증거 ingest 및 잦은 auto-block view publish는
read-only 조회와 다릅니다. 100,000 entry 한도도 4,000,000바이트 정책 예산에 제한되며
100k prefix microbench가 모든 100k 정책의 저장 가능성을 뜻하지 않습니다.
