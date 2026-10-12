# Validation — 2026-10-12

## Checks
- Guard core: 10 tests passed, including bounded ASN prefix lookup and duplicate validation.
- Guard service: 6 API/auth/body/persistence/decision/dashboard-header tests passed.
- Guard workspace: formatting, strict Clippy and release build passed.
- Native Hangang: 9 new guard tests passed, binary build and strict Clippy passed.
- Existing Hangang proxy regressions: all 70 tests passed.
- Real-process E2E passed with release guard + native debug Hangang: collector/admin
  credential separation; observe honeypot candidate; reviewed approval; native403;
  no self-renewal; allow precedence; query failure503; SQLite restart restoration;
  optional1-second cache expiry; explicit fail-allow. Processes use temporary ports,
  tokens and databases. No operating gateway restart or config mutation occurred.

## Small local performance sample

Command: `python3 tools/bench_decision.py` using optimized guard, empty observe
policy,8 Python clients,2,000 decisions over loopback HTTP keep-alive.

| Measurement | Observed |
| --- | ---: |
| Total time | 0.213 seconds |
| Requests/second | 9,409 |
| p50 | 0.752 ms |
| p95 | 1.579 ms |
| p99 | 2.109 ms |
| Guard RSS | 7,764 KiB |

This includes Python client overhead and loopback transport. It is a small sample,
not maximum capacity or a production SLA. It does not qualify large block catalogs,
filled candidate windows, concurrent durable admin commits, TLS or distributed
traffic. Test those workloads before selecting production capacity/timeouts.

## Remaining qualification
- Native functionality requires upgrading the deployed Hangang image; existing
  production gateway currently lacks the new module.
- Observe-only production rollout and realistic traffic/candidate memory profiling.
- Remote TLS, sustained load, multi-instance credentials/audit history.
- Online ASN refresh, attack-pattern feeds and LLM inspection are explicit TODOs.
