# Validation — 2026-10-12

[한국어](ko/VALIDATION.md) · [Documentation index](README.md)

## Checks
- Guard core: 10 tests passed, including bounded ASN prefix lookup and duplicate validation.
- Guard service: 6 API/auth/body/persistence/decision/dashboard-header tests passed.
- Guard workspace: formatting, strict Clippy and release build passed.
- Native Hangang: 9 new guard tests passed, binary build and strict Clippy passed.
- Existing Hangang proxy regressions: all 70 tests passed.
- Real-process E2E passed with release guard + native debug Hangang: collector/admin
  credential separation; observe honeypot candidate; reviewed approval; native 403;
  no self-renewal; allow precedence; query failure 503; SQLite restart restoration;
  optional 1-second cache expiry; explicit fail-allow. Processes use temporary ports,
  tokens and databases. No operating gateway restart or config mutation occurred.

## Small local performance sample

Command: `python3 tools/bench_decision.py` using optimized guard, empty observe
policy, 8 Python clients, 2,000 decisions over loopback HTTP keep-alive.

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

## Performance/rules/operator extension verification
- Core 20 tests, service 18 tests, native 14 guard tests and 70 existing proxy regressions pass.
- Rust format/strict Clippy, release builds and credential scan pass.
- Extended real-process E2E: native binary decisions, GeoIP City/reload last-good,
  Lua dry-run/apply, IP risk, CIDR inspection, snapshot rejection, durable rules and
  authority restart/reconnect.
- Chromium browser regression: 10k candidates/100k blocks test fixtures, ≤100 DOM
  rows, search/pagination, all administrator flows, risk/GeoIP/JSON/Lua, mobile layout,
  unsaved draft preservation, XSS-safe rendering and malformed response feedback.
- Final 15 transport workload cases: 12 current configurations above 100 kQPS, zero
  errors/histogram overflow. See PERFORMANCE.md and raw JSON.
