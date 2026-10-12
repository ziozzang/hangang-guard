# 검증 — 2026-10-12

[English](../VALIDATION.md) · [문서 목록](README.md)

## 초기 검사

- Guard core 10개: bounded ASN prefix 조회 및 중복 검증 포함.
- Guard service 6개: API/auth/body/영속성/판단/대시보드 header.
- Workspace format, strict Clippy, release build 통과.
- Hangang 신규 guard 9개, binary build, strict Clippy 통과.
- 기존 proxy 회귀 70개 통과.
- Release guard+debug Hangang 실제 E2E: collector/admin 분리, observe 후보,
  승인→403, 자기 증거 갱신 방지, allow 우선, query 장애→503, SQLite 복구,
  선택적 1초 cache 만료, 명시적 fail-allow. 임시 port/token/DB 사용이며 운영 변경 없음.

## 초기 소규모 성능 표본

`python3 tools/bench_decision.py`: optimized guard, 빈 observe 정책,
Python client 8개, loopback HTTP keep-alive 2,000개 판단.

| 측정 | 결과 |
| --- | ---: |
| 총 시간 | 0.213초 |
| 요청/초 | 9,409 |
| p50 | 0.752ms |
| p95 | 1.579ms |
| p99 | 2.109ms |
| RSS | 7,764KiB |

Python 비용과 loopback을 포함한 작은 표본이며 최대 용량/SLA가 아닙니다.
대규모 catalog, 가득 찬 후보 window, 동시 durable commit, TLS/분산 트래픽은
포함하지 않았습니다. 용량/timeout 선택 전 해당 부하를 검증해야 합니다.

## 남은 검증

- 기존 운영 이미지에는 모듈이 없으므로 네이티브 지원 이미지 업그레이드 필요.
- Observe 운영 배포 및 실제 traffic/후보 memory profiling.
- 원격 TLS, 지속 부하, 다중 인스턴스 credential/audit.
- 온라인 ASN refresh, pattern feed, LLM은 명시적 TODO.

## 성능·룰·관리 화면 확장 검증

- Core 20개, service 18개, native guard 14개, 기존 proxy 70개 통과.
- Format/strict Clippy/release build/credential scan 통과.
- 확장 실제 E2E: native binary, GeoIP City/reload last-good, Lua dry-run/apply,
  IP/CIDR 검사, snapshot 거부, 영속 룰, authority 재시작/reconnect.
- Chromium: 후보 10k/block 100k fixture, DOM 100행 이하, 검색/page,
  관리자 흐름/risk/GeoIP/JSON/Lua/mobile/미저장 초안 유지/XSS/잘못된 응답 표시.
- 최종 transport 15개 case 중 현재 구성 12개 모두 100k QPS 초과,
  오류/histogram overflow 0. [PERFORMANCE.md](PERFORMANCE.md)와 raw JSON 참조.
