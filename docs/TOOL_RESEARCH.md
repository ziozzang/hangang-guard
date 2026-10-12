# 보안 도구 조사와 반영 계획 — 2026-10-12

공식 문서를 기준으로 기능을 비교한다. 특정 도구와 프로토콜/룰 호환을 구현한
것은 아니며, 검증 가능한 설계 아이디어와 운영 기능을 흡수한다.

| 도구 | 참고 기능 | hangang-guard 반영 |
| --- | --- | --- |
| CrowdSec | 조건 필터, source별 bucket, 중복 구분, 탐지와 차단 분리, allowlist 단계 | IP 시간창 점수, threshold/BCL, observe/enforce, whitelist 우선순위. distinct 공격 패턴과 다중 시나리오는 후속 확장 |
| Fail2Ban | findtime/maxretry/bantime, 동적 필터·action 설정 | window/threshold/TTL 정책, 관리자 즉시 설정 변경, 만료·해제 |
| BunkerWeb | IP/ASN/country 블랙리스트, bad behavior, 관리 설정 | IPv4/IPv6 CIDR +GeoIP/ASN, 동적 범위·국가·ASN 룰, 조회/점수 UI. 봇 challenge/captcha는 후속 |
| OWASP Coraza/CRS | 룰 id/우선순위, 관찰 모드, anomaly score, phase별 검사 | 룰 id/priority/reason과 risk score·의심 단계, dry-run·원자적 적용. 전체 request/body WAF 호환은 별도 과제 |
| MaxMind | 오프라인 MMDB, country/city/ASN, metadata·accuracy radius | 로컬 DB 조회, 메타데이터 상태, 마지막 정상 DB 유지·reload, 관리자 조회 |

근거:
- [CrowdSec scenarios](https://docs.crowdsec.net/docs/log_processor/scenarios/intro/)
- [CrowdSec whitelists](https://docs.crowdsec.net/u/getting_started/post_installation/whitelists/)
- [Fail2Ban client](https://github.com/fail2ban/fail2ban/blob/master/man/fail2ban-client.1)
- [BunkerWeb features](https://docs.bunkerweb.io/latest/features/)
- [BunkerWeb security tuning](https://docs.bunkerweb.io/security-tuning/)
- [Coraza actions](https://coraza.io/docs/seclang/actions/)
- [Coraza internals](https://www.coraza.io/docs/reference/internals/)
- [MaxMind accuracy](https://support.maxmind.com/knowledge-base/articles/maxmind-geolocation-accuracy)

GeoIP는 정확한 개인 위치가 아니라 네트워크에 대한 추정 정보다. unknown을
별도로 다루고 국가·ASN 하나를 악성의 증거로 자동 단정하지 않는다.

## 룰 런타임 결정
Rust에 Lua54를 임베딩하지만 운영자가 설정을 적용할 때만 실행한다. Lua는
RuleSet 테이블을 반환하고 검증한 뒤 내부 판단 구조로 컴파일한다. 질의당 Lua
VM 생성/스크립트 실행을 하지 않는다. JSON RuleSet도 같은 검증·배포 경로를 쓴다.

스크립트32KiB, Lua 메모리4MiB, 명령어100,000/실행50ms budget을 적용하며
파일/네트워크/프로세스 접근을 제공하지 않는다. 룰은 id, priority, 조건
(CIDR·country·ASN), score, action, 선택적 만료로 구성한다. 실제 schema와
우선순위/의심 단계는 구현 검증 후 RULES.md에 기록한다.

IP 점수와 CIDR 집계 점수는 구분한다. 일부 IP가 의심스럽다는 이유만으로
전체 네트워크를 자동 차단하지 않는다. CIDR 점수는 unique IP수·합계·최대
IP점수와 함께 표시해 운영자가 영향 범위를 판단할 수 있게 한다.
