# 운영 절차

## 적용 단계
1. Collector/admin 토큰을 분리 발급하고 환경 파일 권한을 0600으로 설정한다.
2. Guard를 loopback에서 observe로 실행하고 DB 디렉터리에 쓰기 권한을 준다.
3. 별도 Hangang 인스턴스에서 요청별 질의·장애 처리를 검증한다.
4. 운영 gateway 업그레이드 시 native guard 플래그를 추가하고 observe를 유지한다.
5. 실제 허니팟 경로와 정상 관리 IP/CIDR을 검토한다. 일반 403을 공격으로 세지 않는다.
6. 후보·오탐과 질의 지연을 확인한 뒤 enforce 및 수동 승인부터 시작한다.
7. 자동 차단은 제한된 IP 정책에서 켠다. ASN-wide 자동 차단은 사용하지 않는다.

기존 운영 Docker gateway는 `/docker/hangang/gateway`를 데이터 볼륨으로 사용한다.
이번 작업의 통합 테스트는 별도 포트와 임시 설정에서 수행한다. 운영 컨테이너
재시작·이미지 교체·강제 차단 활성화는 이 초기 검증에 포함하지 않는다.

## 장애와 복구
- Query 기본은 guard 장애/타임아웃/잘못된 응답 시503이다. 인증이 중요한
  경로에 적합하지만 guard 가용성이 gateway 가용성에 영향을 준다.
- `--guard-failure-mode allow`는 장애 시 guard 검사를 허용하되 기존 인증은
  계속 수행한다. 장애 가용성이 우선인 경로에 선택한다.
- 캐시는 기본 비활성화. 활성 TTL은1~5초이고 장애 시 무기한 연장하지 않는다.
- Snapshot 모드는 마지막 정상 정책을 만료까지 유지하고 이후 guard 차단을
  중지한다. Query와는 장애 의미가 다르므로 명시적으로 선택한다.
- SQLite 정책 변경은 성공 응답 전에 트랜잭션으로 저장한다. 집계와 자동
  판단은5초 checkpoint 및 정상 종료 시 저장하므로 crash 때 최근 집계를 잃을
  수 있다. WAL/SHM을 고려해 SQLite backup API 또는 정지 상태에서 백업한다.
- 관리자 정책 변경의 직렬화·복제·fsync가 질의를 일시 지연시킬 수 있다.
  체크포인트는 메모리 잠금을 해제한 뒤 직렬화/fsync한다. 대규모 운영 전
  실제 rule 수로 지연·메모리를 측정하고 타임아웃을 조정한다.

## 자원 제한
Tracked IP 최대10,000, IP별 집계 bucket 최대64, block 최대100,000,
정책 snapshot 보수적 JSON budget4,000,000바이트, HTTP body4MiB,
배치256, 서버 요청 동시 수64, blocking 작업 상한1,024. 숫자 제한보다 byte budget이 먼저 적용될
수 있다. 시간창이64초보다 크면 bucket 경계의 부분 증거를 보수적으로 버린다.
원시 요청 로그나 body/토큰은 저장하지 않는다.

## ASN catalog

`--asn-catalog path.json`으로 운영자가 제공한 prefix 목록을 로드한다.
형식은 `[{"network":"192.0.2.0/24","asn":64500}]`이다. 정확한 ASN 제공자,
갱신 주기와 검증 방식이 정해지기 전에는 온라인 자동 갱신을 활성화하지 않는다.
ASN은 IP 후보 목록에 표시하는 분류 정보이고 광역 차단의 근거로 단독 사용하지 않는다.

## 되돌리기

Guard 정책을 observe로 바꾸면 다음 질의 또는 캐시 TTL 이내에 guard 차단이
해제된다. Guard 장애로 query fail-deny가 동작할 때는 guard 복구 또는 Hangang
플래그 변경/재시작이 필요하다. Native 기능 전체 해제는 `--guard-url`을 제거한다.
기존 Hangang zero-trust 인증과 방어 기능은 독립적으로 유지된다.
