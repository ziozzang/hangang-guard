# Kubernetes 네이티브 정책 원천

[English](../KUBERNETES_AUTHORITY.md)

명시적으로 활성화하면 인증된 `SumunjangPolicy` 객체 하나가 기존 수문장 IP 판정
엔진의 정책 원천이 된다. CNI를 활성화하거나 표준 NetworkPolicy를 IP만 받는
`Network.Check`로 번역하는 기능이 아니다. 기존 `--kubernetes-policy-source`
NetworkPolicy 진단 기능은 별개로 유지한다.

[배포 예제](../../deploy/sumunjang-native-policy.yaml)의 CRD를 먼저 설치하고
Established를 확인한 뒤 namespace, 정책 객체, 읽기 전용 ServiceAccount/Role을
생성한다. Role은 이름 하나의 GET만 허용한다. 객체를 수정하는 관리자 권한은
별도 정책 관리 권한이다. 생성된 객체 UID를 조회하여 관리자 소유 설정을 만든다.

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

설정에는 토큰 값 대신 환경변수 이름만 넣는다. 서비스의 자격증명 주입 방식으로
마운트된 ServiceAccount 토큰을 환경변수에 제공하고 환경변수 자격증명 교체 시
프로세스를 재시작한다. `token_env` 대신 `token_file` 참조를 설정할 수 있으며 정확히 하나만 지정해야 한다.
제한된 크기의 projected token 파일과 CA 파일을 매 수집마다 다시 읽어 회전 후
이전 자격증명 연결 pool을 유지하지 않는다. 수문장 자체 원격
판정/관리 endpoint의 기존 mTLS 설정도 유지한다.

```sh
sumunjang --kubernetes-authority /etc/sumunjang/native-source.json \
  --database /var/lib/sumunjang/policy.sqlite3
```

[Deployment 템플릿](../../deploy/sumunjang-native-authority-deployment.yaml)은 회전되는
projected token 파일, localhost HTTP 관리, 원격 mTLS binary/gRPC 및 local exec
`/readyz` probe를 사용한다. 이미지와 실제 UID를 교체하고 별도 검증한 신규 기능
빌드를 사용해야 한다. 기존 공개 0.3.5 바이너리에는 이 기능이 없다. 서로 다른
API 토큰 Secret과 TLS Secret은 미리 생성해야 하며 템플릿은 비밀값을 만들거나
공개하지 않는다. 이미지는 명시된 probe 도구를 포함해야 한다. source pin/config은
시작 시 한 번 읽으므로 설정 변경 후 재시작한다.

`--check`는 설정과 clock 기능만 검사하며 클러스터 접속/활성화를 증명하지 않는다.
이 모드는 `--policy`, `--bootstrap-policy`, `--asn-catalog`와 함께 쓸 수 없다.
suspend를 포함하는 clock(현재 Linux BOOTTIME)이 필요하다. 기본 로컬 DB 모드는
새 clock 요구사항 없이 그대로 동작한다.

CRD spec은 기존 네이티브 `policy`, 선택적 `rules`, `blocks`, `asn_catalog`를 받는다.
같은 validator, prefix tree, GeoIP, 우선순위, allowlist, 차단 의미와 DecisionView를
그대로 사용한다. `auto_block`은 false여야 한다. 이벤트 집계 및 수동 정책/규칙/
차단/Lua/GeoIP reload writer를 금지한다. 시작 시 GeoIP 파일은 독립적으로 설정된
불변 프로세스 catalog이며 Pod 신원이 아니다. 두 번째 정책 overlay나 판정마다의
Kubernetes API 호출은 없다. 잘못된 spec 하나라도 전체 관측을 거절한다.

고정 CA로 정확한 namespace/name을 HTTPS GET하며 ambient proxy/신뢰 root나
redirect를 사용하지 않는다. kind/namespace/name/UID가 일치해야 한다. 삭제 중,
resourceVersion 누락, 재생성 UID, non-200, timeout, 크기 초과, compile/persist 실패는
권한을 철회한다. resourceVersion은 불투명 문자열이며 숫자 순서로 해석하지 않는다.
자격증명/TLS/전송/파싱/컴파일/영속화 전부터 시작한 원래 BOOTTIME 1초 예산을
모두 함께 소비한다. 성공 후 500ms 대기하고 다음 GET 전에 기존 publication을
철회한다. 같은 resourceVersion도 실제 새 인증 GET은 새 현재성 관측이지만,
기존 publication 반복 조회는 수명을 갱신하지 못한다.

HTTP/binary/gRPC 판정은 정확한 native view와 source 세대를 검사하고 원래 source
잔여 예산으로 TTL을 제한한다. 만료/clock 역행/읽기 오류는 해당 publication을
영구 거절한다. 새 인증 GET이 새 세대를 만들 수 있지만 이전 capture는 부활하지
않는다. task 종료/취소 시 철회하며 재시작한 source 모드도 최초 인증 GET 전에는
DB checkpoint로 허용하지 않는다. 재시작 시 모드를 계속 설정해야 한다.
관리자가 의도적으로 `--kubernetes-authority`를 제거하면 로컬 DB 모드로 돌아간다.
기존 timed block/rule의 UTC 의미는 유지되며 BOOTTIME 원천 lease가 이를 바꾸지 않는다.

`/healthz`는 프로세스 생존 확인이다. readiness에는 `/readyz`를 사용한다. 첫 유효
source 전 또는 만료/철회 후 503을 반환한다. 관리자 인증된
`GET /v1/kubernetes/authority`는 enabled/available/phase, 불투명 resource_version,
remaining_ms를 노출하며 비밀값은 내보내지 않는다. 잔여 시간은 로컬 관측값이지
이전 가능한 서명 권한이 아니다. 수동 변경은 body/Lua 파싱 전에 거절한다.
source lease를 표현하지 못하는 기존 `/v1/snapshot`은 비활성화한다. Hangang plugin은
원천 상태를 표시하고 수동 변경을 비활성화하며 source가 없으면 기존 UI를 유지한다.

소유한 TLS fixture 검사와 실제 클러스터 검증을 구분해야 한다. 아직 배포하지
않았고 API server failover, 실제 토큰 회전/RBAC 철회, watch/relist, CNI를 검증하지
않았다. 이 기능은 native 정책 객체 하나를 제한적으로 polling하며 watch controller가 아니다.
