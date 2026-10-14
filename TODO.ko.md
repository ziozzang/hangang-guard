# TODO

[English](TODO.md)

현재 hangang (~/hangang)용  보안 플러그인 만드는게 목표.
요청 로그를 분석해서 ㄷ음 조건에 따라 해당 IP등을 실시간 차단하거나 하는 것을 수행한다.
hangang은 네이티브 zero-trust매커니즘을 이미 내장하고 있기 때문에. 충분히 가능할 것으로 보인다.

# 예시 메커니즘
1. 허니팟에서 기록하기.
2. IP주소에서 ASN역 PULL하기.
3. 임계값을 초과한건 블록후보(BCL)에 넣기.
4. 블록할 ASN의 IP주소 풀을 가져오기
5.  화이트리스트 결정하기(반자동으로 LLM으로?)
6. 블록할 IP주소를 범위 결정하기.

아마 내부적으로 hangang -> 실시간 zero-trust server 는 lua든 아니면 쿼리든 뭐든 가능할거고.
- 이걸 대시보드로 관리 가능해야하고
- 위의 정책을 동적으로 처리 가능하도록
- 블럭 풀 등을 처리 가능한 초고속의 서버
같은게 필요할거 같긴해.

필요하다면 geoip 같은것도 이쪽에 이관 가능할거 같기도 하거든?

먼저 충분히 디자인하고 (필요하다면 astra는 비싸지만 아주 가끔. 꼭 필요할때만 호출) 하도록하고. 서브 에이전트를 통해서 구현하도록하자. 적당히 비용 생각해가면서.
- 현재 구동중인 서버에 붙여서 테스트 해볼수 있을거야.

비슷한 제품이 이미 있을거 같기도 한데.
- 공격 패턴을 자동 수집을 한다던가. 특정 패턴을 잡아내면 이걸 허니팟IP등으로 (스캐닝하던놈) 들로 관리 가능할거 같긴 하거든.
- 이런 패턴도 수집/업데이트가 된다면 그걸 써먹을수도 있을거 같긴 해.

# 코드는
- rust로 하고. 리소스는 꽤 적게 차지 하도록. 데이터베이스는 항상 조회가 할건 아니고 커밋/캐시할때만. 로그를 모두 담으면 문제 됨.

# 기타

서버 이름은 뭐가 좋을까.
hangang-flogging 같은거라고 할까?


# 확정된 방향 (2026-10-12)
- 프로젝트 이름: hangang-guard. 현재 workspace 디렉터리 hangang-safe는 유지.
- Rust로 구현하고 hangang에 네이티브 first-class 연동을 제공한다.
- 기본은 hangang이 매 요청 guard에 질의하는 방식이다. 캐시는 선택 사항이며
  활성화할 때 TTL은 1~5초로 극도로 짧게 제한한다.
- 설계/검토 → 단위별 서브 에이전트 구현 → 실제 프로세스 통합 검증 →
  커밋/푸시 순서로 진행한다. 기존 hangang 미커밋 작업은 별도 worktree로 보호한다.
- 초기 구현: 관찰/차단 정책, BCL 후보 및 수동 승인, CIDR 허용/차단/만료,
  대시보드, bounded 집계, SQLite checkpoint, 요청별 질의와 선택적 캐시.
- 다음 단계: 온라인 ASN prefix pull/refresh, ASN 차단 후보 영향 분석,
  서명/출처/버전/롤백을 갖춘 공격 패턴 수집·업데이트, GeoIP 역할 검토.

# TODO: 프롬프트 기반 요청 패턴 검사와 LLM 질의
사용자 요청: 프롬프트에 따라 요청 패턴을 검사하고 LLM을 통해 질의/판단할 수
있는 기능을 검토한다. 구현 방식은 충분히 설계한 뒤 결정한다.

- [ ] 운영자가 검사 목적·판단 기준·출력 스키마를 정의하는 프롬프트 정책 모델 설계.
- [ ] 요청별 동기 질의와 집계 패턴의 비동기 분석을 비교: 지연, 비용, 처리량,
      장애 시 동작, 선택적 1~5초 decision cache와 정책 갱신 관계를 측정.
- [ ] HTTP method/path 구조, 상태·빈도·시간 분포, honeypot/scanner 증거 등
      필요한 최소 입력 선정. 헤더/body 사용 여부는 별도 명시적 정책으로 결정하고
      토큰·쿠키·개인정보는 전달 전에 제거/마스킹. 입력 길이·집계량 상한 설정.
- [ ] 공격자가 보낸 요청 문자열의 prompt injection을 비신뢰 데이터로 처리하고
      시스템 프롬프트/운영 정책/도구 권한과 분리. 구조화 출력 검증과 근거 추적.
- [ ] 모델/제공자/프롬프트 버전, 비용 예산, timeout, concurrency, circuit breaker,
      재시도/중복 제거와 결과 만료 설계. 프롬프트 변경 때 관련 cache를 무효화.
- [ ] LLM 결과를 후보/보조 설명으로 사용하는 방식부터 평가하고, 자동 차단을
      허용하는 경우 deterministic 정책 gate·오탐 검증·shadow 평가·롤백을 설계.
      LLM의 whitelist 수정/ASN 광역 차단 권한은 별도 검토 없이는 부여하지 않는다.
- [ ] 대시보드에 프롬프트 정책·질의 결과·근거·비용·지연·승인 상태를 표시하고
      재현 가능한 정상/공격 패턴 평가셋과 품질 기준을 마련한다.

# 성능·정책·관리 확장 (2026-10-12)
- [x] 압축 radix tree 기반 IPv4/IPv6 IP pool 조회, immutable lock-free 판단.
- [x] 초당10,000–100,000 질의 목표를 실제 통신 부하 테스트로 검증.
- [x] 연결 재사용/1회 인증/고정24바이트 바이너리 프로토콜과 native 연동.
- [x] 관리자 목록 검색·정렬·페이지네이션, 구조화 정책/화이트리스트 편집.
- [x] 오프라인 GeoIP Country/City/ASN 처리·관리자 조회·last-good reload.
- [x] IP/CIDR 점수·의심 단계·규칙 근거 조회.
- [x] 유사 도구 조사와 기능 반영, Lua 임베딩/JSON 동적 RuleSet 검증·배포.
- [ ] 전체 proxy/실제 운영 traffic에서 지속 부하·실패·분산 배포 qualification.
- [ ] 프롬프트 기반 LLM 요청 패턴 분석은 앞의 TODO에 따라 별도 설계.
- [x] 사용자 확인: 임베딩은 Lua 런타임 내장을 의미하며 Lua 5.4로 구현.

# 문서 언어와 역할 경계
- 영어 문서가 기본이며 한국어 번역을 함께 유지한다.
- Guard는 제로트러스트 백본의 IP/네트워크 정책 및 위험 판단 구성 요소이다.
- Hopae는 사용자/주체를 관리한다. Guard는 계정/세션 관리 기능을 중복 구현하지 않는다.
- 향후 기능 범위를 확장할 때도 이 책임 경계를 유지한다.

## Hangang 네이티브 콘솔
- [x] 해시 고정 Guard 메뉴 패키지·host 인증·native 테마.
- [x] 재현 가능한 생성과 host credential/역할/감사 제한.
- [ ] 검증된 패키지 활성화와 런타임 자동 업데이트 조율; host pin은 명시적으로 유지.

## Kubernetes ipBlock 코어

코어에 `network_policy::IpBlock`을 구현했습니다. 예외 개수 제한, IPv4/IPv6 및
mapped 주소 정규화, strict subnet 검증과 peer별 CIDR 차집합을 지원합니다.
예외는 해당 peer에만 적용되며 다른 peer/정책이 같은 주소를 허용할 수 있습니다.
서버 NetworkPolicy 집행은 아직 활성화되지 않았습니다. 목적지·포트·방향·선택자
문맥, API 원천 권위, 스냅샷 신선도 및 CNI 검증이 추가로 필요합니다.

## 선택된 방향별 네트워크 코어

`SelectedDirection`은 선택자가 해석된 대상·방향에 TCP/UDP/SCTP 목적지 포트와
범위를 적용합니다. 선택된 정책 없음과 격리된 기본 거부를 구분하며, 규칙 간에는
허용을 합치고 각 규칙 안에서는 peer와 포트 조건을 함께 요구합니다. 빈 peer/포트는
제한 없음입니다. 격리된 대상의 목적지 포트 0은 거부합니다. 규칙·peer·포트 전체
개수를 제한합니다. 원천 어댑터가 선택자와 named port를 해석하고 ingress/egress를
독립적으로 조정해야 합니다. 규칙 후보는 아직 제한된 순차 조회이므로 대규모 정책의
성능을 주장하려면 인덱스와 측정이 필요합니다. 서버·프로토콜·CNI 활성화는 아닙니다.

의미 참조: [Kubernetes Network Policies](https://kubernetes.io/docs/concepts/services-networking/network-policies/).

## 라벨 선택자 조건 코어

개수와 값 크기가 제한된 `LabelSelector`/`Requirement`에 In·NotIn·Exists·
DoesNotExist 및 조건의 AND 평가를 추가했습니다. NotIn은 키가 없는 객체도
포함하며 빈 값과 키 없음은 구별합니다. 빈 선택자는 모든 객체를 선택합니다.
matchLabels는 단일 값 In 조건으로 변환할 수 있습니다. 생성자는 연산자별 값
개수와 용량을 검증하며 K8s 라벨 문법 검증은 API 어댑터 책임입니다. 요청 헤더가
아닌 원천 라벨에만 적용해야 합니다. Namespace 범위, Namespace/Pod 선택자의
결합 해석, 원천 스냅샷 일관성과 서버 연결은 남아 있습니다.
참조: [Kubernetes labels](https://kubernetes.io/docs/concepts/overview/working-with-objects/labels/).

## Namespace·Pod peer 선택자 결합

`PodPeerSelector`는 namespaceSelector와 podSelector를 AND로 결합합니다.
namespaceSelector가 없으면 podSelector는 정책의 Namespace 안에서만 적용됩니다.
빈 namespaceSelector는 모든 Namespace를 선택하지만 빈 podSelector만 있으면
같은 Namespace로 제한됩니다. 둘 다 없는 경우 생성자가 거부하므로 어댑터가
전체 peer를 명시적으로 표현해야 합니다. 실제 원천의 살아 있는 Pod·Namespace
사실에만 적용하며 클러스터·UID·신선도 보호는 어댑터 책임입니다. API 파싱,
선택자에서 주소로의 구체화 및 서버 집행은 남아 있습니다. 코어 테스트는 결합
선택자와 빈 값·없음의 범위 차이를 검증합니다.
참조: [NetworkPolicy selectors](https://kubernetes.io/docs/concepts/services-networking/network-policies/#behavior-of-to-and-from-selectors).

## 서버 선택자 원천 어댑터

서버에 K8s LabelSelector JSON의 matchLabels·matchExpressions를 코어로 변환하는
어댑터를 추가했습니다. 알 수 없는 필드·연산자, null map, 연산자별 잘못된 값
개수와 과도한 입력을 거부합니다. `sumunjang --check-kubernetes-selector FILE`은
DB·리스너 없이 실행됩니다. 검증 범위는 구조·조건 용량이며 K8s 라벨 문법 전체는
아닙니다. API 수집·NetworkPolicy 파싱·UID/신선도 보호·요청 문맥 연결은 남았고
이 명령이 운영 정책을 활성화하지는 않습니다.

## K8s 선택자 라벨 문법

서버 어댑터에서 라벨 이름·값의 ASCII 영숫자 경계, 내부 dash/underscore/dot,
63바이트 제한과 빈 값 허용을 검증합니다. 선택적 소문자 DNS 접두사는 전체
253바이트로 제한합니다. matchLabels와 matchExpressions 모두 잘못된 문법을
거부하며 오프라인 선택자 검사에도 포함됩니다. 정책 수집·주소 구체화·실행 중
NetworkPolicy 연결은 남아 있습니다. 이전 문법 검증 유보 기록은 과거 상태이며
이번 서버 어댑터 검증으로 대체합니다.

## 실제 K8s 선택자 문법 호환성

소유한 K8s v1.37 서버 dry-run 비교에서 어댑터가 DNS 접두사 개별 구간 길이를
과도하게 제한하는 차이를 발견했습니다. 해당 제한을 제거하고 API의 전체 접두사
253바이트 제한은 유지했습니다. `tools/kubernetes_selector_qualification.py`가
12개 허용·거부 경계 입력을 실제 API와 수문장 오프라인 명령에 비교하며 모두
일치합니다. 리소스는 dry-run만 수행하고 저장하지 않습니다. 서버 선택자 테스트와
Clippy가 통과했습니다. 선택자 문법 검증이며 수집·조정·NetworkPolicy 집행은 아닙니다.

## 오프라인 NetworkPolicy 평가 어댑터

서버에 networking.k8s.io/v1 NetworkPolicy 대상 선택자·Namespace 범위·policyTypes
기본값·ingress/egress 규칙·ipBlock 예외·숫자 포트/범위·TCP/UDP/SCTP를 코어로
변환하는 경로를 추가했습니다. 입력 fixture 필드는 policy·namespace·labels·
direction·peer·protocol·port이며 `--evaluate-kubernetes-policy FILE`은 DB/리스너
없이 not_selected·not_isolated·allowed·denied를 출력합니다. 입력은 1MiB로
제한합니다. 알 수 없는 spec/규칙 필드, 선택자 peer, 명시적 빈 peer, named port와
규칙/types 모순은 명시적으로 거부합니다. 지원 부분집합이며 전체 K8s 호환이나
실행 중 집행은 아닙니다. 실제 API 수집·peer 구체화·UID/원천 신선도·한강 문맥
연결은 남아 있습니다.

## 실제 API 기본값 적용 NetworkPolicy 검증

소유한 클러스터의 server dry-run JSON 응답을 실제 수문장 오프라인 평가 명령에
전달하도록 검증 도구를 확장했습니다. ingress/egress 기본값, 명시적 egress 격리,
빈 규칙 허용, 기본 TCP, 프로토콜 불일치, CIDR 예외와 숫자 endPort의 8개 평가가
기존 선택자 문법 비교 12개와 함께 통과했습니다. 리소스를 저장하지 않고 CNI
패킷 집행을 주장하지 않습니다. 실제 API 정책 구조와 구현된 평가기를 연결한
검증이며 수집/watch·원천 신선도·실행 중 연결은 남았습니다.

## 잘못된 peer의 실제 API 호환성

소유한 K8s 서버 dry-run은 `from: [{}]`와 ipBlock·podSelector를 결합한 peer를
거부합니다. 기존 로컬 평가기의 거부와 일치하며 검증 도구에 두 사례를 추가했습니다.
기존 20개 문법/평가 사례도 통과합니다. 빈 ingress 규칙 `{}`는 전체 peer를
허용하지만 빈 peer 객체는 유효하지 않습니다. 빈 peer wildcard 기능은 커밋하거나
배포하지 않았습니다.

## 컴파일된 NetworkPolicy 후보 분리

서버 정책 컴파일이 대상 선택자와 독립적인 ingress/egress 뷰를 소유합니다.
타입이 정해진 조회는 후보를 재사용하며 JSON 파싱·파일·DB·API 접근을 하지
않습니다. 오프라인 평가는 한 번 컴파일한 뒤 같은 조회 메서드를 사용합니다.
원본 변경 후 새 거부 후보를 생성해도 이전/새 후보의 반복 조회가 독립적인지,
잘못된 교체 후보가 기존 뷰를 바꾸지 않는지 검증했습니다. 어댑터 테스트 6개,
Clippy와 실제 API 비교 22개가 통과했습니다. 실행 중 게시·신선도 상태 머신은
아직 없으며 이 단위 테스트의 이전 후보 보존이 오래된 원천 정책 허용을 의미하지
않습니다. 운영은 변경하지 않았습니다.

## 컴파일된 NetworkPolicy 집합

오프라인 어댑터가 개수를 제한한 NetworkPolicyList의 모든 항목을 검증한 뒤 후보를
생성합니다. 비어 있지 않은 continue 토큰과 잘못된 항목을 거부하므로 불완전한 API
페이지를 전체 정책 집합으로 사용하지 않습니다. 선택된 정책들의 허용을 합치며,
미선택 정책이나 반대 방향만 격리하는 정책이 다른 정책의 거부를 해제하지 못합니다.
빈 집합/미선택은 not_selected를 반환합니다. 호출자는 일반 K8s 미격리 의미를
적용해야 하며 이를 제로트러스트 권한 허가로 사용하면 안 됩니다. 어댑터 테스트
7개·Clippy·실제 API 회귀 22개가 통과했습니다. 정책 후보는 제한된 순차 조회이며
대규모 인덱스·실제 페이지 수집·실행 중 신선도는 남아 있습니다. 운영 권위는
활성화하지 않았습니다.

## 인증된 K8s 원천 관찰 경로

`--observe-kubernetes-policy FILE`은 비공개 원천 설정 api·namespace·ca·token_env를
읽습니다. HTTPS Origin과 지정 CA를 사용하며 프록시·리다이렉트를 끄고 Bearer
헤더를 민감값으로 표시합니다. 전체 수집/컴파일을 32페이지·4096항목·1MiB·1초로
제한합니다. 페이지의 resourceVersion 일치, Namespace·UID 사실과 continuation
순환을 검사하고 검증된 collection에서 누락된 항목 TypeMeta만 채웁니다. 전체
컴파일 성공 후 개수/revision만 보고하며 리스너·DB·정책 권위는 변경하지 않습니다.

`tools/kubernetes_source_smoke.py`가 임시 Namespace와 list 전용 ServiceAccount로
실제 실행 파일을 검증합니다. 수집/컴파일·잘못된 토큰 거부·다른 Namespace RBAC
거부가 통과했고 자체 fixture Namespace만 삭제했습니다. 서버 Clippy도 통과했습니다.
악성 페이지/TLS/timeout·원천 게시·watch 복구·회전/풀링·요청 집행은 남아 있습니다.
운영 활성화가 아닌 관찰 경로입니다.

## 자체 TLS 원천의 악성 응답 검증

`tools/kubernetes_source_adversarial.py`가 생성 CA·비공개 합성 Bearer를 사용하는
자체 TLS 서버에 실제 관찰 실행 파일을 연결합니다. 정상 빈 목록과 잘못된 kind,
revision 누락/변경, continuation 순환, UID 중복/누락, Namespace 불일치,
항목 kind 모순, 미해석 정책, 지연, 리다이렉트와 1MiB 초과 본문의 13개 사례가
통과했습니다. 시간 제한과 리다이렉트 미추종을 확인했고 stdout/stderr에 자격값이
없습니다. 초기 fixture의 Content-Length 누락으로 정상 본문이 거부되어 HTTP
프레이밍을 수정한 후 검증했습니다. 잘못된 CA/회전과 실행 중 게시/복구는 별도
검증 대상입니다. 운영 정책·바이너리는 변경하지 않았습니다.

## 원천 목록의 정상 페이지 수집 검증

자체 TLS 테스트에 같은 resourceVersion·서로 다른 UID를 가진 정상 두 페이지를
추가했습니다. continuation 토큰의 `+`·`/`·`%`·`=`를 URL 인코딩하고 서버에서
원래 값과 비교합니다. 실제 관찰 명령은 두 요청 후 정확히 두 정책의 컴파일을
보고합니다. 기존 불확실한 응답 거부를 포함해 14개 사례가 통과했습니다. 완전한
페이지 조립 검증이며 원천 게시·watch 연속성 검증은 아닙니다.

## 원천 CA 신뢰 경계 검증

자체 TLS fixture가 관계없는 CA를 생성하고 실제 관찰 명령의 서버 거부를 검증합니다.
TLS 서버는 HTTP 요청을 받지 않아 Bearer가 신뢰하지 않은 연결에 전달되지 않습니다.
원래 CA로 복구한 뒤 정상 페이지 수집도 통과하며 원천 검증 15개가 모두 통과했습니다.
새 프로세스의 CA 설정 검증이며 실행 중 키/CA 회전·지속 연결 풀 교체는 아직
검증하지 않았습니다.

## 원천 객체 신원 완결성

Namespace 원천 수집에서 이름·UID·개별 resourceVersion이 비어 있지 않고 크기
제한 안에 있어야 합니다. UID가 달라도 같은 이름이 반복되면 거부하여 같은 이름의
교체 객체가 한 후보에 섞이지 않도록 했습니다. 객체별 revision이 collection
revision과 같을 필요는 없습니다. 이름/revision 누락·이름 중복을 포함한 자체 TLS
18개 사례, 실제 K8s 원천/인증/RBAC smoke와 Clippy가 통과했습니다. 여러 리소스의
원자성이나 지속적인 원천 소유권을 입증한 것은 아닙니다.
