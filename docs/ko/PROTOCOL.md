# 영구 연결 바이너리 판단 프로토콜 v1

[English](../PROTOCOL.md) · [문서 목록](README.md)

HTTP API는 관리와 증거 제출에 사용합니다. 선택적 바이너리 리스너는 JSON 없이
동일한 정책·룰·GeoIP 문맥으로 일반 IP 판단을 처리합니다. 평문 **loopback 전용**이며
연결당 한 번 인증합니다. 원격 전송에는 HTTPS를 사용합니다.

```sh
hangang-guard --decision-listen 127.0.0.1:9081
hangang --guard-url http://127.0.0.1:9080 --guard-decision-tcp 127.0.0.1:9081
```

양쪽에 동일한 `HANGANG_GUARD_COLLECTOR_TOKEN`을 공급합니다. Hangang은 최대
64개 연결을 재사용하고 서버의 30초 idle 제한보다 이른 25초에 idle 연결을 종료합니다.
허니팟/스캐너 신호가 있는 요청은 인증된 HTTP 판단 API를 사용합니다. 기본 캐시 없음,
선택적 1~5초 캐시, timeout과 실패 정책은 동일합니다. 잘못된 연결은 폐기하며
HTTP 전송으로 자동 전환하지 않습니다.

## 인증

클라이언트는 `HGD1`(ASCII 4바이트), 토큰 길이(u16 big-endian), 정확히 그 길이의
토큰(16~4096바이트)을 전송합니다. 서버는 collector 인증 후 `HGA1`을 반환합니다.
인증 실패 시 연결을 닫고 admin 토큰은 거부합니다. 인증 5초, idle 읽기 30초,
쓰기 5초 제한을 적용하며 동시 연결은 최대 256개입니다. 종료 시 기존 소켓도 취소합니다.

## 요청 프레임 — 24바이트

| 오프셋 | 길이 | 의미 |
| --- | ---: | --- |
| 0 | 1 | 버전 1 |
| 1 | 1 | IP family 4 또는 6 |
| 2 | 2 | 예약, 반드시 0 |
| 4 | 4 | correlation id, u32 big-endian |
| 8 | 16 | IPv6 주소; IPv4는 앞 4바이트 주소와 뒤 12바이트 0 |

## 응답 프레임 — 24바이트

| 오프셋 | 길이 | 의미 |
| --- | ---: | --- |
| 0 | 1 | 버전 1 |
| 1 | 1 | action: 0 allow, 1 deny |
| 2 | 1 | mode: 0 observe, 1 enforce |
| 3 | 1 | 예약 0 |
| 4 | 4 | 요청 correlation id, u32 big-endian |
| 8 | 8 | 정책 revision, u64 big-endian |
| 16 | 4 | 판단 TTL 밀리초, u32 big-endian, 0~5000 |
| 20 | 4 | 예약 0 |

고정 길이 스트림 프레임이며 요청 pipelining을 지원하고 응답 순서를 유지합니다.
서비스는 읽기당 최대 256프레임을 배치하고 응답 쓰기를 묶습니다. 부분 프레임은
다음 읽기로 이어집니다. 잘못된 버전/family/padding은 연결을 닫습니다. 네이티브
클라이언트는 모든 필드와 correlation을 검증하며 단일 요청 timeout에 pool 대기,
연결, 인증, 읽기/쓰기가 포함됩니다. TTL은 질의 시작부터 측정하여 전송 지연이
유효 시간을 늘리지 못합니다. 이유·GeoIP 이름·점수·인증 정보는 판단 프레임에
포함하지 않으며 관리자 API에서 조회합니다.
