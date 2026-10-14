# gRPC 네트워크 판정

[English](../GRPC.md)

`--grpc-listen IP:port`로 HGD1과 함께 `hangang.sumunjang.v1.Network/Check`를 제공한다.
`--decision-listen`, `--decision-tls-cert`, `--decision-tls-key`,
`--decision-client-ca`도 설정해야 한다. 루프백에서도 클라이언트 인증서가 필수다.
단일 `authorization: Bearer <collector 자격>`을 사용하며 관리자 자격은 거부한다.

요청은 요청 ID, IPv4 4바이트 또는 IPv6 16바이트, 최소 리비전을 포함한다.
응답은 허용·거부·사용 불가 및 관찰·집행 모드를 구분한다. 최소 리비전에 못 미치면
사용 불가와 TTL 0을 반환한다. HGD1과 동일한 메모리·GeoIP 판정이며 SQL을 질의하지 않는다.
K8s 수집은 여전히 진단용이고 NetworkPolicy 집행 완료를 의미하지 않는다.

공용 런타임이 연결 2,048개, 연결당 스트림·동시 요청 64개, 헤더 8KiB,
TLS 파일 1MiB, 요청 시간 1초를 제한한다. 메시지 입력·출력 제한은 2/1KiB이며
압축은 활성화하지 않는다. gRPC 판정 처리량 제한은 HTTP와 별도다.

Linux 감독 실행에서 HUP 시 리스너를 인계한다. 클라이언트 재연결은 필요할 수 있다.
빌드에는 protoc가 필요하고 grpcio·grpcio-tools가 있는 별도 Python 환경에서
`python tools/grpc_smoke.py --binary target/debug/sumunjang`으로 실제 전송을 검증한다.
인증서·자격 거부, 입력 제한, 네이티브 일치, 정책 변경 및 HUP 인계를 확인했다.
실제 K8s gRPC 배포·한강 gRPC 클라이언트·릴리즈는 미완료다.
