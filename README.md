# hangang-guard

Hangang의 요청별 보안 판단을 담당하는 Rust 서비스입니다. **기본 연동은 매
요청마다 guard 질의**이며, 선택적으로 **1~5초 캐시**를 사용할 수 있습니다.
Guard 허용은 기존 Hangang 인증을 우회하지 않습니다.

명시적으로 지정한 허니팟·스캐너 경로의 신호를 집계하고, 임계값을 넘는 IP를
차단 후보로 관리합니다. 기본은 `observe` 모드입니다. 검토한 IP/CIDR 차단,
허용 목록, 만료, 자동 IP 차단을 API와 내장 대시보드에서 관리합니다.
판단은 메모리에서 처리하고 SQLite에는 정책과 제한된 집계만 저장합니다.

## 실행

Rust 1.96 이상이 필요합니다.

```sh
cargo build --release
export HANGANG_GUARD_COLLECTOR_TOKEN="$(python3 -c 'import secrets; print(secrets.token_hex(32))')"
export HANGANG_GUARD_ADMIN_TOKEN="$(python3 -c 'import secrets; print(secrets.token_hex(32))')"
./target/release/hangang-guard --listen 127.0.0.1:9080 --database ./guard.sqlite3
```

두 토큰은 서로 달라야 하며 각각 최소 16바이트입니다. 실제 배포에서는 같은
collector 토큰을 guard와 Hangang에 지속적으로 공급하고, 환경 파일은 권한
`0600`으로 보호하세요. 저장소에 인증 정보를 넣지 마세요.

대시보드는 `http://127.0.0.1:9080/`입니다. 관리자 토큰은 브라우저 메모리에서만
사용합니다. 원격 접근에는 HTTPS 역방향 프록시나 SSH 터널을 사용하세요.

## Hangang 네이티브 연동

Hangang의 `feat/hangang-guard` 브랜치가 필요합니다.

```sh
# guard와 동일한 HANGANG_GUARD_COLLECTOR_TOKEN 환경에서 실행
hangang --config hangang.json --listen 127.0.0.1:8080 \
  --guard-url http://127.0.0.1:9080 \
  --guard-honeypot-path /trap \
  --guard-scanner-path /.git/config
```

기본은 `--guard-mode query`, 캐시 없음, 질의 타임아웃 100ms입니다. Guard
불통 시 기본은 `--guard-failure-mode deny`로 503을 반환합니다. 명시적으로
`allow`를 선택하면 guard 장애 시 기존 Hangang 정책으로 계속 처리합니다.
선택적 캐시는 `--guard-cache-ms 1000`부터 `5000`까지이며 탐지 신호가 있는
요청은 항상 guard에 전달합니다. 캐시를 켜면 정책 변경 반영에 최대 해당 TTL이
걸릴 수 있습니다. `--guard-mode snapshot`은 별도 선택 가능한 로컬 정책
스냅샷 방식입니다. 상세 연동은 Hangang의 `docs/GUARD.md`를 참고하세요.

## API

Collector 토큰: `POST /v1/decision`, `POST /v1/events`, `GET /v1/snapshot`.
Admin 토큰: `GET /v1/status`, `GET /v1/candidates`, `GET/PUT /v1/policy`,
`GET/POST/DELETE /v1/blocks`, `POST /v1/candidates/approve`.
모든 API 인증은 `Authorization: Bearer …`입니다. `/healthz`는 인증 없는
최소 상태 확인 경로입니다. [프로토콜·설계](docs/DESIGN.md)를 참고하세요.

IP는 Hangang이 신뢰 프록시 경계에서 판별합니다. 임의의 X-Forwarded-For를
그대로 믿지 않습니다. Guard 차단 요청은 증거를 갱신하지 않습니다. 허용
목록은 guard 차단만 면제하고 다른 인증·보안 정책을 면제하지 않습니다.

## 검증

```sh
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo build --workspace
# Hangang 연동 worktree에서도 cargo build --bin hangang 실행 후
python3 tools/e2e.py --hangang-bin ../hangang-guard-integration/target/debug/hangang
```

E2E는 임시 DB·별도 포트·임시 토큰으로 실제 프로세스를 실행하고 종료합니다.
운영 서버 설정을 변경하지 않습니다.

## 범위와 다음 단계

지원: 요청별 질의, 짧은 선택적 캐시, IPv4/IPv6 CIDR, 가중치 기반 제한된
시간창 집계, 수동 후보 승인·차단 해제, 정책 변경, SQLite 복구, 오프라인
ASN prefix catalog, 대시보드, Hangang 네이티브 연동.

ASN 정보는 분류를 위한 보조 자료입니다. ASN 전체 차단은 자동화하지 않습니다.
온라인 ASN 풀 갱신, 서명된 공격 패턴 피드, ASN 차단 제안의 영향 분석,
GeoIP 역할 변경, LLM 검토 보조는 다음 단계입니다. 운영 적용 순서와 한계는
[운영 문서](docs/OPERATIONS.md), 작업 절차는 [설계](docs/DESIGN.md)에 있습니다.
