# 서명된 업데이트

[English](../UPDATES.md) · [문서 목록](README.md)

Hangang Guard는 제로트러스트 백본의 판단 authority입니다. 업데이트 채널도 신뢰
경계이며 다운로드 출처가 침해되어도 정책 엔진을 교체할 수 없어야 합니다.
Hangang의 서명 release 방식을 참고하되 Guard 저장소와 독립된 공개키를 고정합니다.

## 신뢰 모델

운영자가 다운로드 출처와 독립적으로 base64 Ed25519 공개키를 공급합니다.
TOFU나 unsigned fallback은 없습니다. Decode한 payload의 정확한 바이트 서명을
검증한 뒤 manifest를 해석합니다. Target은 현재 바이너리와 일치하고 semantic version은
더 최신이어야 합니다. 동일 버전은 정상 no-op이며 downgrade, 잘못된/weak key,
변조 서명, 크기/SHA-256 불일치는 거부합니다.

HTTPS 필수, manifest 64KiB, binary 128MiB 이하이며 임시 파일로 streaming합니다.
일반 HTTPS redirect는 scheme/host/port를 유지해야 합니다. GitHub 모드는 고정된
`ziozzang/hangang-guard` asset 경로, 해당 API asset ID, GitHub
`release-assets.githubusercontent.com` CDN만 허용합니다. Release metadata는 탐색 정보이며
서명 authority가 아닙니다. URL/크기/target/release version은 서명 payload와 일치해야 합니다.

비공개 GitHub 저장소는 서비스 환경에 `HANGANG_GUARD_GITHUB_TOKEN`을 설정합니다.
토큰은 고정 API와 선택한 API asset에만 전달하고 CDN cross-origin redirect에서는
제거합니다. 일반 manifest 다운로드에는 전달하지 않습니다. CLI/URL/status/log에 넣지 마세요.

## Release manifest

서명 payload는 다음 필드만 포함합니다.

```json
{
  "version": "0.3.0",
  "target": "x86_64-unknown-linux-gnu",
  "artifact_url": "https://github.com/ziozzang/hangang-guard/releases/download/v0.3.0/hangang-guard-x86_64-unknown-linux-gnu",
  "sha256": "<64 lowercase hexadecimal characters>",
  "size": 12345678
}
```

Envelope는 base64 `payload`와 `signature`입니다. JSON 공백/필드 순서도 서명 대상이므로
최종 바이트를 서명한 뒤 JSON을 다시 생성하지 마세요. Envelope/payload 모두 알 수
없는 필드를 거부합니다. Target마다 `hangang-guard-<target>` binary와
`hangang-guard-<target>.manifest.json` envelope를 게시합니다.

별도 오프라인 서명 도구:

```sh
cargo run -p guard-update --bin guard-release-sign -- \
  payload.json /secure/guard-release-seed manifest.json
cargo run -p guard-update --bin guard-release-sign -- \
  --public-key /secure/guard-release-seed
```

Seed는 base64 32바이트 Ed25519 seed를 담은 일반 파일이며 Unix group/other 접근을
막아야 합니다(예: `0600`). 저장소와 배포 환경 밖에 보관합니다. 실행 중 updater는
공개키만 사용하며 Guard 서명키는 Hangang 키와 독립적입니다.

## 활성화 경계

현재 executable 디렉터리에 후보를 staging합니다. 활성화 직전에 digest/size를
재검증하고 이전 executable의 hard link를 유지한 뒤 atomic rename/directory sync를
수행합니다. 취소하면 임시 파일을 삭제합니다. 일반 파일과 동일 디렉터리 staging만 허용합니다.

Supervisor는 검증된 후보의 `--version` 및 `--check`를 제한된 실행으로 검사합니다.
Version은 manifest와 일치하고 config 검증은 성공해야 합니다. Stdout 64KiB/30초
상한이며 취소 시 후보를 종료합니다. `--check`는 listener bind, 정책 변경, 운영 DB
생성이나 별도 writer 시작을 하지 않습니다.

Binary 교체만으로 readiness를 보장하지 않습니다. Process owner는 serving worker를
교체하고 명시적 readiness를 기다리며 실패하면 이전 binary/worker를 복구해야 합니다.
성공 후에만 rollback link를 삭제합니다. Handoff 중 두 worker가 writable 정책 DB를
동시에 열지 않아야 합니다. 업데이트는 DB schema를 migration/rollback하지 않으며
후보는 기존 저장 형식과 호환되어야 합니다.

Authority 교체 구간은 Hangang의 명시적 guard 실패 정책으로 처리합니다. 보호된
zero-trust 경로는 fail-closed를 선택하세요. 운영자가 선택한 fail-open은 장애 중
트래픽을 허용하여 같은 보장을 제공하지 않습니다. Listener ownership/readiness는
서명 검증과 구분되는 process lifecycle 책임입니다.

## Supervisor 자동 업데이트 (Linux)

서비스 환경에 신뢰 공개키 `HANGANG_GUARD_UPDATE_KEY`와 collector/admin 토큰을
공급한 뒤 설치된 서비스를 실행합니다.

```sh
hangang-guard --supervised --database /var/lib/hangang-guard/policy.sqlite3 \
  --listen 127.0.0.1:9080 --decision-listen 127.0.0.1:9081 \
  --update-github --update-key-env HANGANG_GUARD_UPDATE_KEY \
  --update-interval-seconds 300
```

운영자 호스팅 envelope는 `--update-github` 대신
`--update-manifest https://updates.example/guard.manifest.json`을 사용합니다.
`--update-status-file`로 supervisor 상태 파일을 선택할 수 있습니다.
공개 Guard 저장소에는 GitHub 토큰이 필요 없으며 비공개 접근 시에만 공급합니다.

Linux supervisor는 worker 교체 중 listener 소켓을 유지합니다. 이전 worker를
checkpoint/stop한 뒤 후보를 시작하므로 정책 DB writer는 하나입니다. Private Unix
socket으로 readiness를 전달합니다. 실패하면 이전 binary와 worker를 복구합니다.
기존 연결은 reset될 수 있고 새 연결은 유지된 listener에서 queue될 수 있습니다.
짧은 authority 중단이므로 보호된 Hangang 경로는 fail-closed를 사용해야 합니다.

`--check`는 listener/DB 생성 없이 설정을 검증합니다. `--check-update`는 최신 release
metadata만 확인하며 binary를 활성화하지 않습니다. Update 표시 이후에도 사용 전
전체 서명 검증이 필요합니다. `--version`/`--about`은 identity/capability를 표시합니다.
자동 supervisor는 Linux 전용이며 macOS는 서비스와 오프라인 서명 도구를 지원하되
자동 supervisor 활성화는 지원하지 않습니다.

## 네이티브 release 검증

`Native binary qualification` workflow는 Linux amd64/arm64, macOS amd64/arm64에서
네이티브 build/test를 수행합니다. CI artifact는 unsigned 검증 자산이며 서명된
업데이트로 사용할 수 없습니다. Workflow는 release를 게시하지 않습니다.
검증한 target의 자산을 오프라인으로 준비합니다.

```sh
python3 tools/prepare_release.py --target x86_64-unknown-linux-gnu \
  --signing-seed-file /secure/guard-release-seed --output dist
```

도구는 workspace/executable version을 검사하고 `hangang-guard`, `guard-release-sign`,
`LICENSE`만 package하며 manifest/checksum을 생성합니다. 기존 `release-public-key.txt`는
seed와 비교합니다. 출력 디렉터리는 비어 있고 seed와 별개여야 합니다.
`--unsigned`는 CI 검증용으로 signed manifest/public-key asset을 생략합니다.
검증 성공 후 일치하는 안정 `v<version>` tag에 서명 binary/envelope를 게시합니다.

## 검증

Updater 테스트는 TLS release fixture, 정상/변조 서명과 payload, downgrade/잘못된
target/unsigned metadata 불일치, 과대 manifest, digest/size 실패, atomic activation,
rollback, bounded preflight, 비공개 asset redirect에서 CDN 토큰 제거를 포함합니다.

```sh
cargo test -p guard-update
```

## 상태와 프로세스 검증

관리자 `GET /v1/update/status`, `POST /v1/update/check`와 콘솔에서 상태와 검사
요청을 관리합니다. 검사 요청은 새로운 서명 릴리즈를 자동 적용할 수 있지만
URL/신뢰 키는 선택하지 않습니다. 비활성 서비스는 검사 요청을 거부합니다.
Generic HTTPS manifest의 사설 PKI는 `--update-ca /path/ca.pem`으로 추가하고,
GitHub는 system roots만 사용해 이 옵션을 거부합니다. 종료 grace는1–15초입니다.

```sh
cargo build --locked -p guard-server -p guard-update --bins
python3 tools/update_smoke.py
```

Linux fixture는 실행파일 복사본·임시 키/DB/포트만 사용합니다. HUP 재시작,
서명 preflight, 활성화, 정책 유지, readiness 실패 rollback, 변조 거부 및
취소를 검사합니다. 미래 버전 launcher는 소유한 runtime에 위임하므로 임의
schema migration 검증을 의미하지 않습니다.
