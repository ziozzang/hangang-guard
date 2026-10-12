# Signed updates

[한국어](ko/UPDATES.md) · [Documentation index](README.md)

Hangang Guard is a decision authority in the zero-trust backbone. Its update
channel is part of the trust boundary: a compromised download origin must not be
able to replace the policy engine. Guard follows Hangang's signed-release
mechanism, with a separately pinned Guard public key and Guard repository.

## Trust model

Operators provision a base64 Ed25519 public key independently of the download
origin. There is no trust-on-first-use or unsigned fallback. The updater verifies
a signature over the exact decoded payload bytes before interpreting the
manifest. A valid release must match the running binary's target and have a
strictly newer semantic version. An equal version is a healthy no-op; downgrades,
malformed keys, weak keys, altered signatures, size mismatches, and SHA-256
mismatches are rejected.

Transport requires HTTPS. A manifest is limited to 64 KiB and its binary to
128 MiB; downloads are streamed to a temporary file. Generic HTTPS redirects
must retain the original scheme, host, and port. The GitHub release mode allows
only the pinned `ziozzang/hangang-guard` release asset paths, their corresponding
GitHub API asset IDs, and GitHub's `release-assets.githubusercontent.com` CDN.
Release metadata is discovery information, never a signing authority. Selected
asset URL, size, target, and release version must agree with the signed payload.

For a private GitHub repository, set `HANGANG_GUARD_GITHUB_TOKEN` in the service's
environment. Authentication is sent to the pinned API endpoint and selected API
asset URLs. Authorization is removed on cross-origin redirects to the CDN.
Generic HTTPS manifest downloads never receive this token. Avoid placing it in
command-line arguments, manifest URLs, status responses, or logs.

## Release manifest

The signed payload has exactly these fields:

```json
{
  "version": "0.3.0",
  "target": "x86_64-unknown-linux-gnu",
  "artifact_url": "https://github.com/ziozzang/hangang-guard/releases/download/v0.3.0/hangang-guard-x86_64-unknown-linux-gnu",
  "sha256": "<64 lowercase hexadecimal characters>",
  "size": 12345678
}
```

The envelope contains base64 `payload` and `signature` fields. Payload JSON
whitespace and field order form part of the signature: sign the final bytes,
and do not regenerate the JSON after signing. Both envelope and payload reject
unknown fields. For GitHub releases, publish one binary
`hangang-guard-<target>` and one signed envelope
`hangang-guard-<target>.manifest.json` per supported target.

The separate offline helper signs the manifest:

```sh
cargo run -p guard-update --bin guard-release-sign -- \
  payload.json /secure/guard-release-seed manifest.json
cargo run -p guard-update --bin guard-release-sign -- \
  --public-key /secure/guard-release-seed
```

The seed file must be a regular file containing a base64 32-byte Ed25519 seed,
with Unix permissions excluding group and other access (for example `0600`).
Keep the seed outside the repository and deployment environment. The running
updater consumes the public key only. A Guard signing key is independent from
Hangang's signing key.

## Activation boundary

Candidates are staged in the installed executable's own directory. The updater
checks digest and size again immediately before activation, keeps a hard link
to the previous executable, atomically renames the candidate into place, and
syncs the directory. Staging cancellation removes the temporary file.
Activation requires regular files and rejects cross-directory staging.

Before activation, the supervisor runs bounded `--version` and `--check` probes
of the verified candidate. Its version report must agree with the signed
manifest; its configuration check must succeed. Probes allow at most 64 KiB of
stdout and 30 seconds, and kill the candidate if cancelled. `--check` must not
bind listeners, mutate policy, create the production database, or start another
writer.

Binary activation alone does not establish readiness. The process owner must
replace the serving worker, wait for explicit readiness, and restore the old
binary and worker if startup fails. Remove the rollback link only after
readiness succeeds. Guard workers must never concurrently open writable policy
databases during handoff. Updates do not migrate or roll back database schemas;
release candidates must remain compatible with existing policy storage.

The authority replacement interval must be handled according to Hangang's
explicit Guard failure policy. Choose `fail-closed` for protected zero-trust
routes. An operator-selected `fail-open` policy admits traffic during authority
failure and does not provide this guarantee. Listener ownership and readiness
are process-lifecycle responsibilities, separate from signature verification.

## Supervised automatic updates (Linux)

Provision the trusted public key in `HANGANG_GUARD_UPDATE_KEY` and the normal
collector/admin tokens in the service environment. Start the installed service:

```sh
hangang-guard --supervised --database /var/lib/hangang-guard/policy.sqlite3 \
  --listen 127.0.0.1:9080 --decision-listen 127.0.0.1:9081 \
  --update-github --update-key-env HANGANG_GUARD_UPDATE_KEY \
  --update-interval-seconds 300
```

For an operator-hosted signed envelope, substitute
`--update-manifest https://updates.example/guard.manifest.json` for
`--update-github`. `--update-status-file` optionally selects the supervisor's
status file. The public Guard repository does not need a GitHub token; provide
one only when access to a private repository requires it.

The Linux supervisor retains the listening sockets while a worker is replaced.
It checkpoints and stops the old worker before starting the candidate, so policy
storage has one writer. Readiness arrives over a private Unix socket. If the
candidate fails readiness, the supervisor restores the previous binary and
starts the previous worker. Existing connections can reset during replacement;
retained listeners can queue new connections. This is a brief authority
interruption, and protected Hangang routes must use `fail-closed`.

`--check` validates configuration without listeners or database creation.
`--check-update` inspects latest-release metadata without activating a binary;
a reported update is still subject to full signature verification before use.
`--version` and `--about` report binary identity and capabilities. Automatic
supervision is Linux-only; macOS builds support the policy service and offline
release helper, without supervised automatic activation.

## Native release qualification

The `Native binary qualification` workflow builds and tests Linux amd64/arm64
and macOS amd64/arm64 natively. CI artifacts are unsigned qualification assets
and cannot be accepted as signed updates. The workflow does not publish a
release. For a qualified target, prepare assets offline:

```sh
python3 tools/prepare_release.py --target x86_64-unknown-linux-gnu \
  --signing-seed-file /secure/guard-release-seed --output dist
```

The helper checks the workspace version and executable version, packages only
`hangang-guard`, `guard-release-sign`, and `LICENSE`, generates the signed
manifest and checksums, and checks an existing `release-public-key.txt` against
the signing seed. The output directory must be empty and separate from the
seed. `--unsigned` omits signed manifests and the public-key asset for CI
qualification. Publish the signed target binaries and envelopes under the
matching stable `v<version>` release tag after qualification succeeds.

## Validation

The updater test suite includes generated TLS release fixtures, valid signatures,
tampered signatures and payloads, downgrades, wrong targets, unsigned metadata
mismatches, oversized manifests, SHA-256 and size failures, atomic activation and
rollback, bounded executable preflight, and authenticated private asset redirects
that verify the token is absent at the CDN.

```sh
cargo test -p guard-update
```

## Status and process checks

Admin endpoints `GET /v1/update/status` and `POST /v1/update/check` show state and
queue a check of the configured source. The operator console exposes both. A
check may install a newer signed release automatically; it does not select a URL
or trust key. Disabled services reject check requests. A private release PKI
can be configured with `--update-ca /path/ca.pem` for generic HTTPS manifests;
GitHub updates use system roots and reject this flag. Worker grace is1–15seconds.

```sh
cargo build --locked -p guard-server -p guard-update --bins
python3 tools/update_smoke.py
```

The Linux fixture owns executable copies, generated Ed25519/testTLS keys and
temporary databases/listeners. It tests HUP restart, signature preflight, upgrade
activation, retained policy, failed readiness rollback, tamper rejection and
shutdown cancellation. Future-version launcher fixtures delegate to an owned
runtime; they validate lifecycle mechanisms, not arbitrary schema migrations.
