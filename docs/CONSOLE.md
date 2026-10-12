# Hangang console integration

[한국어](ko/CONSOLE.md) · [Documentation](README.md)

Guard is a native Hangang sidebar entry through an operator-installed trusted
console package. Generate it with `python3 tools/build_console_plugin.py`.
The generated `plugins/guard` manifest pins its JavaScript, HTML and stylesheet;
configure the reviewed manifest SHA-256 in Hangang's `--admin-plugins` registry.
An optional native `hangang-console` adapter can reuse an already running native
Hangang admin authority. No Guard account/password database is introduced.

The package reuses Guard's management functions: candidates, block/allow pools,
policy editing, IP/CIDR scoring and GeoIP inspection, structured/Lua rules,
GeoIP database reload, metrics and signed-update status/check. Its own token form
is removed. Host authentication supplies each registered call; the Guard admin
credential exists only in the server-side broker environment. Collector credentials
and decision endpoints are excluded from this management allowlist.

The host admits only current enabled administrators, rechecks authority before
backend dispatch and response disclosure, bounds requests/responses and persists
mutation intent/outcomes with actor and body hash. Viewers are denied. The host
owns account/session revocation; Guard continues to own network policy and state.
Already accepted backend mutations are not globally atomically revoked.

Packages are trusted same-origin code and must be reviewed; imports are not a
sandbox. Startup verifies immutable pinned files and rejects tampering/unsafe
permissions. Restart with a new pin to activate an update. No credentials or
backend origin appear in browser discovery. Keep package/config/audit paths
protected, and place public plaintext console adapters behind TLS/access controls.

The UI follows native Hangang light/dark theme variables, locale selection and
navigation lifecycle. Hidden views stop periodic requests; logout disposes views
and rejects late operations. Policy drafts remain while navigating other views.
Backend failures are visible and do not trigger automatic mutation retries.

Qualification includes reproducible package generation, hash/allowlist/credential
checks in the host, actual browser navigation/lifecycle and real-process management
operations. Refer to Hangang's `docs/CONSOLE_PLUGINS.md` for registry configuration
and to the zero-trust design repository for ontology/automation plans. Console
integration does not itself implement pentest orchestration or ontology decisions.
