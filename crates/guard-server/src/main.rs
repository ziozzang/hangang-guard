mod geoip;
mod lua_rules;
mod protocol;
#[cfg(target_os = "linux")]
mod supervisor;
use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, State as HttpState},
    http::{HeaderMap, StatusCode},
    response::{Html, IntoResponse, Response},
    routing::{get, post},
    serve::ListenerExt,
};
use clap::Parser;
use guard_core::{Block, Engine, EventBatch, Policy};
use rusqlite::Connection;
use serde::Deserialize;
use serde_json::{Value, json};
use std::{
    path::PathBuf,
    sync::{Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};

#[derive(Parser)]
#[command(
    name = env!("CARGO_BIN_NAME"),
    version,
    about = "Zero-trust IP/network decision authority"
)]
#[command(group(clap::ArgGroup::new("update_source").args(["update_manifest", "update_github"]).requires("supervised")))]
struct Args {
    /// Report version, identity, and capabilities without starting the service.
    #[arg(long)]
    about: bool,
    /// Validate configured credentials, stored policy and GeoIP without writes/listeners.
    #[arg(long)]
    check: bool,
    /// Discover latest stable GitHub release without activating it.
    #[arg(long)]
    check_update: bool,
    /// Linux stable-PID owner, retaining listeners across a single-writer replacement.
    #[arg(long)]
    supervised: bool,
    #[arg(long, hide = true)]
    serve_child: bool,
    #[arg(long)]
    update_manifest: Option<String>,
    #[arg(long)]
    update_github: bool,
    #[arg(long, default_value = "HANGANG_GUARD_UPDATE_KEY")]
    update_key_env: String,
    #[arg(long, requires = "update_source", conflicts_with = "update_github")]
    update_ca: Option<PathBuf>,
    #[arg(long, default_value_t = 300, value_parser = clap::value_parser!(u64).range(10..))]
    update_interval_seconds: u64,
    #[arg(long, requires = "supervised")]
    update_status_file: Option<PathBuf>,
    #[arg(long, default_value_t = 15, value_parser = clap::value_parser!(u64).range(1..=15))]
    update_grace_seconds: u64,

    #[arg(long, default_value = "127.0.0.1:9080")]
    listen: String,
    /// Optional persistent binary decision endpoint; remote listeners require mTLS.
    #[arg(long)]
    decision_listen: Option<std::net::SocketAddr>,
    #[arg(long, requires_all = ["decision_tls_key", "decision_client_ca", "decision_listen"])]
    decision_tls_cert: Option<PathBuf>,
    #[arg(long, requires = "decision_tls_cert")]
    decision_tls_key: Option<PathBuf>,
    #[arg(long, requires = "decision_tls_cert")]
    decision_client_ca: Option<PathBuf>,
    #[arg(long,default_value_t=4096,value_parser=clap::value_parser!(u32).range(1..=65536))]
    max_http_requests: u32,
    #[arg(long,default_value_t=8,value_parser=clap::value_parser!(u16).range(1..=64))]
    threads: u16,
    #[arg(long, default_value = "hangang-guard.sqlite3")]
    database: PathBuf,
    #[arg(long)]
    policy: Option<PathBuf>,
    #[arg(long)]
    asn_catalog: Option<PathBuf>,
    #[arg(long)]
    geoip_database: Option<PathBuf>,
    #[arg(long)]
    geoip_asn_database: Option<PathBuf>,
}
struct Inner {
    engine: Engine,
}
#[derive(Clone)]
struct App {
    inner: Arc<Mutex<Inner>>,
    view: Arc<arc_swap::ArcSwap<guard_core::DecisionView>>,
    db: Arc<Mutex<Connection>>,
    workers: Arc<tokio::sync::Semaphore>,
    max_http_requests: usize,
    geo: Arc<arc_swap::ArcSwap<geoip::GeoCatalog>>,
    geo_paths: Arc<geoip::GeoPaths>,
    geo_reload: Arc<tokio::sync::Semaphore>,
    collector: Arc<String>,
    admin: Arc<String>,
    update_status: Option<PathBuf>,
    update_request: Option<PathBuf>,
}
impl App {
    fn query<'a>(
        &self,
        view: &'a guard_core::DecisionView,
        ip: std::net::IpAddr,
        time: u64,
    ) -> guard_core::DecisionRef<'a> {
        if view.requires_geo() {
            let geo = self.geo.load();
            view.query_ip_context(ip, time, geo.context(ip))
        } else {
            view.query_ip(ip, time)
        }
    }
}
type ApiResult = Result<Json<Value>, (StatusCode, Json<Value>)>;
fn error(code: StatusCode, message: impl ToString) -> (StatusCode, Json<Value>) {
    (code, Json(json!({"error":message.to_string()})))
}
fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
fn authorize(headers: &HeaderMap, token: &str) -> Result<(), (StatusCode, Json<Value>)> {
    let supplied = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let supplied = supplied.strip_prefix("Bearer ").unwrap_or("");
    // Comparison visits every credential byte for equal-length credentials.
    let different = supplied.len() != token.len()
        || supplied
            .bytes()
            .zip(token.bytes())
            .fold(0u8, |a, (b, c)| a | (b ^ c))
            != 0;
    if different {
        Err(error(StatusCode::UNAUTHORIZED, "unauthorized"))
    } else {
        Ok(())
    }
}
fn persist_state(db: &mut Connection, state: &guard_core::State) -> anyhow::Result<()> {
    let encoded = serde_json::to_string(state)?;
    let tx = db.transaction()?;
    tx.execute("INSERT INTO checkpoint(id,body) VALUES(1,?1) ON CONFLICT(id) DO UPDATE SET body=excluded.body", [&encoded])?;
    tx.commit()?;
    Ok(())
}
async fn operation<F>(app: App, durable: bool, f: F) -> ApiResult
where
    F: FnOnce(&mut Engine) -> anyhow::Result<Value> + Send + 'static,
{
    let permit = app
        .workers
        .clone()
        .try_acquire_owned()
        .map_err(|_| error(StatusCode::SERVICE_UNAVAILABLE, "worker capacity reached"))?;
    tokio::task::spawn_blocking(move || {
        let _permit = permit;
        // DB gate orders durable writes and checkpoints, so an older checkpoint
        // cannot overwrite a newly committed policy. Ordinary queries skip it.
        let mut db =
            if durable {
                Some(app.db.lock().map_err(|_| {
                    error(StatusCode::INTERNAL_SERVER_ERROR, "database unavailable")
                })?)
            } else {
                None
            };
        let mut inner = app
            .inner
            .lock()
            .map_err(|_| error(StatusCode::INTERNAL_SERVER_ERROR, "state unavailable"))?;
        let value = if let Some(ref mut db) = db {
            let mut next = inner.engine.clone();
            let result = f(&mut next).map_err(|e| error(StatusCode::BAD_REQUEST, e))?;
            persist_state(db, &next.state())
                .map_err(|_| error(StatusCode::INTERNAL_SERVER_ERROR, "checkpoint failed"))?;
            inner.engine = next;
            result
        } else {
            f(&mut inner.engine).map_err(|e| error(StatusCode::BAD_REQUEST, e))?
        };
        if inner.engine.revision() != app.view.load().revision {
            app.view.store(Arc::new(inner.engine.decision_view()));
        }
        drop(inner);
        if serde_json::to_vec(&value)
            .map_err(|_| error(StatusCode::INTERNAL_SERVER_ERROR, "serialization failed"))?
            .len()
            > 4 * 1024 * 1024
        {
            return Err(error(
                StatusCode::SERVICE_UNAVAILABLE,
                "response exceeds size limit",
            ));
        }
        Ok(Json(value))
    })
    .await
    .map_err(|_| error(StatusCode::INTERNAL_SERVER_ERROR, "worker failed"))?
}

async fn events(HttpState(app): HttpState<App>, Json(batch): Json<EventBatch>) -> ApiResult {
    let received = now();
    if batch.events.len() > 256
        || batch.source_id.is_empty()
        || batch.source_id.len() > 64
        || batch
            .events
            .iter()
            .any(|e| e.observed_at.abs_diff(received) > 300)
    {
        return Err(error(
            StatusCode::BAD_REQUEST,
            "invalid event batch or timestamp",
        ));
    }
    operation(app, false, move |engine| {
        Ok(serde_json::to_value(engine.ingest(batch, received)?)?)
    })
    .await
}
async fn snapshot(HttpState(app): HttpState<App>) -> ApiResult {
    operation(app, false, |e| {
        anyhow::ensure!(
            e.rules().rules.is_empty(),
            "dynamic rules require decision protocol"
        );
        Ok(serde_json::to_value(e.snapshot(now()))?)
    })
    .await
    .map_err(|(code, body)| {
        if body.0["error"] == "dynamic rules require decision protocol" {
            (StatusCode::NOT_IMPLEMENTED, body)
        } else {
            (code, body)
        }
    })
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DecisionRequest {
    source_id: String,
    ip: std::net::IpAddr,
    kind: Option<guard_core::EventKind>,
}
async fn decision(
    HttpState(app): HttpState<App>,
    Json(input): Json<DecisionRequest>,
) -> Result<Response, (StatusCode, Json<Value>)> {
    if input.source_id.is_empty() || input.source_id.len() > 64 {
        return Err(error(StatusCode::BAD_REQUEST, "invalid source ID"));
    }
    let time = now();
    let view = app.view.load();
    let before = app.query(&view, input.ip, time);
    // Admission reads never wait for evidence aggregation or admin fsync.
    if input.kind.is_none() || before.action == "deny" {
        return Ok(Json(before).into_response());
    }
    drop(view);
    let geo = app.geo.load_full();
    operation(app, false, move |engine| {
        let ip = input.ip.to_string();
        if engine
            .decision_context(&ip, time, geo.context(input.ip))?
            .action
            != "deny"
        {
            engine.ingest(
                EventBatch {
                    source_id: input.source_id,
                    events: vec![guard_core::Event {
                        ip: ip.clone(),
                        kind: input.kind.expect("kind checked"),
                        observed_at: time,
                    }],
                },
                time,
            )?;
        }
        Ok(serde_json::to_value(engine.decision_context(
            &ip,
            time,
            geo.context(input.ip),
        )?)?)
    })
    .await
    .map(IntoResponse::into_response)
}

async fn status(HttpState(app): HttpState<App>) -> ApiResult {
    let max_requests = app.max_http_requests;
    let geoip = app.geo.load().status();
    operation(app,false,move|e|{let(candidates,blocks)=e.capacity();Ok(json!({"health":"ok","stats":e.stats(),"geoip":geoip,"rules":{"count":e.rules().rules.len(),"snapshot_supported":e.rules().rules.is_empty()},"capacity":{"candidates":candidates,"blocks":blocks,"max_candidates":guard_core::MAX_CANDIDATES,"max_blocks":guard_core::MAX_BLOCKS,"max_batch":256,"max_body_bytes":4*1024*1024,"max_workers":1024,"max_requests":max_requests}}))}).await
}

async fn candidates(HttpState(app): HttpState<App>) -> ApiResult {
    operation(app, false, |e| {
        Ok(serde_json::to_value(e.candidates(now()))?)
    })
    .await
}
async fn policy_get(HttpState(app): HttpState<App>) -> ApiResult {
    operation(app, false, |e| Ok(serde_json::to_value(e.policy())?)).await
}
async fn policy_put(HttpState(app): HttpState<App>, Json(policy): Json<Policy>) -> ApiResult {
    operation(app, true, move |e| {
        e.set_policy(policy)?;
        Ok(json!({"ok":true}))
    })
    .await
}
async fn blocks(HttpState(app): HttpState<App>) -> ApiResult {
    operation(app, false, |e| {
        Ok(serde_json::to_value(e.snapshot(now()).blocks)?)
    })
    .await
}
async fn block_add(HttpState(app): HttpState<App>, Json(block): Json<Block>) -> ApiResult {
    operation(app, true, move |e| {
        e.add_block(block, now())?;
        Ok(json!({"ok":true}))
    })
    .await
}
#[derive(Deserialize)]
struct Network {
    network: String,
}
async fn block_delete(HttpState(app): HttpState<App>, Json(input): Json<Network>) -> ApiResult {
    operation(app, true, move |e| {
        Ok(json!({"removed":e.remove_block(&input.network)?}))
    })
    .await
}
#[derive(Deserialize)]
struct Approval {
    ip: String,
}
async fn approve(HttpState(app): HttpState<App>, Json(input): Json<Approval>) -> ApiResult {
    operation(app, true, move |e| {
        Ok(serde_json::to_value(e.approve(&input.ip, now())?)?)
    })
    .await
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LookupRequest {
    ip: std::net::IpAddr,
}
async fn lookup(HttpState(app): HttpState<App>, Json(input): Json<LookupRequest>) -> ApiResult {
    let geo = app.geo.load_full();
    operation(app, false, move |engine| {
        let ip = input.ip.to_string();
        let inspection = engine.inspect_ip(&ip, now(), geo.context(input.ip))?;
        Ok(json!({"ip":ip,"geoip":geo.lookup(input.ip),"inspection":inspection}))
    })
    .await
}
async fn network_inspect(HttpState(app): HttpState<App>, Json(input): Json<Network>) -> ApiResult {
    operation(app, false, move |engine| {
        Ok(serde_json::to_value(
            engine.inspect_network(&input.network, now())?,
        )?)
    })
    .await
}
async fn geo_reload(HttpState(app): HttpState<App>) -> ApiResult {
    let _permit = app
        .geo_reload
        .clone()
        .try_acquire_owned()
        .map_err(|_| error(StatusCode::CONFLICT, "GeoIP reload already running"))?;
    let paths = app.geo_paths.clone();
    let catalog = tokio::task::spawn_blocking(move || geoip::GeoCatalog::load(&paths))
        .await
        .map_err(|_| error(StatusCode::INTERNAL_SERVER_ERROR, "GeoIP worker failed"))?
        .map_err(|e| error(StatusCode::BAD_REQUEST, e))?;
    let status = catalog.status();
    app.geo.store(Arc::new(catalog));
    Ok(Json(json!({"geoip":status})))
}
async fn rules_get(HttpState(app): HttpState<App>) -> ApiResult {
    operation(app, false, |e| Ok(serde_json::to_value(e.rules())?)).await
}
async fn rules_put(
    HttpState(app): HttpState<App>,
    Json(rules): Json<guard_core::RuleSet>,
) -> ApiResult {
    operation(app, true, move |e| {
        e.set_rules(rules)?;
        Ok(serde_json::to_value(e.rules())?)
    })
    .await
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LuaRequest {
    script: String,
}
async fn compile_script(
    app: &App,
    script: String,
) -> Result<guard_core::RuleSet, (StatusCode, Json<Value>)> {
    let permit = app
        .workers
        .clone()
        .try_acquire_owned()
        .map_err(|_| error(StatusCode::SERVICE_UNAVAILABLE, "worker capacity reached"))?;
    tokio::task::spawn_blocking(move || {
        let _permit = permit;
        lua_rules::compile_lua(&script)
    })
    .await
    .map_err(|_| error(StatusCode::INTERNAL_SERVER_ERROR, "rule worker failed"))?
    .map_err(|e| error(StatusCode::BAD_REQUEST, e))
}
async fn rules_lua(HttpState(app): HttpState<App>, Json(input): Json<LuaRequest>) -> ApiResult {
    let rules = compile_script(&app, input.script).await?;
    operation(app, true, move |e| {
        e.set_rules(rules)?;
        Ok(serde_json::to_value(e.rules())?)
    })
    .await
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RuleValidation {
    rules: Option<guard_core::RuleSet>,
    script: Option<String>,
}
async fn rules_validate(
    HttpState(app): HttpState<App>,
    Json(input): Json<RuleValidation>,
) -> ApiResult {
    let rules = match (input.rules, input.script) {
        (Some(mut rules), None) => {
            rules
                .validate()
                .map_err(|e| error(StatusCode::BAD_REQUEST, e))?;
            rules
        }
        (None, Some(script)) => compile_script(&app, script).await?,
        _ => {
            return Err(error(
                StatusCode::BAD_REQUEST,
                "provide exactly one of rules or script",
            ));
        }
    };
    Ok(Json(json!({"valid":true,"rules":rules})))
}
fn router(app: App) -> Router {
    let credentials = app.clone();
    let requests = Arc::new(tokio::sync::Semaphore::new(app.max_http_requests));
    Router::new()
        .route("/", get(|| async { Html(include_str!("dashboard.html")) }))
        .route("/healthz", get(|| async { Json(json!({"status":"ok"})) }))
        .route(
            "/v1/decision",
            post(decision).layer(DefaultBodyLimit::max(4096)),
        )
        .route("/v1/events", post(events))
        .route("/v1/snapshot", get(snapshot))
        .route("/v1/status", get(status))
        .route("/v1/update/status", get(update_status))
        .route("/v1/update/check", post(update_check))
        .route(
            "/v1/lookup",
            post(lookup).layer(DefaultBodyLimit::max(4096)),
        )
        .route(
            "/v1/networks/inspect",
            post(network_inspect).layer(DefaultBodyLimit::max(4096)),
        )
        .route("/v1/geoip/reload", post(geo_reload))
        .route("/v1/rules", get(rules_get).put(rules_put))
        .route(
            "/v1/rules/lua",
            axum::routing::put(rules_lua).layer(DefaultBodyLimit::max(64 * 1024)),
        )
        .route("/v1/rules/validate", post(rules_validate))
        .route("/v1/candidates", get(candidates))
        .route("/v1/policy", get(policy_get).put(policy_put))
        .route(
            "/v1/blocks",
            get(blocks).post(block_add).delete(block_delete),
        )
        .route("/v1/candidates/approve", post(approve))
        .layer(DefaultBodyLimit::max(4 * 1024 * 1024))
        .layer(axum::middleware::from_fn(
            move |request: axum::extract::Request, next: axum::middleware::Next| {
                let credentials = credentials.clone();
                let requests = requests.clone();
                async move {
                    use axum::response::IntoResponse;
                    let _permit = match requests.try_acquire_owned() {
                        Ok(p) => p,
                        Err(_) => {
                            return error(
                                StatusCode::SERVICE_UNAVAILABLE,
                                "request capacity reached",
                            )
                            .into_response();
                        }
                    };
                    let path = request.uri().path();
                    let token = if matches!(path, "/v1/events" | "/v1/snapshot" | "/v1/decision") {
                        Some(credentials.collector.as_str())
                    } else if path.starts_with("/v1/") {
                        Some(credentials.admin.as_str())
                    } else {
                        None
                    };
                    if let Some(token) = token
                        && let Err(e) = authorize(request.headers(), token)
                    {
                        return e.into_response();
                    }
                    next.run(request).await
                }
            },
        ))
        .layer(axum::middleware::from_fn(
            |request: axum::extract::Request, next: axum::middleware::Next| async move {
                let mut response = next.run(request).await;
                response.headers_mut().insert(
                    "x-content-type-options",
                    axum::http::HeaderValue::from_static("nosniff"),
                );
                response.headers_mut().insert(
                    "cache-control",
                    axum::http::HeaderValue::from_static("no-store"),
                );
                response
            },
        ))
        .with_state(app)
}
fn open_database(path: &std::path::Path) -> anyhow::Result<Connection> {
    let db = Connection::open(path)?;
    db.busy_timeout(std::time::Duration::from_secs(5))?;
    db.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; CREATE TABLE IF NOT EXISTS checkpoint(id INTEGER PRIMARY KEY CHECK(id=1), body TEXT NOT NULL);")?;
    Ok(db)
}

async fn update_status(HttpState(app): HttpState<App>) -> ApiResult {
    let Some(path) = app.update_status else {
        return Ok(Json(
            json!({"enabled":false,"phase":"disabled","current_version":env!("CARGO_PKG_VERSION")}),
        ));
    };
    let result = tokio::task::spawn_blocking(move || read_bounded(&path, 16 * 1024))
        .await
        .map_err(|_| error(StatusCode::SERVICE_UNAVAILABLE, "update status unavailable"))?;
    let bytes =
        result.map_err(|_| error(StatusCode::SERVICE_UNAVAILABLE, "update status unavailable"))?;
    Ok(Json(serde_json::from_slice(&bytes).map_err(|_| {
        error(StatusCode::SERVICE_UNAVAILABLE, "invalid update status")
    })?))
}

async fn update_check(HttpState(app): HttpState<App>) -> ApiResult {
    let Some(path) = app.update_request else {
        return Err(error(
            StatusCode::CONFLICT,
            "automatic updates are disabled",
        ));
    };
    let mut options = tokio::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(0o600);
    match options.open(path).await {
        Ok(file) => file.sync_all().await.map_err(|_| {
            error(
                StatusCode::SERVICE_UNAVAILABLE,
                "could not queue update check",
            )
        })?,
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(_) => {
            return Err(error(
                StatusCode::SERVICE_UNAVAILABLE,
                "could not queue update check",
            ));
        }
    }
    Ok(Json(json!({"queued":true})))
}

fn read_bounded(path: &std::path::Path, max: usize) -> anyhow::Result<Vec<u8>> {
    use std::io::Read;
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NONBLOCK | libc::O_CLOEXEC);
    }
    let file = options.open(path)?;
    anyhow::ensure!(
        file.metadata()?.is_file(),
        "configured input is not a regular file"
    );
    let mut bytes = Vec::new();
    file.take(max as u64 + 1).read_to_end(&mut bytes)?;
    anyhow::ensure!(bytes.len() <= max, "configured input exceeds size limit");
    Ok(bytes)
}

fn check_configuration(args: &Args) -> anyhow::Result<()> {
    if args.update_github || args.update_manifest.is_some() {
        let key = std::env::var(&args.update_key_env)
            .map_err(|_| anyhow::anyhow!("update public-key environment variable unavailable"))?;
        guard_update::update::TrustKey::from_base64(&key)?;
    }
    if let Some(path) = &args.update_ca {
        reqwest::Certificate::from_pem(&read_bounded(path, 128 * 1024)?)?;
    }
    let collector = std::env::var("HANGANG_GUARD_COLLECTOR_TOKEN")?;
    let admin = std::env::var("HANGANG_GUARD_ADMIN_TOKEN")?;
    anyhow::ensure!(
        (16..=4096).contains(&collector.len())
            && (16..=4096).contains(&admin.len())
            && collector != admin,
        "tokens must be distinct and 16..4096 bytes"
    );
    let mut engine = if args.database.exists() {
        let db = Connection::open_with_flags(
            &args.database,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
        )?;
        let saved = db.query_row("SELECT body FROM checkpoint WHERE id=1", [], |r| {
            r.get::<_, String>(0)
        });
        match saved {
            Ok(body) => Engine::restore(serde_json::from_str(&body)?)?,
            Err(rusqlite::Error::QueryReturnedNoRows) => Engine::new(Policy::default())?,
            Err(e) => return Err(e.into()),
        }
    } else {
        let parent = args
            .database
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(std::path::Path::new("."));
        anyhow::ensure!(parent.is_dir(), "database directory does not exist");
        Engine::new(Policy::default())?
    };
    if let Some(path) = &args.policy {
        engine.set_policy(serde_json::from_slice(&read_bounded(
            path,
            4 * 1024 * 1024,
        )?)?)?;
    }
    if let Some(path) = &args.asn_catalog {
        engine.set_asn_catalog(serde_json::from_slice(&read_bounded(
            path,
            16 * 1024 * 1024,
        )?)?)?;
    }
    geoip::GeoCatalog::load(&geoip::GeoPaths {
        country: args.geoip_database.clone(),
        asn: args.geoip_asn_database.clone(),
    })?;
    Ok(())
}

#[cfg(target_os = "linux")]
fn worker_arguments() -> Vec<std::ffi::OsString> {
    let mut input = std::env::args_os().skip(1);
    let mut result = Vec::new();
    while let Some(arg) = input.next() {
        let name = arg.to_str().unwrap_or("").split('=').next().unwrap_or("");
        if matches!(
            name,
            "--supervised"
                | "--serve-child"
                | "--update-github"
                | "--check"
                | "--check-update"
                | "--about"
        ) {
            continue;
        }
        if matches!(
            name,
            "--update-manifest"
                | "--update-ca"
                | "--update-key-env"
                | "--update-interval-seconds"
                | "--update-status-file"
                | "--update-grace-seconds"
        ) {
            if !arg.to_str().unwrap_or("").contains('=') {
                input.next();
            }
            continue;
        }
        result.push(arg);
    }
    result
}
fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    if args.about {
        println!(
            "{}",
            json!({"name":"sumunjang","version":env!("CARGO_PKG_VERSION"),"repository":"https://github.com/ziozzang/sumunjang","role":"zero-trust IP/network decision authority","principal_management":"hopae","target":env!("GUARD_TARGET"),"supervised_updates":cfg!(target_os="linux")})
        );
        return Ok(());
    }
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(args.threads as usize)
        .enable_all()
        .build()?
        .block_on(run(args))
}
async fn run(args: Args) -> anyhow::Result<()> {
    if args.check_update {
        let release = guard_update::github_release::latest().await?;
        println!(
            "{}",
            serde_json::to_string(&release.check(
                semver::Version::parse(env!("CARGO_PKG_VERSION"))?,
                env!("GUARD_TARGET")
            )?)?
        );
        return Ok(());
    }
    if let Some(address) = args.decision_listen {
        anyhow::ensure!(
            (address.ip().is_loopback() || args.decision_tls_cert.is_some())
                && !address.ip().is_multicast(),
            "remote binary decision listener requires mTLS"
        );
    }
    let decision_tls = args
        .decision_tls_cert
        .as_ref()
        .map(|cert| {
            protocol::tls_acceptor(
                cert,
                args.decision_tls_key.as_ref().unwrap(),
                args.decision_client_ca.as_ref().unwrap(),
            )
        })
        .transpose()?;
    if args.check {
        check_configuration(&args)?;
        println!("configuration valid");
        return Ok(());
    }
    if args.supervised && !args.serve_child {
        #[cfg(target_os = "linux")]
        {
            check_configuration(&args)?;
            let update = if args.update_github || args.update_manifest.is_some() {
                let public_key = std::env::var(&args.update_key_env).map_err(|_| {
                    anyhow::anyhow!("update public-key environment variable unavailable")
                })?;
                guard_update::update::TrustKey::from_base64(&public_key)?;
                Some(supervisor::UpdateOptions {
                    manifest_url: args.update_manifest.clone(),
                    github: args.update_github,
                    additional_ca: args.update_ca.clone(),
                    public_key,
                    interval: std::time::Duration::from_secs(args.update_interval_seconds),
                    status_path: args
                        .update_status_file
                        .clone()
                        .unwrap_or_else(|| args.database.with_extension("update-status.json")),
                })
            } else {
                None
            };
            return supervisor::run(supervisor::Options {
                http: args.listen.parse().map_err(|_| {
                    anyhow::anyhow!("supervised listener must be a literal IP:port")
                })?,
                decision: args.decision_listen,
                database: args.database.clone(),
                worker_arguments: worker_arguments(),
                update,
                grace: std::time::Duration::from_secs(args.update_grace_seconds),
            })
            .await;
        }
        #[cfg(not(target_os = "linux"))]
        anyhow::bail!("supervised automatic updates require Linux");
    }
    if args.serve_child {
        anyhow::ensure!(
            std::env::var("HANGANG_GUARD_WORKER").as_deref() == Ok("1"),
            "private worker handshake unavailable"
        );
        #[cfg(not(target_os = "linux"))]
        anyhow::bail!("supervised workers require Linux");
    }
    let collector = std::env::var("HANGANG_GUARD_COLLECTOR_TOKEN")?;
    let admin = std::env::var("HANGANG_GUARD_ADMIN_TOKEN")?;
    anyhow::ensure!(
        (16..=4096).contains(&collector.len())
            && (16..=4096).contains(&admin.len())
            && collector != admin,
        "tokens must be distinct and 16..4096 bytes"
    );
    let mut db = open_database(&args.database)?;
    let saved = db.query_row("SELECT body FROM checkpoint WHERE id=1", [], |r| {
        r.get::<_, String>(0)
    });
    let mut engine = match saved {
        Ok(body) => Engine::restore(serde_json::from_str(&body)?)?,
        Err(rusqlite::Error::QueryReturnedNoRows) => Engine::new(Policy::default())?,
        Err(e) => return Err(e.into()),
    };
    if let Some(path) = args.policy {
        engine.set_policy(serde_json::from_slice(&std::fs::read(path)?)?)?;
    }
    if let Some(path) = args.asn_catalog {
        engine.set_asn_catalog(serde_json::from_slice(&std::fs::read(path)?)?)?;
    }
    persist_state(&mut db, &engine.state())?;
    let geo_paths = geoip::GeoPaths {
        country: args.geoip_database,
        asn: args.geoip_asn_database,
    };
    let geo = geoip::GeoCatalog::load(&geo_paths)?;
    let app = App {
        geo: Arc::new(arc_swap::ArcSwap::from_pointee(geo)),
        geo_paths: Arc::new(geo_paths),
        geo_reload: Arc::new(tokio::sync::Semaphore::new(1)),
        max_http_requests: args.max_http_requests as usize,
        view: Arc::new(arc_swap::ArcSwap::from_pointee(engine.decision_view())),
        inner: Arc::new(Mutex::new(Inner { engine })),
        db: Arc::new(Mutex::new(db)),
        workers: Arc::new(tokio::sync::Semaphore::new(1024)),
        collector: Arc::new(collector),
        admin: Arc::new(admin),
        update_status: args
            .serve_child
            .then(|| std::env::var_os("HANGANG_GUARD_UPDATE_STATUS").map(PathBuf::from))
            .flatten(),
        update_request: args
            .serve_child
            .then(|| std::env::var_os("HANGANG_GUARD_UPDATE_REQUEST").map(PathBuf::from))
            .flatten(),
    };
    let (stop_tx, mut stop_rx) = tokio::sync::watch::channel(false);
    let binary_worker = if let Some(address) = args.decision_listen {
        anyhow::ensure!(
            (address.ip().is_loopback() || args.decision_tls_cert.is_some())
                && !address.ip().is_multicast(),
            "remote binary decision listener requires mTLS"
        );
        let binary = if args.serve_child {
            #[cfg(target_os = "linux")]
            {
                supervisor::inherited_listener("HANGANG_GUARD_DECISION_FD", address)?
            }
            #[cfg(not(target_os = "linux"))]
            {
                anyhow::bail!("supervised workers require Linux");
            }
        } else {
            tokio::net::TcpListener::bind(address).await?
        };
        eprintln!("binary decisions listening on {}", binary.local_addr()?);
        Some(tokio::spawn(protocol::serve_with_tls(
            binary,
            app.clone(),
            stop_rx.clone(),
            decision_tls,
        )))
    } else {
        None
    };
    let checkpoint_app = app.clone();
    let worker = tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(5));
        loop {
            tokio::select! {_ = interval.tick()=>{let a=checkpoint_app.clone();if let Err(e)=checkpoint(a).await {eprintln!("checkpoint failed: {e}");}}, _=stop_rx.changed()=>break}
        }
    });
    let listener = if args.serve_child {
        #[cfg(target_os = "linux")]
        {
            supervisor::inherited_listener("HANGANG_GUARD_HTTP_FD", args.listen.parse()?)?
        }
        #[cfg(not(target_os = "linux"))]
        {
            anyhow::bail!("supervised workers require Linux");
        }
    } else {
        tokio::net::TcpListener::bind(&args.listen).await?
    };
    eprintln!("sumunjang listening on {}", listener.local_addr()?);
    let shutdown_stop = stop_tx.clone();
    let listener = listener.tap_io(|stream| {
        if let Err(e) = stream.set_nodelay(true) {
            eprintln!("HTTP TCP_NODELAY failed: {e}");
        }
    });
    if args.serve_child {
        #[cfg(target_os = "linux")]
        supervisor::notify_ready()?;
    }
    let serving = axum::serve(listener, router(app.clone()))
        .with_graceful_shutdown(async move {
            shutdown().await;
            let _ = shutdown_stop.send(true);
        })
        .await;
    let _ = stop_tx.send(true);
    let _ = worker.await;
    if let Some(worker) = binary_worker {
        worker.await??;
    }
    checkpoint(app).await?;
    serving?;
    Ok(())
}
async fn checkpoint(app: App) -> anyhow::Result<()> {
    tokio::task::spawn_blocking(move || {
        let mut db = app
            .db
            .lock()
            .map_err(|_| anyhow::anyhow!("database unavailable"))?;
        let state = {
            let inner = app
                .inner
                .lock()
                .map_err(|_| anyhow::anyhow!("state unavailable"))?;
            inner.engine.state()
        };
        // Serialization and SQLite fsync run without holding the engine lock.
        persist_state(&mut db, &state)
    })
    .await?
}

async fn shutdown() {
    #[cfg(unix)]
    {
        let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("SIGTERM handler");
        tokio::select! {_=tokio::signal::ctrl_c()=>{},_=term.recv()=>{}}
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{body::Body, http::Request};
    use tower::ServiceExt;
    pub(crate) fn app() -> App {
        let db = Connection::open_in_memory().unwrap();
        db.execute_batch("CREATE TABLE checkpoint(id INTEGER PRIMARY KEY,body TEXT NOT NULL)")
            .unwrap();
        App {
            geo: Arc::new(arc_swap::ArcSwap::from_pointee(geoip::GeoCatalog::default())),
            geo_paths: Arc::new(geoip::GeoPaths::default()),
            geo_reload: Arc::new(tokio::sync::Semaphore::new(1)),
            max_http_requests: 4096,
            view: Arc::new(arc_swap::ArcSwap::from_pointee(
                Engine::new(Policy::default()).unwrap().decision_view(),
            )),
            inner: Arc::new(Mutex::new(Inner {
                engine: Engine::new(Policy::default()).unwrap(),
            })),
            db: Arc::new(Mutex::new(db)),
            workers: Arc::new(tokio::sync::Semaphore::new(1024)),
            collector: Arc::new("collector-test-token".into()),
            admin: Arc::new("admin-test-token".into()),
            update_status: None,
            update_request: None,
        }
    }

    async fn request(
        app: App,
        path: &str,
        method: &str,
        token: &str,
        body: Value,
    ) -> (StatusCode, Value) {
        let r = router(app)
            .oneshot(
                Request::builder()
                    .uri(path)
                    .method(method)
                    .header("authorization", format!("Bearer {token}"))
                    .header("content-type", "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = r.status();
        let bytes = axum::body::to_bytes(r.into_body(), 4 * 1024 * 1024)
            .await
            .unwrap();
        (status, serde_json::from_slice(&bytes).unwrap())
    }
    #[tokio::test]
    async fn separated_credentials() {
        let a = app();
        assert_eq!(
            request(
                a.clone(),
                "/v1/status",
                "GET",
                "collector-test-token",
                json!(null)
            )
            .await
            .0,
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            request(
                a.clone(),
                "/v1/snapshot",
                "GET",
                "admin-test-token",
                json!(null)
            )
            .await
            .0,
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            request(a, "/v1/status", "GET", "admin-test-token", json!(null))
                .await
                .0,
            StatusCode::OK
        );
    }
    #[tokio::test]
    async fn policy_checkpoint_and_failure_rollback() {
        let a = app();
        let p = json!({"mode":"enforce","auto_block":false});
        assert_eq!(
            request(a.clone(), "/v1/policy", "PUT", "admin-test-token", p)
                .await
                .0,
            StatusCode::OK
        );
        {
            let db = a.db.lock().unwrap();
            let body: String = db
                .query_row("SELECT body FROM checkpoint WHERE id=1", [], |r| r.get(0))
                .unwrap();
            let restored = Engine::restore(serde_json::from_str(&body).unwrap()).unwrap();
            assert_eq!(restored.policy().mode, guard_core::Mode::Enforce);
            db.execute_batch("DROP TABLE checkpoint").unwrap();
        }
        assert_eq!(
            request(
                a.clone(),
                "/v1/policy",
                "PUT",
                "admin-test-token",
                json!({"mode":"observe"})
            )
            .await
            .0,
            StatusCode::INTERNAL_SERVER_ERROR
        );
        assert_eq!(
            a.inner.lock().unwrap().engine.policy().mode,
            guard_core::Mode::Enforce
        );
    }
    #[tokio::test]
    async fn invalid_events_and_approval_persist() {
        let a = app();
        let time = now();
        assert_eq!(request(a.clone(),"/v1/events","POST","collector-test-token",json!({"source_id":"test","events":[{"ip":"192.0.2.1","kind":"honeypot","observed_at":time-301}]})).await.0,StatusCode::BAD_REQUEST);
        assert_eq!(request(a.clone(),"/v1/events","POST","collector-test-token",json!({"source_id":"test","events":[{"ip":"192.0.2.1","kind":"honeypot","observed_at":time}]})).await.0,StatusCode::OK);
        assert_eq!(
            request(
                a.clone(),
                "/v1/candidates/approve",
                "POST",
                "admin-test-token",
                json!({"ip":"192.0.2.1"})
            )
            .await
            .0,
            StatusCode::OK
        );
        let db = a.db.lock().unwrap();
        let body: String = db
            .query_row("SELECT body FROM checkpoint WHERE id=1", [], |r| r.get(0))
            .unwrap();
        let mut restored = Engine::restore(serde_json::from_str(&body).unwrap()).unwrap();
        assert_eq!(restored.snapshot(time).blocks.len(), 1);
    }
    #[tokio::test]
    async fn rules_geo_lookup_durability_and_snapshot_rejection() {
        let a = app();
        let paths = geoip::GeoPaths {
            country: Some(
                std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                    .join("fixtures/GeoIP2-Country-Test.mmdb"),
            ),
            asn: None,
        };
        a.geo
            .store(Arc::new(geoip::GeoCatalog::load(&paths).unwrap()));
        assert_eq!(
            request(
                a.clone(),
                "/v1/lookup",
                "POST",
                "collector-test-token",
                json!({"ip":"81.2.69.160"})
            )
            .await
            .0,
            StatusCode::UNAUTHORIZED
        );
        let rules = json!({"version":1,"rules":[{"id":"gb","priority":10,"countries":["gb"],"action":"deny","score":10},{"id":"network-watch","network":"192.0.2.0/24","action":"observe","score":7}]});
        let (status, validated) = request(
            a.clone(),
            "/v1/rules/validate",
            "POST",
            "admin-test-token",
            json!({"rules":rules}),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(validated["rules"]["rules"][0]["countries"][0], "GB");
        assert_eq!(a.inner.lock().unwrap().engine.rules().rules.len(), 0);
        request(
            a.clone(),
            "/v1/policy",
            "PUT",
            "admin-test-token",
            json!({"mode":"enforce"}),
        )
        .await;
        assert_eq!(
            request(a.clone(), "/v1/rules", "PUT", "admin-test-token", rules)
                .await
                .0,
            StatusCode::OK
        );
        assert_eq!(
            request(
                a.clone(),
                "/v1/snapshot",
                "GET",
                "collector-test-token",
                json!(null)
            )
            .await
            .0,
            StatusCode::NOT_IMPLEMENTED
        );
        for kind in [None, Some("honeypot")] {
            let mut input = json!({"source_id":"test","ip":"81.2.69.160"});
            if let Some(kind) = kind {
                input["kind"] = json!(kind);
            }
            let (_, decision) = request(
                a.clone(),
                "/v1/decision",
                "POST",
                "collector-test-token",
                input,
            )
            .await;
            assert_eq!(decision["action"], "deny");
        }
        let (_, unknown) = request(
            a.clone(),
            "/v1/decision",
            "POST",
            "collector-test-token",
            json!({"source_id":"test","ip":"192.0.2.1"}),
        )
        .await;
        assert_eq!(unknown["action"], "allow");
        let (_, found) = request(
            a.clone(),
            "/v1/lookup",
            "POST",
            "admin-test-token",
            json!({"ip":"81.2.69.160"}),
        )
        .await;
        assert_eq!(found["geoip"]["country_code"], "GB");
        assert_eq!(found["inspection"]["score"], 10);
        assert_eq!(found["inspection"]["suspicion"], "blocked");
        let (_, network) = request(
            a.clone(),
            "/v1/networks/inspect",
            "POST",
            "admin-test-token",
            json!({"network":"192.0.2.31/24"}),
        )
        .await;
        assert_eq!(network["network"], "192.0.2.0/24");
        assert_eq!(network["static_rule_score"], 7);
        let body: String =
            a.db.lock()
                .unwrap()
                .query_row("SELECT body FROM checkpoint WHERE id=1", [], |r| r.get(0))
                .unwrap();
        let restored = Engine::restore(serde_json::from_str(&body).unwrap()).unwrap();
        assert_eq!(restored.rules().rules.len(), 2);
        let script = "return {version=1,rules={{id='lua-watch',network='192.0.2.0/24',action='observe',score=3}}}";
        assert_eq!(
            request(
                a.clone(),
                "/v1/rules/lua",
                "PUT",
                "admin-test-token",
                json!({"script":script})
            )
            .await
            .0,
            StatusCode::OK
        );
        assert_eq!(
            a.inner.lock().unwrap().engine.rules().rules[0].id,
            "lua-watch"
        );
        assert_eq!(
            request(
                a,
                "/v1/rules/validate",
                "POST",
                "admin-test-token",
                json!({"rules":{"version":1,"rules":[]},"script":script})
            )
            .await
            .0,
            StatusCode::BAD_REQUEST
        );
    }
    #[tokio::test]
    async fn failed_geo_reload_preserves_last_good() {
        let mut a = app();
        let path = std::env::temp_dir().join(format!(
            "guard-geo-test-{}-{}.mmdb",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::copy(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("fixtures/GeoIP2-Country-Test.mmdb"),
            &path,
        )
        .unwrap();
        a.geo_paths = Arc::new(geoip::GeoPaths {
            country: Some(path.clone()),
            asn: None,
        });
        assert_eq!(
            request(
                a.clone(),
                "/v1/geoip/reload",
                "POST",
                "admin-test-token",
                json!(null)
            )
            .await
            .0,
            StatusCode::OK
        );
        std::fs::write(&path, b"invalid").unwrap();
        assert_eq!(
            request(
                a.clone(),
                "/v1/geoip/reload",
                "POST",
                "admin-test-token",
                json!(null)
            )
            .await
            .0,
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            a.geo.load().context("81.2.69.160".parse().unwrap()).country,
            Some("GB")
        );
        std::fs::remove_file(path).unwrap();
    }
    #[tokio::test]
    #[allow(clippy::await_holding_lock)] // Deliberately prove queries bypass both held locks.
    async fn plain_decision_does_not_wait_for_engine_or_database() {
        let a = app();
        let held = a.clone();
        let engine_lock = held.inner.lock().unwrap();
        let database_lock = held.db.lock().unwrap();
        let response = tokio::time::timeout(
            std::time::Duration::from_millis(100),
            request(
                a,
                "/v1/decision",
                "POST",
                "collector-test-token",
                json!({"source_id":"test","ip":"192.0.2.1"}),
            ),
        )
        .await
        .unwrap();
        assert_eq!(response.0, StatusCode::OK);
        assert_eq!(response.1["action"], "allow");
        drop(engine_lock);
        drop(database_lock);
    }
    #[tokio::test]
    async fn active_blocks_admin_only_and_headers() {
        let a = app();
        assert_eq!(
            request(
                a.clone(),
                "/v1/blocks",
                "GET",
                "collector-test-token",
                json!(null)
            )
            .await
            .0,
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            request(
                a.clone(),
                "/v1/blocks",
                "POST",
                "admin-test-token",
                json!({"network":"192.0.2.0/24","expires_at":now()+300,"reason":"manual"})
            )
            .await
            .0,
            StatusCode::OK
        );
        let (status, blocks) = request(
            a.clone(),
            "/v1/blocks",
            "GET",
            "admin-test-token",
            json!(null),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(blocks[0]["network"], "192.0.2.0/24");
        let response = router(a.clone())
            .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.headers()["x-content-type-options"], "nosniff");
        assert_eq!(response.headers()["cache-control"], "no-store");
        let response = router(a)
            .oneshot(
                Request::builder()
                    .uri("/v1/blocks")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(response.headers()["cache-control"], "no-store");
    }
    #[tokio::test]
    async fn remote_decision_blocks_without_renewal() {
        let a = app();
        assert_eq!(
            request(
                a.clone(),
                "/v1/decision",
                "POST",
                "admin-test-token",
                json!({"source_id":"test","ip":"192.0.2.1"})
            )
            .await
            .0,
            StatusCode::UNAUTHORIZED
        );
        request(
            a.clone(),
            "/v1/policy",
            "PUT",
            "admin-test-token",
            json!({"mode":"enforce","auto_block":true}),
        )
        .await;
        let (_, first) = request(
            a.clone(),
            "/v1/decision",
            "POST",
            "collector-test-token",
            json!({"source_id":"test","ip":"192.0.2.1","kind":"honeypot"}),
        )
        .await;
        assert_eq!(first["action"], "deny");
        assert!(first["ttl_ms"].as_u64().unwrap() <= 5000);
        let before = a.inner.lock().unwrap().engine.stats().accepted;
        let (_, second) = request(
            a.clone(),
            "/v1/decision",
            "POST",
            "collector-test-token",
            json!({"source_id":"test","ip":"192.0.2.1","kind":"honeypot"}),
        )
        .await;
        assert_eq!(second["action"], "deny");
        assert_eq!(a.inner.lock().unwrap().engine.stats().accepted, before);
        request(
            a.clone(),
            "/v1/policy",
            "PUT",
            "admin-test-token",
            json!({"mode":"enforce","allow":["192.0.2.1/32"]}),
        )
        .await;
        let (_, allowed) = request(
            a,
            "/v1/decision",
            "POST",
            "collector-test-token",
            json!({"source_id":"test","ip":"192.0.2.1"}),
        )
        .await;
        assert_eq!(allowed["action"], "allow");
    }
    #[tokio::test]
    async fn body_and_batch_bounds() {
        let a = app();
        let response = router(a.clone())
            .oneshot(
                Request::builder()
                    .uri("/v1/events")
                    .method("POST")
                    .header("authorization", "Bearer collector-test-token")
                    .header("content-type", "application/json")
                    .body(Body::from(vec![b' '; 4 * 1024 * 1024 + 1]))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
        let event = json!({"ip":"192.0.2.1","kind":"scanner","observed_at":now()});
        assert_eq!(
            request(
                a,
                "/v1/events",
                "POST",
                "collector-test-token",
                json!({"source_id":"test","events":vec![event;257]})
            )
            .await
            .0,
            StatusCode::BAD_REQUEST
        );
    }
}
