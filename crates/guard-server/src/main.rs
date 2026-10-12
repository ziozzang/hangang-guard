use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, State as HttpState},
    http::{HeaderMap, StatusCode},
    response::Html,
    routing::{get, post},
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
#[command(name = "hangang-guard")]
struct Args {
    #[arg(long, default_value = "127.0.0.1:9080")]
    listen: String,
    #[arg(long, default_value = "hangang-guard.sqlite3")]
    database: PathBuf,
    #[arg(long)]
    policy: Option<PathBuf>,
    #[arg(long)]
    asn_catalog: Option<PathBuf>,
}
struct Inner {
    engine: Engine,
}
#[derive(Clone)]
struct App {
    inner: Arc<Mutex<Inner>>,
    db: Arc<Mutex<Connection>>,
    workers: Arc<tokio::sync::Semaphore>,
    collector: Arc<String>,
    admin: Arc<String>,
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
    let expected = format!("Bearer {token}");
    let supplied = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    // Comparison visits every credential byte for equal-length credentials.
    let different = supplied.len() != expected.len()
        || supplied
            .bytes()
            .zip(expected.bytes())
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

async fn events(
    HttpState(app): HttpState<App>,
    headers: HeaderMap,
    Json(batch): Json<EventBatch>,
) -> ApiResult {
    authorize(&headers, &app.collector)?;
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
async fn snapshot(HttpState(app): HttpState<App>, headers: HeaderMap) -> ApiResult {
    authorize(&headers, &app.collector)?;
    operation(app, false, |e| Ok(serde_json::to_value(e.snapshot(now()))?)).await
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
    headers: HeaderMap,
    Json(input): Json<DecisionRequest>,
) -> ApiResult {
    authorize(&headers, &app.collector)?;
    if input.source_id.is_empty() || input.source_id.len() > 64 {
        return Err(error(StatusCode::BAD_REQUEST, "invalid source ID"));
    }
    operation(app, false, move |engine| {
        let time = now();
        let ip = input.ip.to_string();
        let before = engine.decision(&ip, time)?;
        if before.action == "deny" {
            return Ok(serde_json::to_value(before)?);
        }
        if let Some(kind) = input.kind {
            engine.ingest(
                EventBatch {
                    source_id: input.source_id,
                    events: vec![guard_core::Event {
                        ip: ip.clone(),
                        kind,
                        observed_at: time,
                    }],
                },
                time,
            )?;
        }
        Ok(serde_json::to_value(engine.decision(&ip, time)?)?)
    })
    .await
}
async fn status(HttpState(app): HttpState<App>, headers: HeaderMap) -> ApiResult {
    authorize(&headers, &app.admin)?;
    operation(app, false, |e| {let (candidates,blocks)=e.capacity();Ok(json!({"health":"ok","stats":e.stats(),"capacity":{"candidates":candidates,"blocks":blocks,"max_candidates":guard_core::MAX_CANDIDATES,"max_blocks":guard_core::MAX_BLOCKS,"max_batch":256,"max_body_bytes":4*1024*1024,"max_workers":1024,"max_requests":64}}))}).await
}
async fn candidates(HttpState(app): HttpState<App>, headers: HeaderMap) -> ApiResult {
    authorize(&headers, &app.admin)?;
    operation(app, false, |e| {
        Ok(serde_json::to_value(e.candidates(now()))?)
    })
    .await
}
async fn policy_get(HttpState(app): HttpState<App>, headers: HeaderMap) -> ApiResult {
    authorize(&headers, &app.admin)?;
    operation(app, false, |e| Ok(serde_json::to_value(e.policy())?)).await
}
async fn policy_put(
    HttpState(app): HttpState<App>,
    headers: HeaderMap,
    Json(policy): Json<Policy>,
) -> ApiResult {
    authorize(&headers, &app.admin)?;
    operation(app, true, move |e| {
        e.set_policy(policy)?;
        Ok(json!({"ok":true}))
    })
    .await
}
async fn blocks(HttpState(app): HttpState<App>, headers: HeaderMap) -> ApiResult {
    authorize(&headers, &app.admin)?;
    operation(app, false, |e| {
        Ok(serde_json::to_value(e.snapshot(now()).blocks)?)
    })
    .await
}
async fn block_add(
    HttpState(app): HttpState<App>,
    headers: HeaderMap,
    Json(block): Json<Block>,
) -> ApiResult {
    authorize(&headers, &app.admin)?;
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
async fn block_delete(
    HttpState(app): HttpState<App>,
    headers: HeaderMap,
    Json(input): Json<Network>,
) -> ApiResult {
    authorize(&headers, &app.admin)?;
    operation(app, true, move |e| {
        Ok(json!({"removed":e.remove_block(&input.network)?}))
    })
    .await
}
#[derive(Deserialize)]
struct Approval {
    ip: String,
}
async fn approve(
    HttpState(app): HttpState<App>,
    headers: HeaderMap,
    Json(input): Json<Approval>,
) -> ApiResult {
    authorize(&headers, &app.admin)?;
    operation(app, true, move |e| {
        Ok(serde_json::to_value(e.approve(&input.ip, now())?)?)
    })
    .await
}
fn router(app: App) -> Router {
    let credentials = app.clone();
    let requests = Arc::new(tokio::sync::Semaphore::new(64));
    Router::new()
        .route("/", get(|| async { Html(include_str!("dashboard.html")) }))
        .route("/healthz", get(|| async { Json(json!({"status":"ok"})) }))
        .route("/v1/decision", post(decision))
        .route("/v1/events", post(events))
        .route("/v1/snapshot", get(snapshot))
        .route("/v1/status", get(status))
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
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    let collector = std::env::var("HANGANG_GUARD_COLLECTOR_TOKEN")?;
    let admin = std::env::var("HANGANG_GUARD_ADMIN_TOKEN")?;
    anyhow::ensure!(
        collector.len() >= 16 && admin.len() >= 16 && collector != admin,
        "tokens must be distinct and at least 16 bytes"
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
    let app = App {
        inner: Arc::new(Mutex::new(Inner { engine })),
        db: Arc::new(Mutex::new(db)),
        workers: Arc::new(tokio::sync::Semaphore::new(1024)),
        collector: Arc::new(collector),
        admin: Arc::new(admin),
    };
    let (stop_tx, mut stop_rx) = tokio::sync::watch::channel(false);
    let checkpoint_app = app.clone();
    let worker = tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(5));
        loop {
            tokio::select! {_ = interval.tick()=>{let a=checkpoint_app.clone();if let Err(e)=checkpoint(a).await {eprintln!("checkpoint failed: {e}");}}, _=stop_rx.changed()=>break}
        }
    });
    let listener = tokio::net::TcpListener::bind(&args.listen).await?;
    eprintln!("hangang-guard listening on {}", listener.local_addr()?);
    let serving = axum::serve(listener, router(app.clone()))
        .with_graceful_shutdown(shutdown())
        .await;
    let _ = stop_tx.send(true);
    let _ = worker.await;
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
    fn app() -> App {
        let db = Connection::open_in_memory().unwrap();
        db.execute_batch("CREATE TABLE checkpoint(id INTEGER PRIMARY KEY,body TEXT NOT NULL)")
            .unwrap();
        App {
            inner: Arc::new(Mutex::new(Inner {
                engine: Engine::new(Policy::default()).unwrap(),
            })),
            db: Arc::new(Mutex::new(db)),
            workers: Arc::new(tokio::sync::Semaphore::new(1024)),
            collector: Arc::new("collector-test-token".into()),
            admin: Arc::new("admin-test-token".into()),
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
