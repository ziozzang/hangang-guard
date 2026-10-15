//! Linux parent-owned listeners and signed, readiness-gated worker replacement.
use anyhow::{Context, Result, bail, ensure};
use guard_update::{
    preflight,
    update::{StagedUpdate, TrustKey, UpToDate, UpdateManager},
};
use std::{
    ffi::OsString,
    fs,
    io::Write,
    net::{SocketAddr, TcpListener},
    os::{
        fd::{AsRawFd, FromRawFd, RawFd},
        unix::{fs::PermissionsExt, net::UnixStream},
    },
    path::{Path, PathBuf},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::{
    io::AsyncReadExt,
    process::{Child, Command},
    signal::unix::{SignalKind, signal},
};

pub struct Options {
    pub http: SocketAddr,
    pub decision: Option<SocketAddr>,
    pub grpc: Option<SocketAddr>,
    pub readiness: Option<SocketAddr>,
    pub database: PathBuf,
    pub worker_arguments: Vec<OsString>,
    pub update: Option<UpdateOptions>,
    pub grace: Duration,
}
#[derive(Clone)]
pub struct UpdateOptions {
    pub manifest_url: Option<String>,
    pub github: bool,
    pub additional_ca: Option<PathBuf>,
    pub public_key: String,
    pub interval: Duration,
    pub status_path: PathBuf,
}
fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
fn status(
    options: &UpdateOptions,
    current: &str,
    phase: &str,
    version: Option<&str>,
    detail: &str,
) -> Result<()> {
    let parent = options
        .status_path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let mut file = tempfile::NamedTempFile::new_in(parent)?;
    file.as_file()
        .set_permissions(fs::Permissions::from_mode(0o600))?;
    serde_json::to_writer(
        &mut file,
        &serde_json::json!({"enabled":true,"current_version":current,"phase":phase,"version":version,"detail":detail,"last_check_unix":now()}),
    )?;
    file.write_all(b"\n")?;
    file.as_file().sync_all()?;
    file.persist(&options.status_path).map_err(|e| e.error)?;
    fs::File::open(parent)?.sync_all()?;
    Ok(())
}
fn bind(address: SocketAddr) -> Result<TcpListener> {
    let listener = TcpListener::bind(address).context("bind supervisor listener")?;
    listener.set_nonblocking(true)?;
    Ok(listener)
}
fn descriptor(name: &str) -> Result<RawFd> {
    ensure!(
        std::env::var("HANGANG_GUARD_WORKER").as_deref() == Ok("1"),
        "inherited descriptor requires supervised worker"
    );
    let fd: RawFd = std::env::var(name)
        .context("missing inherited descriptor")?
        .parse()
        .context("invalid inherited descriptor")?;
    ensure!(
        fd >= 3,
        "inherited descriptor cannot be standard input/output"
    );
    Ok(fd)
}
/// Transfer one inherited listener into Tokio, rejecting mismatched endpoints.
pub fn inherited_listener(name: &str, expected: SocketAddr) -> Result<tokio::net::TcpListener> {
    let fd = descriptor(name)?;
    // The dedicated serving child owns this descriptor after successful exec.
    let listener = unsafe { TcpListener::from_raw_fd(fd) };
    ensure!(
        listener.local_addr()? == expected,
        "inherited listener endpoint mismatch"
    );
    let mut accepting: libc::c_int = 0;
    let mut length = std::mem::size_of_val(&accepting) as libc::socklen_t;
    ensure!(
        unsafe {
            libc::getsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_ACCEPTCONN,
                (&mut accepting as *mut libc::c_int).cast(),
                &mut length,
            )
        } == 0
            && accepting == 1,
        "inherited socket is not a listener"
    );
    ensure!(
        unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) } == 0,
        "protect inherited descriptor"
    );
    listener.set_nonblocking(true)?;
    tokio::net::TcpListener::from_std(listener).context("adopt inherited listener")
}
pub fn notify_ready() -> Result<()> {
    let fd = descriptor("HANGANG_GUARD_READY_FD")?;
    let mut channel = unsafe { UnixStream::from_raw_fd(fd) };
    channel
        .write_all(b"R")
        .context("notify supervisor readiness")
}
async fn start(
    executable: &Path,
    options: &Options,
    http: &TcpListener,
    decision: Option<&TcpListener>,
    grpc: Option<&TcpListener>,
    readiness: Option<&TcpListener>,
) -> Result<Child> {
    let (read, write) = UnixStream::pair()?;
    read.set_nonblocking(true)?;
    let mut ready = tokio::net::UnixStream::from_std(read)?;
    let mut command = Command::new(executable);
    command
        .args(&options.worker_arguments)
        .arg("--serve-child")
        .env("HANGANG_GUARD_WORKER", "1")
        .env("HANGANG_GUARD_HTTP_FD", http.as_raw_fd().to_string())
        .env("HANGANG_GUARD_READY_FD", write.as_raw_fd().to_string())
        .kill_on_drop(true);
    if let Some(listener) = decision {
        command.env(
            "HANGANG_GUARD_DECISION_FD",
            listener.as_raw_fd().to_string(),
        );
    } else {
        command.env_remove("HANGANG_GUARD_DECISION_FD");
    }
    if let Some(listener) = grpc {
        command.env("HANGANG_GUARD_GRPC_FD", listener.as_raw_fd().to_string());
    } else {
        command.env_remove("HANGANG_GUARD_GRPC_FD");
    }
    if let Some(listener) = readiness {
        command.env(
            "HANGANG_GUARD_READINESS_FD",
            listener.as_raw_fd().to_string(),
        );
    } else {
        command.env_remove("HANGANG_GUARD_READINESS_FD");
    }
    if let Some(update) = &options.update {
        command
            .env("HANGANG_GUARD_UPDATE_STATUS", &update.status_path)
            .env(
                "HANGANG_GUARD_UPDATE_REQUEST",
                update.status_path.with_extension("request"),
            );
    } else {
        command
            .env_remove("HANGANG_GUARD_UPDATE_STATUS")
            .env_remove("HANGANG_GUARD_UPDATE_REQUEST");
    }
    let descriptors = [
        Some(http.as_raw_fd()),
        decision.map(AsRawFd::as_raw_fd),
        grpc.map(AsRawFd::as_raw_fd),
        readiness.map(AsRawFd::as_raw_fd),
        Some(write.as_raw_fd()),
    ];
    let parent_pid = unsafe { libc::getpid() };
    unsafe {
        command.pre_exec(move || {
            if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            if libc::getppid() != parent_pid {
                return Err(std::io::Error::other("supervisor exited"));
            }
            for fd in descriptors.into_iter().flatten() {
                let flags = libc::fcntl(fd, libc::F_GETFD);
                if flags < 0 || libc::fcntl(fd, libc::F_SETFD, flags & !libc::FD_CLOEXEC) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
            }
            Ok(())
        });
    }
    let mut child = command.spawn().context("spawn serving worker")?;
    drop(write);
    let result = tokio::time::timeout(Duration::from_secs(15), async {
        let mut byte = [0u8];
        tokio::select! {
            result = ready.read_exact(&mut byte) => { result?; ensure!(byte == *b"R", "invalid worker readiness"); Ok(()) },
            result = child.wait() => { let _ = result?; bail!("worker exited before readiness") }
        }
    }).await;
    match result {
        Ok(Ok(())) => Ok(child),
        _ => {
            let _ = child.kill().await;
            let _ = child.wait().await;
            bail!("worker failed readiness gate")
        }
    }
}
async fn stop(child: &mut Child, grace: Duration) -> Result<()> {
    if let Some(pid) = child.id()
        && unsafe { libc::kill(pid as libc::pid_t, libc::SIGTERM) } != 0
    {
        let error = std::io::Error::last_os_error();
        if error.raw_os_error() != Some(libc::ESRCH) {
            return Err(error.into());
        }
    }
    match tokio::time::timeout(grace, child.wait()).await {
        Ok(result) => {
            ensure!(result?.success(), "worker did not exit cleanly");
            Ok(())
        }
        Err(_) => {
            let _ = child.kill().await;
            let _ = child.wait().await;
            bail!("worker checkpoint shutdown timed out")
        }
    }
}
async fn stage(
    options: UpdateOptions,
    version: semver::Version,
    executable: PathBuf,
    arguments: Vec<OsString>,
) -> Result<StagedUpdate> {
    let key = TrustKey::from_base64(&options.public_key)?;
    let target = env!("GUARD_TARGET");
    ensure!(
        matches!(
            target,
            "x86_64-unknown-linux-gnu" | "aarch64-unknown-linux-gnu" | "x86_64-unknown-linux-musl"
        ),
        "signed updates are not qualified for this target"
    );
    let ca = options
        .additional_ca
        .as_deref()
        .map(|path| -> Result<_> {
            Ok(reqwest::Certificate::from_pem(&crate::read_bounded(
                path,
                128 * 1024,
            )?)?)
        })
        .transpose()?;
    let manager = if options.github {
        UpdateManager::new_github(key, version, target)?
    } else {
        UpdateManager::new_with_ca(key, version, target, ca)?
    };
    let directory = executable.parent().context("executable parent")?;
    let staged = if options.github {
        manager.stage_github(directory).await?
    } else {
        manager
            .stage(
                options
                    .manifest_url
                    .as_deref()
                    .context("missing manifest source")?,
                directory,
            )
            .await?
    };
    preflight::validate_candidate(staged.path(), staged.version(), &arguments).await?;
    Ok(staged)
}
pub async fn run(options: Options) -> Result<()> {
    let _ = &options.database; // Workers alone own/checkpoint the policy database.
    ensure!(
        !options.grace.is_zero() && options.grace <= Duration::from_secs(15),
        "shutdown grace must be 1..15 seconds"
    );
    let executable = std::env::current_exe()?.canonicalize()?;
    let http = bind(options.http)?;
    let decision = options.decision.map(bind).transpose()?;
    let grpc = options.grpc.map(bind).transpose()?;
    let readiness = options.readiness.map(bind).transpose()?;
    let mut current = semver::Version::parse(env!("CARGO_PKG_VERSION"))?;
    if let Some(update) = &options.update {
        ensure!(
            update.interval >= Duration::from_secs(10),
            "update interval must be at least 10 seconds"
        );
        ensure!(
            update.github != update.manifest_url.is_some(),
            "select exactly one update source"
        );
        TrustKey::from_base64(&update.public_key)?;
        status(
            update,
            &current.to_string(),
            "idle",
            None,
            "supervisor starting",
        )?;
    }
    let mut child = start(
        &executable,
        &options,
        &http,
        decision.as_ref(),
        grpc.as_ref(),
        readiness.as_ref(),
    )
    .await?;
    let mut term = signal(SignalKind::terminate())?;
    let mut interrupt = signal(SignalKind::interrupt())?;
    let mut hup = signal(SignalKind::hangup())?;
    let mut tick = tokio::time::interval(Duration::from_secs(1));
    let mut next = tokio::time::Instant::now();
    let mut pending: Option<tokio::task::JoinHandle<Result<StagedUpdate>>> = None;
    loop {
        tokio::select! {
            _ = term.recv() => break,
            _ = interrupt.recv() => break,
            result = child.wait() => { result?; if let Some(task) = pending.take() { task.abort(); let _ = task.await; } bail!("serving worker exited unexpectedly"); },
            _ = hup.recv() => {
                stop(&mut child, options.grace).await?;
                child = start(&executable, &options, &http, decision.as_ref(), grpc.as_ref(), readiness.as_ref()).await?;
            },
            _ = tick.tick() => {
                if let Some(update) = &options.update {
                    let marker = update.status_path.with_extension("request");
                    let requested = match fs::symlink_metadata(&marker) {
                        Ok(metadata) => { ensure!(metadata.is_file() && !metadata.file_type().is_symlink(), "invalid update request marker"); fs::remove_file(&marker)?; true },
                        Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
                        Err(error) => return Err(error.into()),
                    };
                    if pending.is_none() && (requested || tokio::time::Instant::now() >= next) {
                        status(update, &current.to_string(), "checking", None, "verifying signed release")?;
                        pending = Some(tokio::spawn(stage(update.clone(), current.clone(), executable.clone(), options.worker_arguments.clone())));
                        next = tokio::time::Instant::now() + update.interval;
                    }
                }
            },
            joined = async { pending.as_mut().expect("guarded staging task").await }, if pending.is_some() => {
                pending = None;
                let update = options.update.as_ref().expect("update task requires options");
                match joined {
                    Ok(Ok(staged)) => {
                        let version = staged.version().clone();
                        status(update, &current.to_string(), "activating", Some(&version.to_string()), "candidate verified")?;
                        let activated = match UpdateManager::activate(staged, &executable) {
                            Ok(value) => value,
                            Err(_) => { status(update, &current.to_string(), "rejected", None, "atomic activation failed")?; continue; }
                        };
                        if let Err(error) = stop(&mut child, options.grace).await {
                            UpdateManager::rollback(activated)?;
                            return Err(error);
                        }
                        match start(&executable, &options, &http, decision.as_ref(), grpc.as_ref(), readiness.as_ref()).await {
                            Ok(worker) => { child = worker; current = version; activated.discard_rollback()?; status(update, &current.to_string(), "active", Some(&current.to_string()), "candidate ready")?; },
                            Err(_) => { UpdateManager::rollback(activated)?; child = start(&executable, &options, &http, decision.as_ref(), grpc.as_ref(), readiness.as_ref()).await.context("restore prior serving worker")?; status(update, &current.to_string(), "rolled_back", None, "candidate readiness failed; prior binary restored")?; }
                        }
                    },
                    Ok(Err(error)) if error.downcast_ref::<UpToDate>().is_some() => { status(update, &current.to_string(), "up_to_date", Some(&current.to_string()), "signed release is already running")?; },
                    _ => { status(update, &current.to_string(), "rejected", None, "release verification or configuration preflight failed")?; }
                }
            }
        }
    }
    if let Some(task) = pending.take() {
        task.abort();
        let _ = task.await;
    }
    let result = stop(&mut child, options.grace).await;
    if let Some(update) = &options.update {
        let _ = status(
            update,
            &current.to_string(),
            "stopped",
            None,
            "supervisor stopped",
        );
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn update_status_is_atomic_private_and_has_no_source_credentials() {
        let directory = tempfile::tempdir().unwrap();
        let options = UpdateOptions {
            manifest_url: Some("https://example.test/secret-token".into()),
            github: false,
            additional_ca: None,
            public_key: "private-test-placeholder".into(),
            interval: Duration::from_secs(300),
            status_path: directory.path().join("update.json"),
        };
        status(
            &options,
            "0.3.0",
            "checking",
            None,
            "verifying signed release",
        )
        .unwrap();
        status(
            &options,
            "0.3.0",
            "up_to_date",
            Some("0.3.0"),
            "signed release is already running",
        )
        .unwrap();
        let bytes = fs::read(&options.status_path).unwrap();
        let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(value["phase"], "up_to_date");
        assert_eq!(value["current_version"], "0.3.0");
        assert!(!String::from_utf8(bytes).unwrap().contains("secret-token"));
        assert_eq!(
            fs::metadata(&options.status_path)
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        assert_eq!(fs::read_dir(directory.path()).unwrap().count(), 1);
    }
}
