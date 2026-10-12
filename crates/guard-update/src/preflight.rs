//! Bounded executable probes. These run only after signature and artifact validation.
use anyhow::{Context, Result, ensure};
use std::{ffi::OsString, path::Path, time::Duration};
use tokio::{io::AsyncReadExt, process::Command};

/// Require the candidate's own version report to match the signed manifest,
/// then validate configuration without opening listeners or modifying policy.
pub async fn validate_candidate(
    executable: &Path,
    version: &semver::Version,
    configuration_arguments: &[OsString],
) -> Result<()> {
    let reported = bounded_probe(executable, &[OsString::from("--version")]).await?;
    ensure!(
        (reported.trim() == format!("sumunjang {version}")
            || reported.trim() == format!("hangang-guard {version}")),
        "candidate version differs from signed manifest"
    );
    let mut arguments = configuration_arguments.to_vec();
    arguments.push(OsString::from("--check"));
    bounded_probe(executable, &arguments)
        .await
        .context("candidate configuration preflight")?;
    Ok(())
}

pub async fn bounded_probe(executable: &Path, arguments: &[OsString]) -> Result<String> {
    let mut child = Command::new(executable)
        .args(arguments)
        .env_remove("HANGANG_GUARD_WORKER")
        .env_remove("HANGANG_GUARD_READY_FD")
        .env_remove("HANGANG_GUARD_HTTP_FD")
        .env_remove("HANGANG_GUARD_DECISION_FD")
        .env_remove("HANGANG_GUARD_UPDATE_STATUS")
        .env_remove("HANGANG_GUARD_UPDATE_REQUEST")
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .context("spawn candidate preflight")?;
    let stdout = child.stdout.take().context("candidate stdout")?;
    let result = tokio::time::timeout(Duration::from_secs(30), async {
        let mut bytes = Vec::new();
        stdout.take(64 * 1024 + 1).read_to_end(&mut bytes).await?;
        ensure!(bytes.len() <= 64 * 1024, "candidate output too large");
        ensure!(child.wait().await?.success(), "candidate preflight failed");
        Ok::<_, anyhow::Error>(String::from_utf8(bytes)?)
    })
    .await
    .context("candidate preflight timeout")?;
    // kill_on_drop closes any candidate still running after errors or cancellation.
    result
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::{fs, os::unix::fs::PermissionsExt};
    fn executable(dir: &Path, body: &str) -> std::path::PathBuf {
        let path = dir.join("candidate");
        fs::write(&path, format!("#!/bin/sh\n{body}\n")).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        path
    }
    #[tokio::test]
    async fn fake_candidate_requires_matching_version_and_successful_check() {
        let dir = tempfile::tempdir().unwrap();
        let path = executable(
            dir.path(),
            "if [ \"$1\" = --version ]; then echo 'hangang-guard 2.0.0'; else exit 0; fi",
        );
        validate_candidate(&path, &semver::Version::new(2, 0, 0), &[])
            .await
            .unwrap();
        assert!(
            validate_candidate(&path, &semver::Version::new(3, 0, 0), &[])
                .await
                .is_err()
        );
        let path = executable(
            dir.path(),
            "if [ \"$1\" = --version ]; then echo 'hangang-guard 2.0.0'; else exit 1; fi",
        );
        assert!(
            validate_candidate(&path, &semver::Version::new(2, 0, 0), &[])
                .await
                .is_err()
        );
    }
    #[tokio::test]
    async fn rejects_excess_output_and_unsuccessful_probe() {
        let dir = tempfile::tempdir().unwrap();
        let path = executable(dir.path(), "head -c 70000 /dev/zero");
        assert!(bounded_probe(&path, &[]).await.is_err());
        let path = executable(dir.path(), "exit 9");
        assert!(bounded_probe(&path, &[]).await.is_err());
    }
}
