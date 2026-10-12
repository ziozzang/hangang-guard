use base64::{Engine as _, engine::general_purpose::STANDARD};
use ed25519_dalek::SigningKey;
use guard_update::update::{
    ReleaseManifest, TrustKey, UpToDate, UpdateManager, sign_release_manifest,
};
use semver::Version;
use sha2::{Digest, Sha256};
use std::{collections::HashMap, path::Path, sync::Arc};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};

async fn fixture(
    bodies: HashMap<&'static str, Vec<u8>>,
) -> anyhow::Result<(String, tokio::task::JoinHandle<()>)> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let bodies = Arc::new(bodies);
    let task = tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                break;
            };
            let bodies = bodies.clone();
            tokio::spawn(async move {
                let mut request = vec![0; 4096];
                let Ok(read) = stream.read(&mut request).await else {
                    return;
                };
                let line = String::from_utf8_lossy(&request[..read]);
                let path = line.split_whitespace().nth(1).unwrap_or("/");
                let (status, body) = match bodies.get(path) {
                    Some(body) => ("200 OK", body.as_slice()),
                    None => ("404 Not Found", b"missing".as_slice()),
                };
                let response = format!(
                    "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                let _ = stream.write_all(response.as_bytes()).await;
                let _ = stream.write_all(body).await;
            });
        }
    });
    Ok((format!("http://{address}"), task))
}

async fn redirect_fixture(
    location: String,
) -> anyhow::Result<(String, tokio::task::JoinHandle<()>)> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let task = tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                break;
            };
            let location = location.clone();
            tokio::spawn(async move {
                let mut request = [0; 1024];
                let _ = stream.read(&mut request).await;
                let response = format!(
                    "HTTP/1.1 302 Found\r\nLocation: {location}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                );
                let _ = stream.write_all(response.as_bytes()).await;
            });
        }
    });
    Ok((format!("http://{address}"), task))
}

fn signed_manifest(
    signing_key: &SigningKey,
    version: &str,
    target: &str,
    artifact_url: String,
    artifact: &[u8],
) -> Vec<u8> {
    let payload = ReleaseManifest {
        version: Version::parse(version).unwrap(),
        target: target.to_owned(),
        artifact_url,
        sha256: format!("{:x}", Sha256::digest(artifact)),
        size: artifact.len() as u64,
    };
    let payload = serde_json::to_vec(&payload).unwrap();
    sign_release_manifest(&payload, signing_key).unwrap()
}

fn manager(signing_key: &SigningKey) -> UpdateManager {
    let trust =
        TrustKey::from_base64(&STANDARD.encode(signing_key.verifying_key().to_bytes())).unwrap();
    UpdateManager::loopback_http_for_tests(
        trust,
        Version::parse("1.0.0").unwrap(),
        "x86_64-unknown-linux-gnu",
    )
    .unwrap()
}

#[tokio::test]
async fn stages_signed_artifact_then_activates_and_rolls_back_fake_binary() -> anyhow::Result<()> {
    let signing_key = SigningKey::from_bytes(&[7; 32]);
    let artifact = b"#!/bin/sh\necho hangang 1.1.0\n".to_vec();
    let (base, fixture_task) = fixture(HashMap::from([("/artifact", artifact.clone())])).await?;
    let manifest = signed_manifest(
        &signing_key,
        "1.1.0",
        "x86_64-unknown-linux-gnu",
        format!("{base}/artifact"),
        &artifact,
    );
    let temp = tempfile::tempdir()?;
    let (base, manifest_task) = fixture(HashMap::from([("/manifest", manifest)])).await?;

    let staged = manager(&signing_key)
        .stage(&format!("{base}/manifest"), temp.path())
        .await?;
    assert_eq!(staged.version(), &Version::parse("1.1.0")?);
    assert_eq!(std::fs::read(staged.path())?, artifact);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(staged.path())?.permissions().mode() & 0o777,
            0o700
        );
    }

    let installed = temp.path().join("hangang-fake");
    std::fs::write(&installed, b"old binary")?;
    let activated = UpdateManager::activate(staged, &installed)?;
    assert_eq!(std::fs::read(&installed)?, artifact);
    assert_eq!(std::fs::read(activated.rollback_path())?, b"old binary");

    UpdateManager::rollback(activated)?;
    assert_eq!(std::fs::read(&installed)?, b"old binary");
    fixture_task.abort();
    manifest_task.abort();
    Ok(())
}

#[tokio::test]
async fn rejects_tampered_signed_payload_without_staging_a_file() -> anyhow::Result<()> {
    let signing_key = SigningKey::from_bytes(&[9; 32]);
    let artifact = b"candidate";
    let (artifact_base, artifact_task) =
        fixture(HashMap::from([("/artifact", artifact.to_vec())])).await?;
    let signed = signed_manifest(
        &signing_key,
        "1.1.0",
        "x86_64-unknown-linux-gnu",
        format!("{artifact_base}/artifact"),
        artifact,
    );
    let mut envelope: serde_json::Value = serde_json::from_slice(&signed)?;
    let payload = envelope["payload"].as_str().unwrap();
    let mut decoded = STANDARD.decode(payload)?;
    let needle = decoded.iter().position(|byte| *byte == b'1').unwrap();
    decoded[needle] = b'2';
    envelope["payload"] = STANDARD.encode(decoded).into();
    let tampered = serde_json::to_vec(&envelope)?;
    let (base, manifest_task) = fixture(HashMap::from([("/manifest", tampered)])).await?;
    let temp = tempfile::tempdir()?;

    let error = manager(&signing_key)
        .stage(&format!("{base}/manifest"), temp.path())
        .await
        .unwrap_err();
    assert!(error.to_string().contains("signature"));
    assert!(directory_is_empty(temp.path())?);
    artifact_task.abort();
    manifest_task.abort();
    Ok(())
}

#[tokio::test]
async fn rejects_downgrade_wrong_target_and_artifact_mismatch() -> anyhow::Result<()> {
    let signing_key = SigningKey::from_bytes(&[11; 32]);
    let artifact = b"candidate".to_vec();
    let temp = tempfile::tempdir()?;

    for (version, target, served_artifact, expected) in [
        (
            "0.9.0",
            "x86_64-unknown-linux-gnu",
            artifact.clone(),
            "downgrade",
        ),
        (
            "1.1.0",
            "aarch64-unknown-linux-gnu",
            artifact.clone(),
            "target",
        ),
        (
            "1.1.0",
            "x86_64-unknown-linux-gnu",
            b"corrupted".to_vec(),
            "digest",
        ),
    ] {
        let (artifact_base, artifact_task) =
            fixture(HashMap::from([("/artifact", served_artifact)])).await?;
        let manifest = signed_manifest(
            &signing_key,
            version,
            target,
            format!("{artifact_base}/artifact"),
            &artifact,
        );
        let (base, manifest_task) = fixture(HashMap::from([("/manifest", manifest)])).await?;
        let error = manager(&signing_key)
            .stage(&format!("{base}/manifest"), temp.path())
            .await
            .unwrap_err();
        assert!(error.to_string().contains(expected), "{error:#}");
        assert!(directory_is_empty(temp.path())?);
        artifact_task.abort();
        manifest_task.abort();
    }
    Ok(())
}

#[tokio::test]
async fn equal_signed_version_is_a_typed_healthy_noop() -> anyhow::Result<()> {
    let signing_key = SigningKey::from_bytes(&[12; 32]);
    let artifact = b"already running";
    let manifest = signed_manifest(
        &signing_key,
        "1.0.0",
        "x86_64-unknown-linux-gnu",
        "http://127.0.0.1:9/artifact".to_owned(),
        artifact,
    );
    let (base, server) = fixture(HashMap::from([("/manifest", manifest)])).await?;
    let temp = tempfile::tempdir()?;

    let error = manager(&signing_key)
        .stage(&format!("{base}/manifest"), temp.path())
        .await
        .unwrap_err();
    let up_to_date = error.downcast_ref::<UpToDate>().expect("typed no-op error");
    assert_eq!(up_to_date.version(), &Version::parse("1.0.0")?);
    assert!(directory_is_empty(temp.path())?);
    server.abort();
    Ok(())
}

#[tokio::test]
async fn rejects_manifest_over_64_kib_before_artifact_download() -> anyhow::Result<()> {
    let signing_key = SigningKey::from_bytes(&[13; 32]);
    let oversized = vec![b'x'; 64 * 1024 + 1];
    let (base, server) = fixture(HashMap::from([("/manifest", oversized)])).await?;
    let temp = tempfile::tempdir()?;

    let error = manager(&signing_key)
        .stage(&format!("{base}/manifest"), temp.path())
        .await
        .unwrap_err();
    assert!(error.to_string().contains("64 KiB"), "{error:#}");
    assert!(directory_is_empty(temp.path())?);
    server.abort();
    Ok(())
}

#[tokio::test]
async fn production_requires_https_and_redirects_cannot_change_origin() -> anyhow::Result<()> {
    let signing_key = SigningKey::from_bytes(&[15; 32]);
    let trust = TrustKey::from_base64(&STANDARD.encode(signing_key.verifying_key().to_bytes()))?;
    let production =
        UpdateManager::new(trust, Version::parse("1.0.0")?, "x86_64-unknown-linux-gnu")?;
    let temp = tempfile::tempdir()?;
    let error = production
        .stage("http://127.0.0.1:9/manifest", temp.path())
        .await
        .unwrap_err();
    assert!(error.to_string().contains("manifest URL"));

    let (redirect_target, target_task) =
        fixture(HashMap::from([("/manifest", b"{}".to_vec())])).await?;
    let (base, redirect_task) = redirect_fixture(format!("{redirect_target}/manifest")).await?;
    let error = manager(&signing_key)
        .stage(&format!("{base}/manifest"), temp.path())
        .await
        .unwrap_err();
    assert!(format!("{error:#}").contains("cross-origin"), "{error:#}");
    assert!(directory_is_empty(temp.path())?);
    target_task.abort();
    redirect_task.abort();
    Ok(())
}

fn directory_is_empty(path: &Path) -> anyhow::Result<bool> {
    Ok(std::fs::read_dir(path)?.next().is_none())
}
