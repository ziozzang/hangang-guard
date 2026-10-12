//! Bounded, persistent-connection load generator; no production traffic by default.
use anyhow::{Context, Result, ensure};
use clap::{Parser, ValueEnum};
use std::{
    net::IpAddr,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader},
    net::TcpStream,
};

#[derive(Clone, Copy, ValueEnum)]
enum Protocol {
    Http,
    Tcp,
}
#[derive(Parser)]
struct Args {
    #[arg(long, default_value = "127.0.0.1:9081")]
    address: std::net::SocketAddr,
    #[arg(long, value_enum, default_value = "tcp")]
    protocol: Protocol,
    #[arg(long, default_value_t = 64)]
    connections: usize,
    #[arg(long, default_value_t = 16)]
    pipeline: usize,
    #[arg(long, default_value_t = 10)]
    seconds: u64,
    #[arg(long, default_value_t = 2)]
    warmup: u64,
    #[arg(long, default_value = "HANGANG_GUARD_COLLECTOR_TOKEN")]
    token_env: String,
    #[arg(long, default_value = "192.0.2.1")]
    ip: IpAddr,
    /// Cycle low address bits to test varied IP lookups (one means a single IP).
    #[arg(long, default_value_t = 1)]
    ip_space: u32,
    #[arg(long, default_value_t = 8)]
    threads: usize,
}
#[derive(Default, Debug)]
struct Stats {
    queries: u64,
    denied: u64,
    capped: u64,
    hist: Vec<u64>,
    elapsed: f64,
}
fn percentile(hist: &[u64], count: u64, fraction: f64) -> f64 {
    let target = (count as f64 * fraction).ceil() as u64;
    let mut sum = 0;
    for (i, n) in hist.iter().enumerate() {
        sum += n;
        if sum >= target {
            return (i + 1) as f64 / 100.0;
        }
    }
    100.01
}
fn address_ip(base: IpAddr, id: u32, space: u32) -> IpAddr {
    match base {
        IpAddr::V4(ip) => std::net::Ipv4Addr::from(u32::from(ip).wrapping_add(id % space)).into(),
        IpAddr::V6(ip) => {
            std::net::Ipv6Addr::from(u128::from(ip).wrapping_add(u128::from(id % space))).into()
        }
    }
}
async fn run(args: Arc<Args>, token: Arc<String>, worker: usize) -> Result<Stats> {
    let mut stream = TcpStream::connect(args.address).await?;
    stream.set_nodelay(true)?;
    if matches!(args.protocol, Protocol::Tcp) {
        let mut auth = Vec::with_capacity(token.len() + 6);
        auth.extend_from_slice(b"HGD1");
        auth.extend_from_slice(&(token.len() as u16).to_be_bytes());
        auth.extend_from_slice(token.as_bytes());
        stream.write_all(&auth).await?;
        let mut ack = [0u8; 4];
        stream.read_exact(&mut ack).await?;
        ensure!(&ack == b"HGA1", "authentication failed");
    }
    let mut stream = BufReader::new(stream);
    let start = Instant::now();
    let measuring = start + Duration::from_secs(args.warmup);
    let end = measuring + Duration::from_secs(args.seconds);
    let mut stats = Stats {
        hist: vec![0; 10001],
        ..Default::default()
    };
    let mut id = (worker as u32).wrapping_mul(100_000);
    let mut sent = Vec::with_capacity(args.pipeline);
    let mut buffer = Vec::with_capacity(args.pipeline * 256);
    let mut header = Vec::with_capacity(256);
    let mut body = Vec::with_capacity(1024);
    while Instant::now() < end {
        buffer.clear();
        sent.clear();
        for _ in 0..args.pipeline {
            let ip = address_ip(args.ip, id, args.ip_space);
            match args.protocol {
                Protocol::Tcp => {
                    let mut frame = [0u8; 24];
                    frame[0] = 1;
                    frame[4..8].copy_from_slice(&id.to_be_bytes());
                    match ip {
                        IpAddr::V4(ip) => {
                            frame[1] = 4;
                            frame[8..12].copy_from_slice(&ip.octets());
                        }
                        IpAddr::V6(ip) => {
                            frame[1] = 6;
                            frame[8..24].copy_from_slice(&ip.octets());
                        }
                    }
                    buffer.extend_from_slice(&frame);
                }
                Protocol::Http => {
                    let json = format!("{{\"source_id\":\"load\",\"ip\":\"{ip}\"}}");
                    let req = format!(
                        "POST /v1/decision HTTP/1.1\r\nHost: {}\r\nAuthorization: Bearer {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                        args.address,
                        token,
                        json.len(),
                        json
                    );
                    buffer.extend_from_slice(req.as_bytes());
                }
            }
            sent.push((id, Instant::now()));
            id = id.wrapping_add(1);
        }
        stream.get_mut().write_all(&buffer).await?;
        for (id, sent_at) in &sent {
            let denied = match args.protocol {
                Protocol::Tcp => {
                    let mut frame = [0u8; 24];
                    stream.read_exact(&mut frame).await?;
                    ensure!(
                        frame[0] == 1
                            && frame[1] <= 1
                            && frame[2] <= 1
                            && frame[3] == 0
                            && frame[20..24] == [0; 4]
                            && u32::from_be_bytes(frame[4..8].try_into()?) == *id,
                        "invalid TCP response"
                    );
                    frame[1] == 1
                }
                Protocol::Http => {
                    header.clear();
                    ensure!(stream.read_until(b'\n', &mut header).await? > 0, "HTTP EOF");
                    ensure!(
                        header.starts_with(b"HTTP/1.1 200 "),
                        "HTTP error: {}",
                        String::from_utf8_lossy(&header)
                    );
                    let mut length = None;
                    loop {
                        header.clear();
                        ensure!(
                            stream.read_until(b'\n', &mut header).await? > 0,
                            "HTTP header EOF"
                        );
                        ensure!(header.len() < 8192, "HTTP header too long");
                        if header == b"\r\n" {
                            break;
                        }
                        let line = std::str::from_utf8(&header)?;
                        if let Some((name, value)) = line.split_once(':')
                            && name.eq_ignore_ascii_case("content-length")
                        {
                            length = Some(value.trim().parse::<usize>()?);
                        }
                    }
                    let length = length.context("missing content length")?;
                    ensure!(length <= 4096, "response too large");
                    body.resize(length, 0);
                    stream.read_exact(&mut body).await?;
                    let deny = body.windows(15).any(|s| s == b"\"action\":\"deny\"");
                    ensure!(
                        deny || body.windows(16).any(|s| s == b"\"action\":\"allow\""),
                        "invalid HTTP decision"
                    );
                    deny
                }
            };
            if *sent_at >= measuring {
                stats.queries += 1;
                stats.denied += u64::from(denied);
                let micros = sent_at.elapsed().as_micros();
                stats.capped += u64::from(micros >= 100_000);
                let bucket = (micros / 10).min(10000) as usize;
                stats.hist[bucket] += 1;
            }
        }
    }
    stats.elapsed = Instant::now().duration_since(measuring).as_secs_f64();
    Ok(stats)
}
fn main() -> Result<()> {
    let args = Args::parse();
    ensure!(
        args.address.ip().is_loopback(),
        "load generator requires loopback"
    );
    ensure!(
        (1..=1024).contains(&args.connections)
            && (1..=256).contains(&args.pipeline)
            && args.seconds > 0
            && args.seconds <= 300
            && args.warmup <= 60
            && args.ip_space > 0
            && (1..=32).contains(&args.threads),
        "invalid load limits"
    );
    let token = std::env::var(&args.token_env).context("collector token unavailable")?;
    ensure!(
        (16..=4096).contains(&token.len()) && token.bytes().all(|b| b.is_ascii_graphic()),
        "invalid token"
    );
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(args.threads)
        .enable_all()
        .build()?;
    runtime.block_on(async move {
        let args = Arc::new(args);
        let token = Arc::new(token);
        let mut jobs = Vec::new();
        for worker in 0..args.connections {
            jobs.push(tokio::spawn(run(args.clone(), token.clone(), worker)));
        }
        let mut combined = Stats { hist: vec![0; 10001], ..Default::default() };
        let mut errors = 0;
        for job in jobs {
            match job.await {
                Ok(Ok(stats)) => {
                    combined.queries += stats.queries;
                    combined.denied += stats.denied;
                    combined.capped += stats.capped;
                    combined.elapsed = combined.elapsed.max(stats.elapsed);
                    for (total, count) in combined.hist.iter_mut().zip(stats.hist) {
                        *total += count;
                    }
                }
                result => {
                    errors += 1;
                    eprintln!("load worker failed: {result:?}");
                }
            }
        }
        println!("{}", serde_json::json!({
            "queries": combined.queries,
            "denied": combined.denied,
            "latency_capped_queries": combined.capped,
            "errors": errors,
            "elapsed_secs": combined.elapsed,
            "qps": combined.queries as f64 / combined.elapsed.max(0.001),
            "p50_ms_upper": percentile(&combined.hist, combined.queries, 0.50),
            "p95_ms_upper": percentile(&combined.hist, combined.queries, 0.95),
            "p99_ms_upper": percentile(&combined.hist, combined.queries, 0.99),
            "connections": args.connections,
            "pipeline": args.pipeline,
            "ip_space": args.ip_space,
            "protocol": match args.protocol { Protocol::Http => "http", Protocol::Tcp => "tcp" },
            "latency_resolution_us": 10,
            "latency_cap_ms": 100
        }));
        ensure!(errors == 0, "load workers failed");
        Ok(())
    })
}
