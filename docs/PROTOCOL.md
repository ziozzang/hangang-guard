# Persistent binary decision protocol v1

The HTTP API remains the management/evidence interface. The optional binary
listener handles ordinary IP decisions with the same policy, rules and GeoIP
context, without JSON. It is plaintext **loopback only** and authenticated once
per connection; remote transport still uses HTTPS. Enable with:

```sh
hangang-guard --decision-listen 127.0.0.1:9081
hangang --guard-url http://127.0.0.1:9080 --guard-decision-tcp 127.0.0.1:9081
```

Supply matching collector tokens through `HANGANG_GUARD_COLLECTOR_TOKEN`.
Native Hangang uses up to64 concurrent reusable connections. Idle sockets are retired after25seconds, before
the service30second idle deadline. Requests carrying a
honeypot/scanner signal still use the authenticated HTTP decision endpoint. The
same default no-cache, optional1–5s cache, timeout and failure policy apply. A
broken/malformed connection is discarded; no silent HTTP transport fallback.

## Authentication

Client writes `HGD1` (4ASCII bytes), token length (u16big-endian), then exactly that
many token bytes (16–4096). Server verifies collector credential and returns
`HGA1`; invalid authentication closes the connection. Admin tokens are rejected.
Authentication deadline5s, idle read deadline30s, write deadline5s; at most256
concurrent binary connections. Shutdown cancels existing sockets.

## Query frame — 24 bytes

| Offset | Length | Meaning |
| --- | ---: | --- |
| 0 | 1 | Version1 |
| 1 | 1 | IP family4 or6 |
| 2 | 2 | Reserved, must be zero |
| 4 | 4 | Correlation id, u32 big-endian |
| 8 | 16 | IPv6 bytes; IPv4 uses first4 bytes and12zero bytes |

## Response frame — 24 bytes

| Offset | Length | Meaning |
| --- | ---: | --- |
| 0 | 1 | Version1 |
| 1 | 1 | Action0allow,1deny |
| 2 | 1 | Mode0observe,1enforce |
| 3 | 1 | Reserved zero |
| 4 | 4 | Echoed correlation id, u32 big-endian |
| 8 | 8 | Policy revision, u64 big-endian |
| 16 | 4 | Decision TTL milliseconds, u32 big-endian,0–5000 |
| 20 | 4 | Reserved zero |

Stream framing is fixed-size; queries may be pipelined and responses remain in
order. The service batches up to256frames per read and combines response writes.
It retains a partial frame across reads. Invalid versions/families/padding close
connection. Native client validates all response fields/correlation, and the
single request timeout includes pool wait, connect, auth, read/write. TTL is
measured from query start, so transport latency cannot extend decision validity.
No reason strings, GeoIP names, scores or credentials occur in decision frames;
operator inspection uses admin APIs instead.
