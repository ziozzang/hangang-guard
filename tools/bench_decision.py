#!/usr/bin/env python3
"""Small local decision latency sample, not a saturation/capacity benchmark."""
import argparse
from concurrent.futures import ThreadPoolExecutor
import http.client
import json
import os
from pathlib import Path
import secrets
import signal
import socket
import subprocess
import tempfile
import time


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--guard-bin', default='target/release/hangang-guard')
    parser.add_argument('--requests', type=int, default=2000)
    parser.add_argument('--clients', type=int, default=8)
    args = parser.parse_args()
    assert 1 <= args.clients <= 32 and args.requests >= args.clients
    collector = secrets.token_hex(24)
    env = os.environ.copy()
    env.update(HANGANG_GUARD_COLLECTOR_TOKEN=collector, HANGANG_GUARD_ADMIN_TOKEN=secrets.token_hex(24))
    with socket.socket() as s:
        s.bind(('127.0.0.1', 0))
        port = s.getsockname()[1]
    with tempfile.TemporaryDirectory(prefix='guard-bench-') as directory:
        log = open(Path(directory) / 'server.log', 'wb')
        proc = subprocess.Popen([str(Path(args.guard_bin).resolve()), '--listen', f'127.0.0.1:{port}',
                                 '--database', str(Path(directory) / 'state.db')], env=env, stdout=log, stderr=log)
        try:
            for _ in range(100):
                try:
                    conn = http.client.HTTPConnection('127.0.0.1', port, timeout=2)
                    conn.request('GET', '/healthz')
                    response = conn.getresponse()
                    response.read()
                    conn.close()
                    if response.status == 200:
                        break
                except OSError:
                    time.sleep(.05)
            else:
                raise RuntimeError('guard startup failed')
            def worker(count):
                conn = http.client.HTTPConnection('127.0.0.1', port, timeout=5)
                samples = []
                body = json.dumps({'source_id': 'bench', 'ip': '192.0.2.1'})
                for _ in range(count):
                    start = time.perf_counter()
                    conn.request('POST', '/v1/decision', body=body,
                                 headers={'Authorization': 'Bearer ' + collector, 'Content-Type': 'application/json'})
                    response = conn.getresponse()
                    data = json.loads(response.read())
                    assert response.status == 200 and data['action'] == 'allow'
                    samples.append((time.perf_counter() - start) * 1000)
                conn.close()
                return samples
            counts = [args.requests // args.clients + (i < args.requests % args.clients) for i in range(args.clients)]
            start = time.perf_counter()
            with ThreadPoolExecutor(max_workers=args.clients) as pool:
                samples = sorted(x for result in pool.map(worker, counts) for x in result)
            elapsed = time.perf_counter() - start
            rss = next(line.split()[1] for line in Path(f'/proc/{proc.pid}/status').read_text().splitlines()
                       if line.startswith('VmRSS:'))
            print(json.dumps({'requests': len(samples), 'clients': args.clients, 'elapsed_secs': round(elapsed, 3),
                              'throughput_per_sec': round(len(samples) / elapsed),
                              'p50_ms': round(samples[int(len(samples) * .5)], 3),
                              'p95_ms': round(samples[int(len(samples) * .95)], 3),
                              'p99_ms': round(samples[int(len(samples) * .99)], 3),
                              'guard_rss_kib': int(rss), 'policy': 'empty observe',
                              'scope': 'Python client + loopback HTTP, not maximum server capacity'}, indent=2))
        finally:
            proc.send_signal(signal.SIGTERM)
            try:
                proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()
            log.close()


if __name__ == '__main__':
    main()
