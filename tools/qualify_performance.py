#!/usr/bin/env python3
"""Release transport qualification using a bounded Rust generator on loopback."""
import argparse
import ipaddress
import json
import os
from pathlib import Path
import secrets
import signal
import socket
import sqlite3
import subprocess
import tempfile
import time
import urllib.request


def free_port():
    with socket.socket() as s:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]


def seed_db(path, count, family):
    start = ipaddress.ip_address('192.0.0.0' if family == 4 else '2001:db8::')
    blocks = [{'network': f'{start + i}/{32 if family == 4 else 128}',
               'expires_at': int(time.time()) + 600, 'reason': 'bench'} for i in range(count)]
    policy = {'mode': 'enforce', 'auto_block': False, 'window_secs': 60, 'threshold': 10,
              'block_ttl_secs': 900, 'allow': [],
              'weights': {'honeypot': 10, 'scanner': 5, 'auth_failure': 1, 'invalid_request': 2}}
    state = {'policy': policy, 'revision': 1, 'blocks': blocks, 'aggregates': [],
             'stats': {'accepted': 0, 'dropped_capacity': 0, 'block_capacity_rejections': 0}}
    with sqlite3.connect(path) as db:
        db.execute('CREATE TABLE checkpoint(id INTEGER PRIMARY KEY CHECK(id=1), body TEXT NOT NULL)')
        db.execute('INSERT INTO checkpoint(id,body) VALUES(1,?)', (json.dumps(state),))


def proc_sample(pid):
    status = Path(f'/proc/{pid}/status').read_text()
    rss = int(next(line.split()[1] for line in status.splitlines() if line.startswith('VmRSS:')))
    fields = Path(f'/proc/{pid}/stat').read_text().split()
    return rss, (int(fields[13]) + int(fields[14])) / os.sysconf('SC_CLK_TCK')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--guard-bin', default='target/release/hangang-guard')
    parser.add_argument('--load-bin', default='target/release/guard-load')
    parser.add_argument('--baseline-bin', default='/tmp/hangang-guard-baseline')
    parser.add_argument('--output', default='docs/performance-results.json')
    parser.add_argument('--seconds', type=int, default=10)
    parser.add_argument('--baseline-only', action='store_true')
    parser.add_argument('--geoip-database')
    parser.add_argument('--cases', help='Comma-separated case names; omit for all')
    args = parser.parse_args()
    binaries = {'current': str(Path(args.guard_bin).resolve()), 'baseline': str(Path(args.baseline_bin).resolve())}
    load = str(Path(args.load_bin).resolve())
    token = secrets.token_hex(32)
    env = os.environ.copy()
    env.update(HANGANG_GUARD_COLLECTOR_TOKEN=token, HANGANG_GUARD_ADMIN_TOKEN=secrets.token_hex(32))
    cases = [('baseline-http-empty', 'baseline', 'http', 32, 1, 0, 4)]
    if not args.baseline_only:
        cases += [('baseline-http-pool-v4', 'baseline', 'http', 32, 1, 20000, 4),
                  ('baseline-http-pool-v6', 'baseline', 'http', 32, 1, 20000, 6),
                  ('http-empty', 'current', 'http', 32, 1, 0, 4),
                  ('http-pool-v4-comparable', 'current', 'http', 32, 1, 20000, 4),
                  ('http-pool-v6-comparable', 'current', 'http', 32, 1, 20000, 6),
                  ('http-pool-v4', 'current', 'http', 128, 1, 20000, 4),
                  ('http-pool-v4-pipeline', 'current', 'http', 128, 16, 20000, 4),
                  ('tcp-empty', 'current', 'tcp', 64, 1, 0, 4),
                  ('tcp-pool-v4', 'current', 'tcp', 128, 1, 20000, 4),
                  ('tcp-pool-v4-pipeline', 'current', 'tcp', 64, 16, 20000, 4),
                  ('tcp-pool-v6', 'current', 'tcp', 128, 1, 20000, 6),
                  ('tcp-pool-v6-pipeline', 'current', 'tcp', 64, 16, 20000, 6)]
    if args.geoip_database and not args.baseline_only:
        cases += [('http-geoip-rules', 'current', 'http', 32, 1, 0, 4),
                  ('tcp-geoip-rules', 'current', 'tcp', 128, 1, 0, 4)]
    if args.cases:
        selected = set(args.cases.split(','))
        cases = [case for case in cases if case[0] in selected]
        if not cases:
            raise ValueError('No matching cases')
    report = {'cpu': next(line.split(':', 1)[1].strip() for line in Path('/proc/cpuinfo').read_text().splitlines()
                         if line.startswith('model name')), 'logical_cpus': os.cpu_count(),
              'duration_secs': args.seconds, 'warmup_secs': 2, 'load_threads': 8,
              'scope': 'guard + Rust client on shared host loopback; not full proxy or production SLA', 'results': []}
    with tempfile.TemporaryDirectory(prefix='guard-qualify-') as root:
        root = Path(root)
        for name, build, protocol, connections, pipeline, prefixes, family in cases:
            print('START ' + name, flush=True)
            directory = root / name
            directory.mkdir()
            database = directory / 'state.db'
            if prefixes:
                seed_db(database, prefixes, family)
            hp, tp = free_port(), free_port()
            command = [binaries[build], '--listen', f'127.0.0.1:{hp}', '--database', str(database)]
            if build == 'current':
                command += ['--decision-listen', f'127.0.0.1:{tp}']
            geo_case = 'geoip' in name
            if geo_case:
                command += ['--geoip-database', args.geoip_database]
            with open(directory / 'guard.log', 'wb') as log:
                proc = subprocess.Popen(command, env=env, stdout=log, stderr=log)
                try:
                    for _ in range(200):
                        if proc.poll() is not None:
                            raise RuntimeError('guard startup failed: ' + (directory / 'guard.log').read_text())
                        try:
                            with urllib.request.urlopen(f'http://127.0.0.1:{hp}/healthz', timeout=.2) as response:
                                if response.status == 200:
                                    break
                        except OSError:
                            time.sleep(.05)
                    else:
                        raise RuntimeError('guard startup timeout')
                    if geo_case:
                        headers = {'Authorization': 'Bearer ' + env['HANGANG_GUARD_ADMIN_TOKEN'], 'Content-Type': 'application/json'}
                        for endpoint, payload in [('policy', {'mode': 'enforce'}), ('rules', {'version': 1, 'rules': [
                            {'id': 'geo-observe-us', 'countries': ['US'], 'action': 'observe', 'score': 5, 'priority': 10},
                            {'id': 'geo-deny-gb', 'countries': ['GB'], 'action': 'deny', 'score': 10, 'priority': 5}]} )]:
                            req = urllib.request.Request(f'http://127.0.0.1:{hp}/v1/{endpoint}', data=json.dumps(payload).encode(), headers=headers, method='PUT')
                            with urllib.request.urlopen(req, timeout=10) as response:
                                assert response.status == 200
                    rss_start, cpu_start = proc_sample(proc.pid)
                    started = time.monotonic()
                    result = subprocess.run([load, '--address', f'127.0.0.1:{tp if protocol == "tcp" else hp}',
                                             '--protocol', protocol, '--connections', str(connections),
                                             '--pipeline', str(pipeline), '--seconds', str(args.seconds),
                                             '--warmup', '2', '--ip', '8.8.8.8' if geo_case else ('192.0.0.0' if family == 4 else '2001:db8::'),
                                             '--ip-space', '65536' if prefixes or geo_case else '1'], env=env,
                                            capture_output=True, text=True, timeout=args.seconds + 20)
                    wall = time.monotonic() - started
                    rss_end, cpu_end = proc_sample(proc.pid)
                    if result.returncode:
                        raise RuntimeError(name + ' failed: ' + result.stderr[-3000:] + result.stdout)
                    metrics = json.loads(result.stdout.strip())
                    metrics.update(case=name, prefixes=prefixes, family=family, build=build, geoip_rules=geo_case,
                                   rss_kib=rss_end, rss_start_kib=rss_start,
                                   server_cpu_seconds=round(cpu_end - cpu_start, 3),
                                   server_cpu_cores=round((cpu_end - cpu_start) / wall, 3))
                    report['results'].append(metrics)
                    Path(args.output).write_text(json.dumps(report, indent=2) + '\n')
                    print(json.dumps(metrics), flush=True)
                finally:
                    if proc.poll() is None:
                        proc.send_signal(signal.SIGTERM)
                        try:
                            proc.wait(timeout=10)
                        except subprocess.TimeoutExpired:
                            proc.kill()
                            proc.wait()
    print('WROTE ' + args.output, flush=True)


if __name__ == '__main__':
    main()
