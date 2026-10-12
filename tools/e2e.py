#!/usr/bin/env python3
"""Real-process guard + native Hangang tests, no production changes or third-party Python deps."""
import argparse
import http.server
import json
import os
from pathlib import Path
import secrets
import signal
import shutil
import socket
import subprocess
import tempfile
import threading
import time
import urllib.error
import urllib.request


def port():
    with socket.socket() as s:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]


def request(base, path, token=None, data=None, method=None):
    headers = {}
    if token:
        headers['Authorization'] = 'Bearer ' + token
    if data is not None:
        headers['Content-Type'] = 'application/json'
    req = urllib.request.Request(base + path, data=None if data is None else json.dumps(data).encode(),
                                 headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=3) as response:
            return response.status, response.read()
    except urllib.error.HTTPError as response:
        return response.code, response.read()


def eventually(check, label, seconds=15):
    until = time.monotonic() + seconds
    while time.monotonic() < until:
        try:
            if check():
                return
        except (OSError, urllib.error.URLError):
            pass
        time.sleep(.1)
    raise AssertionError('Timed out: ' + label)


class Origin(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b'origin-ok')

    def log_message(self, *args):
        pass


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--guard-bin', default='target/debug/hangang-guard')
    parser.add_argument('--hangang-bin', default='../hangang-guard-integration/target/debug/hangang')
    args = parser.parse_args()
    guard_bin, hangang_bin = str(Path(args.guard_bin).resolve()), str(Path(args.hangang_bin).resolve())
    collector, admin = secrets.token_hex(24), secrets.token_hex(24)
    env = os.environ.copy()
    env.update(HANGANG_GUARD_COLLECTOR_TOKEN=collector, HANGANG_GUARD_ADMIN_TOKEN=admin, HANGANG_ADMIN_TOKEN=secrets.token_hex(24))
    origin = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Origin)
    threading.Thread(target=origin.serve_forever, daemon=True).start()
    processes = []
    with tempfile.TemporaryDirectory(prefix='hangang-guard-e2e-') as directory:
        directory = Path(directory)
        gp, pp, ap, tp = port(), port(), port(), port()
        base, proxy = f'http://127.0.0.1:{gp}', f'http://127.0.0.1:{pp}'
        geo_path = directory / 'geoip.mmdb'
        shutil.copyfile(Path(__file__).resolve().parents[1] / 'crates/guard-server/fixtures/GeoIP2-City-Test.mmdb', geo_path)
        geo_original = geo_path.read_bytes()
        config = {'revision': 0, 'http': [{'id': 'e2e', 'path_prefix': '/',
                  'backends': [f'http://127.0.0.1:{origin.server_port}']}], 'tcp': []}
        (directory / 'hangang.json').write_text(json.dumps(config))
        logs = []
        def start(command, name):
            log = open(directory / (name + '.log'), 'wb')
            logs.append(log)
            proc = subprocess.Popen(command, env=env, stdout=log, stderr=log)
            processes.append(proc)
            return proc
        def stop(proc):
            if proc.poll() is None:
                proc.send_signal(signal.SIGTERM)
                try:
                    proc.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait()
        try:
            guard_cmd = [guard_bin, '--listen', f'127.0.0.1:{gp}', '--database', str(directory / 'state.sqlite3'),
                         '--decision-listen', f'127.0.0.1:{tp}', '--geoip-database', str(geo_path)]
            guard = start(guard_cmd, 'guard')
            eventually(lambda: request(base, '/healthz')[0] == 200, 'guard startup')
            assert request(base, '/v1/policy', collector)[0] == 401
            assert request(base, '/v1/snapshot', admin)[0] == 401
            native_cmd = [hangang_bin, '--config', str(directory / 'hangang.json'),
                          '--listen', f'127.0.0.1:{pp}', '--admin', f'127.0.0.1:{ap}',
                          '--guard-url', base, '--guard-honeypot-path', '/trap',
                          '--guard-timeout-ms', '1000']
            native = start(native_cmd, 'hangang')
            eventually(lambda: request(proxy, '/ordinary')[0] == 200, 'native startup and remote allow')
            assert request(proxy, '/trap')[0] == 200  # observe by default
            eventually(lambda: any(c['ip'] == '127.0.0.1' for c in json.loads(request(base, '/v1/candidates', admin)[1])),
                       'honeypot candidate')
            policy = json.loads(request(base, '/v1/policy', admin)[1])
            policy['mode'] = 'enforce'
            assert request(base, '/v1/candidates/approve', admin, {'ip': '127.0.0.1'})[0] == 200
            assert request(base, '/v1/policy', admin, policy, 'PUT')[0] == 200
            assert request(proxy, '/ordinary')[0] == 403
            # Guard-denied requests, including traps, must not renew evidence or ban TTL.
            snap1 = json.loads(request(base, '/v1/snapshot', collector)[1])
            for _ in range(3):
                assert request(proxy, '/trap')[0] == 403
            snap2 = json.loads(request(base, '/v1/snapshot', collector)[1])
            assert snap1['blocks'] == snap2['blocks']
            policy['allow'] = ['127.0.0.1/32']
            assert request(base, '/v1/policy', admin, policy, 'PUT')[0] == 200
            assert request(proxy, '/ordinary')[0] == 200
            stop(guard)
            assert request(proxy, '/ordinary')[0] == 503  # default query fail-deny
            guard = start(guard_cmd, 'guard-restart')
            eventually(lambda: request(base, '/healthz')[0] == 200, 'guard restart')
            restored = json.loads(request(base, '/v1/policy', admin)[1])
            assert restored['mode'] == 'enforce' and restored['allow'] == ['127.0.0.1/32']
            assert len(json.loads(request(base, '/v1/snapshot', collector)[1])['blocks']) == 1
            assert request(proxy, '/ordinary')[0] == 200
            # Observe native optional short cache; a new block is stale for <= configured 1 sec.
            stop(native)
            native = start(native_cmd + ['--guard-cache-ms', '1000'], 'hangang-cache')
            eventually(lambda: request(proxy, '/ordinary')[0] == 200, 'cached native startup')
            policy['allow'] = []
            assert request(base, '/v1/policy', admin, policy, 'PUT')[0] == 200
            eventually(lambda: request(proxy, '/ordinary')[0] == 403, '1-second cache invalidation', seconds=3)
            # Failure mode allow is explicit and does not disable other native defenses.
            stop(native)
            stop(guard)
            native = start(native_cmd + ['--guard-failure-mode', 'allow'], 'hangang-fail-allow')
            eventually(lambda: request(proxy, '/ordinary')[0] == 200, 'explicit fail-allow startup')
            stop(native)
            guard = start(guard_cmd, 'guard-tcp')
            eventually(lambda: request(base, '/healthz')[0] == 200, 'TCP authority startup')
            native = start(native_cmd + ['--guard-decision-tcp', f'127.0.0.1:{tp}'], 'hangang-tcp')
            eventually(lambda: request(proxy, '/ordinary')[0] == 403, 'native TCP block')
            assert request(base, '/v1/blocks', admin, {'network': '127.0.0.1/32'}, 'DELETE')[0] == 200
            assert request(proxy, '/ordinary')[0] == 200
            found = json.loads(request(base, '/v1/lookup', admin, {'ip': '81.2.69.160'})[1])
            assert found['geoip']['country_code'] == 'GB' and found['geoip']['city'] == 'London'
            geo_path.write_bytes(b'invalid database')
            assert request(base, '/v1/geoip/reload', admin, {})[0] == 400
            found = json.loads(request(base, '/v1/lookup', admin, {'ip': '81.2.69.160'})[1])
            assert found['geoip']['country_code'] == 'GB'  # last good DB survives
            geo_path.write_bytes(geo_original)
            assert request(base, '/v1/geoip/reload', admin, {})[0] == 200
            script = "return {version=1,rules={{id='loopback-test',network='127.0.0.1/32',action='deny',score=15}}}"
            assert request(base, '/v1/rules/validate', admin, {'script': script})[0] == 200
            assert request(proxy, '/ordinary')[0] == 200  # dry run does not activate
            assert request(base, '/v1/rules/lua', admin, {'script': script}, 'PUT')[0] == 200
            assert request(proxy, '/ordinary')[0] == 403  # same rules on native binary transport
            found = json.loads(request(base, '/v1/lookup', admin, {'ip': '127.0.0.1'})[1])
            assert found['inspection']['static_rule_score'] == 15
            assert found['inspection']['suspicion'] == 'blocked'
            assert request(base, '/v1/networks/inspect', admin, {'network': '127.0.0.0/24'})[0] == 200
            assert request(base, '/v1/snapshot', collector)[0] == 501
            stop(guard)
            assert request(proxy, '/ordinary')[0] == 503
            guard = start(guard_cmd, 'guard-rules-restart')
            eventually(lambda: request(base, '/healthz')[0] == 200, 'rules restart')
            eventually(lambda: request(proxy, '/ordinary')[0] == 403, 'durable rule and TCP reconnect')
            assert request(base, '/v1/rules', admin, {'version': 1, 'rules': []}, 'PUT')[0] == 200
            assert request(proxy, '/ordinary')[0] == 200
            print('PASS: native TCP, GeoIP city lookup/reload/last-good, Lua dry-run/apply, IP risk,')
            print('      CIDR inspection, snapshot rejection, durable rules and TCP reconnect')
            print('PASS: remote query, credential separation, observe candidate, approval, deny, no renewal,')
            print('      allow precedence, fail-deny, SQLite restart, 1-second cache, explicit fail-allow')
        except Exception:
            for path in directory.glob('*.log'):
                # Tokens are not expected in logs; redact defensively.
                text = path.read_text(errors='replace').replace(collector, '[redacted]').replace(admin, '[redacted]')
                print(path.name + ':\n' + text[-6000:])
            raise
        finally:
            for proc in reversed(processes):
                stop(proc)
            for log in logs:
                log.close()
            origin.shutdown()


if __name__ == '__main__':
    main()
