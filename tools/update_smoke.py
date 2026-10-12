#!/usr/bin/env python3
"""Owned-process signed update/restart/rollback smoke. Linux, OpenSSL; no production edits."""
import argparse
import base64
import hashlib
import http.server
import json
import os
from pathlib import Path
import secrets
import shutil
import signal
import socket
import ssl
import subprocess
import tempfile
import threading
import time
import urllib.error
import urllib.request


def free_port():
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        return sock.getsockname()[1]


def request(base, path, token=None, data=None, method=None):
    headers = {'Content-Type': 'application/json'}
    if token:
        headers['Authorization'] = 'Bearer ' + token
    req = urllib.request.Request(base + path, headers=headers,
                                 data=None if data is None else json.dumps(data).encode(), method=method)
    try:
        with urllib.request.urlopen(req, timeout=2) as response:
            return response.status, json.loads(response.read())
    except urllib.error.HTTPError as response:
        return response.code, json.loads(response.read())


def eventually(check, message, seconds=30):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        try:
            if check():
                return
        except (OSError, urllib.error.URLError):
            pass
        time.sleep(.1)
    raise AssertionError(message)


def children(pid):
    path = Path(f'/proc/{pid}/task/{pid}/children')
    return path.read_text().split() if path.exists() else []


class Origin(http.server.BaseHTTPRequestHandler):
    artifact = b''
    manifest = b''
    stall = False
    stalled = threading.Event()
    release_stall = threading.Event()

    def do_GET(self):
        data = type(self).manifest if self.path == '/manifest' else type(self).artifact
        self.send_response(200)
        self.send_header('Content-Length', str(len(data)))
        self.end_headers()
        if self.path == '/manifest' and type(self).stall:
            type(self).stalled.set()
            type(self).release_stall.wait(timeout=20)
        try:
            self.wfile.write(data)
        except (OSError, ssl.SSLError):
            pass

    def log_message(self, *args):
        pass


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--guard-bin', default='target/debug/hangang-guard')
    parser.add_argument('--signer-bin', default='target/debug/guard-release-sign')
    args = parser.parse_args()
    if not Path('/proc/self').exists():
        raise SystemExit('Linux process smoke requires /proc')
    guard = Path(args.guard_bin).resolve()
    signer = Path(args.signer_bin).resolve()
    version = subprocess.check_output([guard, '--version'], text=True).strip().split()[1]
    major, minor, patch = map(int, version.split('.'))
    future = f'{major}.{minor}.{patch + 1}'
    broken = f'{major}.{minor}.{patch + 2}'
    target = json.loads(subprocess.check_output([guard, '--about'], text=True))['target']
    collector, admin = secrets.token_hex(24), secrets.token_hex(24)
    env = os.environ.copy()
    env.update(HANGANG_GUARD_COLLECTOR_TOKEN=collector, HANGANG_GUARD_ADMIN_TOKEN=admin)
    with tempfile.TemporaryDirectory(prefix='guard-update-smoke-') as temporary:
        root = Path(temporary)
        root.chmod(0o700)
        runtime, installed = root / 'runtime', root / 'hangang-guard'
        shutil.copy2(guard, runtime)
        shutil.copy2(guard, installed)
        seed = root / 'seed'
        seed.write_text(base64.b64encode(secrets.token_bytes(32)).decode() + '\n')
        seed.chmod(0o600)
        public = subprocess.check_output([signer, '--public-key', seed], text=True).strip()
        env['HANGANG_GUARD_UPDATE_KEY'] = public
        cert, key = root / 'cert.pem', root / 'key.pem'
        ca, ca_key, csr = root / 'ca.pem', root / 'ca-key.pem', root / 'leaf.csr'
        def openssl(*arguments):
            subprocess.run(['openssl', *map(str, arguments)], check=True,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        openssl('req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', ca_key,
                '-out', ca, '-days', '1', '-subj', '/CN=Guard smoke CA',
                '-addext', 'basicConstraints=critical,CA:TRUE',
                '-addext', 'keyUsage=critical,keyCertSign,cRLSign')
        openssl('req', '-new', '-newkey', 'rsa:2048', '-nodes', '-keyout', key,
                '-out', csr, '-subj', '/CN=127.0.0.1')
        extensions = root / 'leaf.ext'
        extensions.write_text('subjectAltName=IP:127.0.0.1\nbasicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\n')
        openssl('x509', '-req', '-in', csr, '-CA', ca, '-CAkey', ca_key,
                '-CAcreateserial', '-out', cert, '-days', '1', '-extfile', extensions)
        origin = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Origin)
        origin.daemon_threads = True
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cert, key)
        origin.socket = context.wrap_socket(origin.socket, server_side=True)
        threading.Thread(target=origin.serve_forever, daemon=True).start()
        release_base = f'https://127.0.0.1:{origin.server_port}'
        def publish(release_version, artifact, tamper=False):
            Origin.artifact = artifact
            payload = {'version': release_version, 'target': target,
                       'artifact_url': release_base + '/artifact', 'size': len(artifact),
                       'sha256': hashlib.sha256(artifact).hexdigest()}
            payload_path, manifest_path = root / 'payload.json', root / 'manifest.json'
            payload_path.write_text(json.dumps(payload, separators=(',', ':')))
            subprocess.run([signer, payload_path, seed, manifest_path], check=True,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            manifest = manifest_path.read_bytes()
            if tamper:
                value = json.loads(manifest)
                signature = bytearray(base64.b64decode(value['signature']))
                signature[0] ^= 1
                value['signature'] = base64.b64encode(signature).decode()
                manifest = json.dumps(value).encode()
            Origin.manifest = manifest
        publish(version, guard.read_bytes())
        # CLI validation must not create a second policy writer or bind any listener.
        missing_db = root / 'check-only.db'
        subprocess.run([guard, '--check', '--database', missing_db], env=env, check=True,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        assert not missing_db.exists()
        hp, tp = free_port(), free_port()
        api = f'http://127.0.0.1:{hp}'
        status_file, database = root / 'update.json', root / 'policy.db'
        log = open(root / 'worker.log', 'wb')
        proc = subprocess.Popen([installed, '--supervised', '--listen', f'127.0.0.1:{hp}',
                                 '--decision-listen', f'127.0.0.1:{tp}', '--database', str(database),
                                 '--update-manifest', release_base + '/manifest', '--update-ca', str(ca),
                                 '--update-status-file', str(status_file), '--update-interval-seconds', '300'],
                                env=env, stdout=log, stderr=log)
        def phase(name):
            return proc.poll() is None and request(api, '/v1/update/status', admin)[1]['phase'] == name
        def check_now():
            assert request(api, '/v1/update/check', admin, {})[0] == 200
        try:
            eventually(lambda: request(api, '/healthz')[0] == 200, 'initial readiness')
            eventually(lambda: phase('up_to_date'), 'signed equal-version no-op')
            assert request(api, '/v1/update/status', collector)[0] == 401
            policy = {'mode': 'enforce', 'allow': ['192.0.2.2/32']}
            assert request(api, '/v1/policy', admin, policy, 'PUT')[0] == 200
            assert request(api, '/v1/blocks', admin,
                           {'network': '192.0.2.1/32', 'expires_at': int(time.time()) + 600, 'reason': 'smoke'})[0] == 200
            original_child = children(proc.pid)
            proc.send_signal(signal.SIGHUP)
            eventually(lambda: children(proc.pid) != original_child and request(api, '/healthz')[0] == 200,
                       'HUP child replacement')
            assert request(api, '/v1/decision', collector, {'source_id': 'smoke', 'ip': '192.0.2.1'})[1]['action'] == 'deny'
            # Signed future launchers wrap an owned runtime to exercise lifecycle, not cross-version schema migration.
            good = f'#!/bin/sh\nif [ "$1" = --version ]; then echo "hangang-guard {future}"; exit 0; fi\nexec "{runtime}" "$@"\n'.encode()
            publish(future, good)
            check_now()
            eventually(lambda: phase('active'), 'signed upgrade and readiness')
            assert subprocess.check_output([installed, '--version'], text=True).strip() == 'hangang-guard ' + future
            assert request(api, '/v1/policy', admin)[1]['allow'] == ['192.0.2.2/32']
            assert request(api, '/v1/decision', collector, {'source_id': 'smoke', 'ip': '192.0.2.1'})[1]['action'] == 'deny'
            bad = f'#!/bin/sh\nif [ "$1" = --version ]; then echo "hangang-guard {broken}"; exit 0; fi\nfor arg in "$@"; do if [ "$arg" = --check ]; then exec "{runtime}" "$@"; fi; done\nexit 73\n'.encode()
            publish(broken, bad)
            check_now()
            eventually(lambda: phase('rolled_back'), 'candidate readiness failure rollback')
            assert installed.read_bytes() == good
            assert request(api, '/v1/decision', collector, {'source_id': 'smoke', 'ip': '192.0.2.1'})[1]['action'] == 'deny'
            old_child = children(proc.pid)
            publish(broken, bad, tamper=True)
            check_now()
            eventually(lambda: phase('rejected'), 'signature rejection')
            assert children(proc.pid) == old_child and installed.read_bytes() == good
            Origin.stall = True
            Origin.stalled.clear()
            check_now()
            assert Origin.stalled.wait(timeout=3)
            proc.send_signal(signal.SIGTERM)
            assert proc.wait(timeout=5) == 0
            assert not children(proc.pid)
            assert not list(root.glob('.guard-update-*'))
            print('PASS: stable supervisor, read-only preflight, inherited listeners, HUP checkpoint/restart,')
            print('      signed upgrade, policy retention, readiness rollback, tamper rejection, cancellation')
        except Exception:
            log.flush()
            text = (root / 'worker.log').read_text(errors='replace').replace(collector, '[redacted]').replace(admin, '[redacted]')
            print(text[-8000:])
            if status_file.exists():
                print('Supervisor status:', status_file.read_text())
            raise
        finally:
            Origin.release_stall.set()
            if proc.poll() is None:
                proc.send_signal(signal.SIGTERM)
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait()
            log.close()
            origin.shutdown()


if __name__ == '__main__':
    main()
