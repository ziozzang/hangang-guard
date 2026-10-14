#!/usr/bin/env python3
"""Owned gRPC/native parity and supervised listener handover qualification."""
import argparse
import importlib
import os
from pathlib import Path
import secrets
import signal
import socket
import ssl
import struct
import subprocess
import sys
import tempfile
import time
import grpc
from update_smoke import children, eventually, free_port, request


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--binary', default='target/debug/sumunjang', type=Path)
    parser.add_argument('--hangang-client', type=Path)
    args = parser.parse_args()
    binary = args.binary.resolve()
    with tempfile.TemporaryDirectory(prefix='sumunjang-grpc-owned-') as temporary:
        root = Path(temporary)
        root.chmod(0o700)
        def run(*argv):
            subprocess.run(argv, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        def certificate(name, ca=None, usage=None):
            run('openssl', 'req', '-new', '-newkey', 'rsa:2048', '-nodes', '-keyout', str(root/f'{name}.key'), '-out', str(root/f'{name}.csr'), '-subj', f'/CN={name}')
            if ca:
                ext = root/f'{name}.ext'
                ext.write_text(f'basicConstraints=CA:FALSE\nkeyUsage=digitalSignature,keyEncipherment\nextendedKeyUsage={usage}\nsubjectAltName=DNS:sumunjang.example.test\n')
                run('openssl', 'x509', '-req', '-in', str(root/f'{name}.csr'), '-CA', str(root/f'{ca}.pem'), '-CAkey', str(root/f'{ca}.key'), '-CAcreateserial', '-days', '1', '-extfile', str(ext), '-out', str(root/f'{name}.pem'))
            else:
                run('openssl', 'req', '-x509', '-key', str(root/f'{name}.key'), '-in', str(root/f'{name}.csr'), '-days', '1', '-out', str(root/f'{name}.pem'), '-addext', 'basicConstraints=critical,CA:TRUE')
        certificate('ca')
        certificate('server', 'ca', 'serverAuth')
        certificate('client', 'ca', 'clientAuth')
        certificate('other-ca')
        certificate('untrusted', 'other-ca', 'clientAuth')
        proto = Path(__file__).resolve().parents[1]/'crates/guard-grpc/proto'
        run(sys.executable, '-m', 'grpc_tools.protoc', '-I'+str(proto), '--python_out='+str(root), '--grpc_python_out='+str(root), str(proto/'network.proto'))
        sys.path.insert(0, str(root))
        pb = importlib.import_module('network_pb2')
        rpc = importlib.import_module('network_pb2_grpc')
        admin, collector = secrets.token_hex(24), secrets.token_hex(24)
        env = dict(os.environ, HANGANG_GUARD_ADMIN_TOKEN=admin, HANGANG_GUARD_COLLECTOR_TOKEN=collector)
        http, native, transport = free_port(), free_port(), free_port()
        argv = [str(binary), '--supervised', '--listen', f'127.0.0.1:{http}', '--database', str(root/'policy.sqlite3'), '--decision-listen', f'0.0.0.0:{native}', '--grpc-listen', f'0.0.0.0:{transport}', '--decision-tls-cert', str(root/'server.pem'), '--decision-tls-key', str(root/'server.key'), '--decision-client-ca', str(root/'ca.pem')]
        def channel(identity='client', hostname='sumunjang.example.test'):
            creds = grpc.ssl_channel_credentials((root/'ca.pem').read_bytes(), (root/f'{identity}.key').read_bytes() if identity else None, (root/f'{identity}.pem').read_bytes() if identity else None)
            return grpc.secure_channel(f'127.0.0.1:{transport}', creds, options=(('grpc.ssl_target_name_override', hostname),))
        def rejected(stub, message, code, token=collector, metadata=None):
            try:
                stub.Check(message, timeout=1, metadata=metadata or [('authorization', 'Bearer '+token)])
            except grpc.RpcError as error:
                assert error.code() in code, error.code()
            else:
                raise AssertionError('unexpected successful RPC')
        def native_check(ip):
            ctx = ssl.create_default_context(cafile=str(root/'ca.pem'))
            ctx.load_cert_chain(str(root/'client.pem'), str(root/'client.key'))
            ctx.set_alpn_protocols(['hgd1'])
            def exact(sock, length):
                result = b''
                while len(result) < length:
                    part = sock.recv(length-len(result))
                    assert part
                    result += part
                return result
            with ctx.wrap_socket(socket.create_connection(('127.0.0.1', native), timeout=2), server_hostname='sumunjang.example.test') as sock:
                token = collector.encode()
                sock.sendall(b'HGD1'+struct.pack('!H', len(token))+token)
                assert exact(sock, 4) == b'HGA1'
                sock.sendall(bytes([1, 4, 0, 0])+struct.pack('!I', 42)+socket.inet_aton(ip)+bytes(12))
                return exact(sock, 24)
        api = f'http://127.0.0.1:{http}'
        with (root/'server.log').open('wb') as log:
            proc = subprocess.Popen(argv, env=env, stdout=log, stderr=log)
            ch = channel()
            try:
                eventually(lambda: proc.poll() is None and request(api, '/healthz')[0] == 200, 'server readiness')
                grpc.channel_ready_future(ch).result(timeout=5)
                stub = rpc.NetworkStub(ch)
                msg = pb.NetworkRequest(request_id=42, ip=socket.inet_aton('192.0.2.1'))
                def check():
                    return stub.Check(msg, timeout=2, metadata=[('authorization', 'Bearer '+collector)])
                rejected(stub, msg, [grpc.StatusCode.UNAUTHENTICATED], token=admin)
                rejected(stub, msg, [grpc.StatusCode.UNAUTHENTICATED], metadata=[('authorization', 'Bearer '+collector)]*2)
                rejected(stub, pb.NetworkRequest(ip=b'bad'), [grpc.StatusCode.INVALID_ARGUMENT])
                rejected(stub, pb.NetworkRequest(ip=bytes(4096)), [grpc.StatusCode.RESOURCE_EXHAUSTED, grpc.StatusCode.OUT_OF_RANGE])
                for identity, hostname in [(None, 'sumunjang.example.test'), ('untrusted', 'sumunjang.example.test'), ('client', 'wrong.example.test')]:
                    with channel(identity, hostname) as bad:
                        rejected(rpc.NetworkStub(bad), msg, [grpc.StatusCode.UNAVAILABLE, grpc.StatusCode.DEADLINE_EXCEEDED])
                assert check().mode == 1  # Observe is never reported as enforcement.
                assert request(api, '/v1/policy', admin, {'mode': 'enforce', 'allow': ['192.0.2.2/32']}, 'PUT')[0] == 200
                assert request(api, '/v1/blocks', admin, {'network': '192.0.2.1/32', 'expires_at': int(time.time())+600, 'reason': 'owned fixture'})[0] == 200
                reply = check()
                assert (reply.request_id, reply.verdict, reply.mode) == (42, 2, 2)
                frame = native_check('192.0.2.1')
                assert frame[1] == 1 and frame[2] == 1
                assert reply.revision == struct.unpack('!Q', frame[8:16])[0]
                assert reply.ttl_ms == struct.unpack('!I', frame[16:20])[0]
                msg.minimum_revision = reply.revision+1
                unavailable = check()
                assert (unavailable.verdict, unavailable.mode, unavailable.ttl_ms) == (3, 0, 0)
                msg.minimum_revision = 0
                old_children = children(proc.pid)
                proc.send_signal(signal.SIGHUP)
                def replaced():
                    if children(proc.pid) == old_children:
                        return False
                    try:
                        r = check()
                        return r.verdict == 2 and r.revision == reply.revision
                    except grpc.RpcError:
                        return False
                eventually(replaced, 'gRPC listener handover and durable decision')
                assert native_check('192.0.2.1')[1] == 1
                if args.hangang_client:
                    subprocess.run([str(args.hangang_client.resolve()), f'localhost:{transport}', api, str(root/'ca.pem'), str(root/'client.pem'), str(root/'client.key')], env=env, check=True, timeout=20)
                assert request(api, '/v1/blocks', admin, {'network': '192.0.2.1/32'}, 'DELETE')[0] == 200
                revoked = check()
                assert revoked.verdict == 1 and revoked.revision > reply.revision
                assert native_check('192.0.2.1')[1] == 0
                msg.ip = socket.inet_aton('192.0.2.2')
                assert (check().verdict, check().mode) == (1, 2)
                print('PASS: real gRPC mTLS, role isolation, malformed/oversized input, native parity, revision fence, policy updates and supervised listener handover')
            finally:
                ch.close()
                proc.terminate()
                try:
                    proc.wait(timeout=20)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait()


if __name__ == '__main__':
    main()
