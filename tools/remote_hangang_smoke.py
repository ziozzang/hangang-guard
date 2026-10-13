#!/usr/bin/env python3
"""Owned real Sumunjang/Hangang mTLS processes, policy and outage qualification."""
import argparse, http.client, http.server, json, os, pathlib, secrets, socket, subprocess, tempfile, threading, time, urllib.request

def port():
    with socket.socket() as s:
        s.bind(('127.0.0.1',0));return s.getsockname()[1]

def main():
    parser=argparse.ArgumentParser();parser.add_argument('--gateway-binary',required=True,type=pathlib.Path);parser.add_argument('--sumunjang-binary',required=True,type=pathlib.Path);args=parser.parse_args()
    processes=[];hits=[]
    class Origin(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            hits.append(self.path);self.send_response(200);self.end_headers();self.wfile.write(b'owned')
        def log_message(self,*args):pass
    origin=http.server.ThreadingHTTPServer(('127.0.0.1',0),Origin);threading.Thread(target=origin.serve_forever,daemon=True).start()
    try:
        with tempfile.TemporaryDirectory(prefix='owned-sumunjang-mtls-') as tmp:
            root=pathlib.Path(tmp);collector,admin,system=[secrets.token_hex(32) for _ in range(3)];public,parent_admin,control,native=[port() for _ in range(4)]
            def openssl(*args):subprocess.run(['openssl',*args],cwd=root,check=True,capture_output=True)
            openssl('req','-x509','-newkey','rsa:2048','-nodes','-keyout','ca.key','-out','ca.pem','-days','1','-subj','/CN=Owned CA','-addext','basicConstraints=critical,CA:TRUE')
            for name,usage in [('server','serverAuth'),('client','clientAuth')]:
                openssl('req','-new','-newkey','rsa:2048','-nodes','-keyout',name+'.key','-out',name+'.csr','-subj','/CN='+name)
                (root/(name+'.ext')).write_text('basicConstraints=critical,CA:FALSE\nkeyUsage=digitalSignature,keyEncipherment\nextendedKeyUsage='+usage+'\nsubjectAltName=DNS:sumunjang.example.test\n')
                openssl('x509','-req','-in',name+'.csr','-CA','ca.pem','-CAkey','ca.key','-CAcreateserial','-days','1','-extfile',name+'.ext','-out',name+'.pem')
            (root/'policy.json').write_text(json.dumps({'mode':'enforce','auto_block':False}))
            (root/'hangang.json').write_text(json.dumps({'http':[{'id':'owned','host':'app.example.test','backends':[f'http://127.0.0.1:{origin.server_port}']}]}))
            env=dict(os.environ,HANGANG_GUARD_COLLECTOR_TOKEN=collector,HANGANG_GUARD_ADMIN_TOKEN=admin,FIXTURE_GUARD_KEY=collector,HANGANG_ADMIN_TOKEN=system)
            def start(binary,argv,name):
                log=open(root/(name+'.log'),'ab');p=subprocess.Popen([str(binary.resolve()),*argv],env=env,stdout=log,stderr=log);processes.append(p);return p
            def wait(url,p,name,token=None):
                for _ in range(150):
                    if p.poll() is not None:raise RuntimeError(name+' startup failed: '+(root/(name+'.log')).read_text().replace(collector,'[redacted]').replace(admin,'[redacted]').replace(system,'[redacted]'))
                    try:
                        with urllib.request.urlopen(urllib.request.Request(url,headers={'Authorization':'Bearer '+token} if token else {}),timeout=1) as r:
                            if r.status==200:return
                    except OSError:time.sleep(.05)
                raise RuntimeError(name+' readiness deadline')
            server=start(args.sumunjang_binary,['--listen',f'127.0.0.1:{control}','--decision-listen',f'0.0.0.0:{native}','--database',str(root/'sumunjang.db'),'--policy',str(root/'policy.json'),'--decision-tls-cert',str(root/'server.pem'),'--decision-tls-key',str(root/'server.key'),'--decision-client-ca',str(root/'ca.pem')],'sumunjang')
            wait(f'http://127.0.0.1:{control}/healthz',server,'sumunjang')
            def gateway(name='sumunjang.example.test'):
                p=start(args.gateway_binary,['--config',str(root/'hangang.json'),'--listen',f'127.0.0.1:{public}','--admin',f'127.0.0.1:{parent_admin}','--threads','2','--lua-workers','1','--drain-seconds','1','--guard-url',f'http://127.0.0.1:{control}','--guard-decision-tcp',f'127.0.0.1:{native}','--guard-token-env','FIXTURE_GUARD_KEY','--guard-cache-ms','0','--guard-decision-server-name',name,'--guard-decision-ca',str(root/'ca.pem'),'--guard-decision-cert',str(root/'client.pem'),'--guard-decision-key',str(root/'client.key')],'hangang')
                wait(f'http://127.0.0.1:{parent_admin}/v1/config',p,'hangang',system);return p
            def request():
                c=http.client.HTTPConnection('127.0.0.1',public,timeout=3);c.request('GET','/ordinary',headers={'Host':'app.example.test'});r=c.getresponse();status=r.status;r.read();c.close();return status
            def block(method):
                headers={'Authorization':'Bearer '+admin,'Content-Type':'application/json'};body={'network':'127.0.0.1/32'}
                if method=='POST':body.update(expires_at=int(time.time())+300,reason='owned-qualification')
                with urllib.request.urlopen(urllib.request.Request(f'http://127.0.0.1:{control}/v1/blocks',data=json.dumps(body).encode(),headers=headers,method=method),timeout=3) as r:assert r.status==200
            parent=gateway();assert request()==200 and request()==200;assert len(hits)==2
            block('POST');assert request()==403 and len(hits)==2
            block('DELETE');assert request()==200 and len(hits)==3
            parent.terminate();parent.wait(timeout=5)
            parent=gateway('wrong.example.test');assert request()==503 and len(hits)==3
            parent.terminate();parent.wait(timeout=5)
            parent=gateway();assert request()==200 and len(hits)==4
            server.terminate();server.wait(timeout=5);assert request()==503 and len(hits)==4
            print('PASS: real Hangang/Sumunjang mTLS HGD1, persistent allow, immediate manual deny/removal, wrong-name failure/recovery and authority-outage fail-closed; no full-stack throughput claim.')
    finally:
        for p in reversed(processes):
            if p.poll() is None:
                p.terminate()
                try:p.wait(timeout=5)
                except subprocess.TimeoutExpired:p.kill();p.wait()
        origin.shutdown();origin.server_close()

if __name__=='__main__':main()
