#!/usr/bin/env python3
"""Owned TLS source boundary tests. No operational API or credentials involved."""
import argparse, http.server, json, os, secrets, ssl, subprocess, tempfile, threading, time, socket, sys, urllib.request, urllib.error
from pathlib import Path
from urllib.parse import parse_qs, urlsplit


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--binary',required=True);args=parser.parse_args()
    binary=str(Path(args.binary).resolve());os.umask(0o077)
    token=secrets.token_hex(32);rotated_token=secrets.token_hex(32);accepted_token=token;authenticated=[]
    with tempfile.TemporaryDirectory(prefix='owned-sum-source-tls-') as root:
        root=Path(root)
        def openssl(*arguments):subprocess.run(['openssl',*arguments],cwd=root,check=True,capture_output=True)
        openssl('req','-x509','-newkey','rsa:2048','-nodes','-keyout','ca.key','-out','ca.pem','-days','1','-subj','/CN=Owned source CA','-addext','basicConstraints=critical,CA:TRUE')
        openssl('req','-x509','-newkey','rsa:2048','-nodes','-keyout','wrong-ca.key','-out','wrong-ca.pem','-days','1','-subj','/CN=Owned unrelated CA','-addext','basicConstraints=critical,CA:TRUE')
        openssl('req','-new','-newkey','rsa:2048','-nodes','-keyout','server.key','-out','server.csr','-subj','/CN=Owned source')
        (root/'extensions').write_text('basicConstraints=critical,CA:FALSE\nsubjectAltName=IP:127.0.0.1\nextendedKeyUsage=serverAuth\n')
        openssl('x509','-req','-in','server.csr','-CA','ca.pem','-CAkey','ca.key','-CAcreateserial','-days','1','-extfile','extensions','-out','server.pem')
        mode='valid';requests=[];connections=set()
        class Handler(http.server.BaseHTTPRequestHandler):
            protocol_version="HTTP/1.1"
            def log_message(self,*args):pass
            def do_GET(self):
                requests.append(self.path)
                connections.add(self.client_address)
                if self.headers.get('Authorization')!='Bearer '+accepted_token:
                    self.send_response(401);self.end_headers();return
                authenticated.append((accepted_token,self.client_address))
                page=parse_qs(urlsplit(self.path).query).get('continue',[''])[0]
                policy={'metadata':{'namespace':'owned','uid':'uid-one','name':'policy-one','resourceVersion':'item-rv'},'spec':{'podSelector':{},'policyTypes':['Ingress']}}
                body={'kind':'NetworkPolicyList','apiVersion':'networking.k8s.io/v1','metadata':{'resourceVersion':'opaque-rv','continue':''},'items':[]}
                status=200
                if mode=='valid-paginated':
                    if page and page!='opaque+/%=token':
                        self.send_response(400);self.end_headers();return
                    policy['metadata']['uid']='uid-two' if page else 'uid-one'
                    policy['metadata']['name']='policy-two' if page else 'policy-one'
                    body['items']=[policy]
                    body['metadata']['continue']='' if page else 'opaque+/%=token'
                if mode=='wrong-kind':body['kind']='List'
                if mode=='missing-revision':del body['metadata']['resourceVersion']
                if mode=='revision-change':
                    body['metadata']['continue']='next' if not page else ''
                    if page:body['metadata']['resourceVersion']='changed'
                if mode=='cycle':body['metadata']['continue']='repeat'
                if mode=='deleting-policy':policy['metadata']['deletionTimestamp']='2026-01-01T00:00:00Z';body['items']=[policy]
                if mode=='missing-name':del policy['metadata']['name'];body['items']=[policy]
                if mode=='missing-item-revision':del policy['metadata']['resourceVersion'];body['items']=[policy]
                if mode=='duplicate-name':
                    other=json.loads(json.dumps(policy));other['metadata']['uid']='uid-two';body['items']=[policy,other]
                if mode=='duplicate-uid':body['items']=[policy,policy]
                if mode=='wrong-namespace':policy['metadata']['namespace']='other';body['items']=[policy]
                if mode=='missing-uid':del policy['metadata']['uid'];body['items']=[policy]
                if mode=='contradictory-kind':policy['kind']='Other';body['items']=[policy]
                if mode=='unsupported-policy':policy['spec']['ingress']=[{'from':[{'podSelector':{}}]}];body['items']=[policy]
                if mode=='slow':time.sleep(1.3)
                payload=b' '*1048577 if mode=='oversize' else json.dumps(body).encode()
                self.send_response(302 if mode=='redirect' else status)
                self.send_header('Content-Length',str(len(payload)))
                if mode=='redirect':self.send_header('Location','https://127.0.0.1:'+str(server.server_port)+'/redirect-target')
                self.end_headers()
                try:self.wfile.write(payload)
                except (BrokenPipeError,ConnectionResetError,ssl.SSLError):pass
        class OwnedHTTPServer(http.server.ThreadingHTTPServer):
            def handle_error(self,request,address):
                if isinstance(sys.exc_info()[1],(BrokenPipeError,ConnectionResetError,ssl.SSLError)):return
                super().handle_error(request,address)
        server=OwnedHTTPServer(('127.0.0.1',0),Handler);server.daemon_threads=True
        context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);context.load_cert_chain(root/'server.pem',root/'server.key');server.socket=context.wrap_socket(server.socket,server_side=True)
        thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
        try:
            config=root/'source.json';config.write_text(json.dumps({'api':'https://127.0.0.1:'+str(server.server_port),'namespace':'owned','ca':str(root/'ca.pem'),'token_env':'OWNED_SUM_SOURCE_TOKEN'}))
            cases=['valid','wrong-ca','valid-paginated','wrong-kind','missing-revision','revision-change','cycle','deleting-policy','missing-name','missing-item-revision','duplicate-name','duplicate-uid','wrong-namespace','missing-uid','contradictory-kind','unsupported-policy','slow','redirect','oversize']
            for case in cases:
                mode=case;requests.clear();started=time.monotonic()
                source=json.loads(config.read_text())
                source['ca']=str(root/('wrong-ca.pem' if case=='wrong-ca' else 'ca.pem'))
                config.write_text(json.dumps(source))
                result=subprocess.run([binary,'--observe-kubernetes-policy',str(config)],env=dict(os.environ,OWNED_SUM_SOURCE_TOKEN=token),text=True,capture_output=True,timeout=5)
                elapsed=time.monotonic()-started
                if token in result.stdout+result.stderr:raise RuntimeError('source credential exposed')
                if case in ['valid','valid-paginated']:
                    if result.returncode or json.loads(result.stdout).get('activated') is not False:
                        Path('/tmp/owned-sum-source-tls-failure.log').write_text(result.stderr.replace(token,'[REDACTED]'))
                        raise RuntimeError('valid owned source refused; private sanitized diagnostic retained')
                    if case=='valid-paginated':
                        if json.loads(result.stdout).get('policies')!=2 or len(requests)!=2:
                            raise RuntimeError('complete pagination or opaque continuation encoding failed')
                elif result.returncode==0:raise RuntimeError('malformed source accepted: '+case)
                if case=='wrong-ca' and requests:raise RuntimeError('credential reached untrusted TLS source')
                if case=='slow' and elapsed>1.2:raise RuntimeError('source deadline exceeded')
                if case=='redirect' and len(requests)!=1:raise RuntimeError('source redirect followed')
            mode='valid';requests.clear();connections.clear()
            admin=secrets.token_hex(32)
            with socket.socket()as listener:listener.bind(('127.0.0.1',0));port=listener.getsockname()[1]
            with (root/'follower.log').open('wb')as log:
                process=subprocess.Popen([binary,'--listen','127.0.0.1:'+str(port),'--database',str(root/'follower.sqlite3'),'--kubernetes-policy-source',str(config)],env=dict(os.environ,OWNED_SUM_SOURCE_TOKEN=token,OWNED_SUM_ROTATED_TOKEN=rotated_token,OWNED_SUM_BAD_TOKEN='owned-invalid-token',HANGANG_GUARD_ADMIN_TOKEN=admin,HANGANG_GUARD_COLLECTOR_TOKEN=secrets.token_hex(32)),stdout=log,stderr=log)
                try:
                    def status():
                        request=urllib.request.Request('http://127.0.0.1:'+str(port)+'/v1/kubernetes/status',headers={'Authorization':'Bearer '+admin})
                        try:
                            with urllib.request.urlopen(request,timeout=1)as response:return response.status,json.load(response)
                        except urllib.error.HTTPError as error:return error.code,json.load(error)
                    deadline=time.monotonic()+5
                    while time.monotonic()<deadline:
                        if process.poll() is not None:raise RuntimeError('pooled source follower exited')
                        try:
                            code,body=status()
                            if code==200 and body.get('fresh') and len(requests)>=3:break
                        except OSError:pass
                        time.sleep(.05)
                    else:raise RuntimeError('pooled source cycles not completed')
                    if len(connections)!=1:raise RuntimeError('unchanged source did not reuse one TLS connection')
                    source=json.loads(config.read_text());source['ca']=str(root/'wrong-ca.pem');replacement=root/'next.json';replacement.write_text(json.dumps(source));replacement.replace(config)
                    time.sleep(1.1)
                    if status()[0]!=503:raise RuntimeError('changed untrusted CA retained source candidate')
                    source['ca']=str(root/'ca.pem');replacement.write_text(json.dumps(source));replacement.replace(config)
                    deadline=time.monotonic()+5
                    while time.monotonic()<deadline:
                        code,body=status()
                        if code==200 and body.get('fresh'):break
                        time.sleep(.05)
                    else:raise RuntimeError('source trust restoration did not recover')
                    if len(connections)<2:raise RuntimeError('changed CA retained old TLS pool')
                    before=set(connections);accepted_token=rotated_token
                    source['token_env']='OWNED_SUM_ROTATED_TOKEN';replacement.write_text(json.dumps(source));replacement.replace(config)
                    deadline=time.monotonic()+5
                    while time.monotonic()<deadline:
                        code,body=status()
                        used={address for credential,address in authenticated if credential==rotated_token}
                        if code==200 and body.get('fresh') and used:break
                        time.sleep(.05)
                    else:raise RuntimeError('rotated source credential did not recover')
                    if used & before:raise RuntimeError('credential changed without replacing TLS pool')
                    source['token_env']='OWNED_SUM_BAD_TOKEN';replacement.write_text(json.dumps(source));replacement.replace(config)
                    time.sleep(1.1)
                    if status()[0]!=503:raise RuntimeError('invalid rotated credential retained candidate')
                    before=set(connections)
                    source['token_env']='OWNED_SUM_ROTATED_TOKEN';replacement.write_text(json.dumps(source));replacement.replace(config)
                    deadline=time.monotonic()+5
                    while time.monotonic()<deadline:
                        code,body=status()
                        used={address for credential,address in authenticated if credential==rotated_token}
                        if code==200 and body.get('fresh') and used-before:break
                        time.sleep(.05)
                    else:raise RuntimeError('credential failure recovery did not create new authenticated connection')

                finally:
                    process.terminate()
                    try:process.wait(timeout=5)
                    except subprocess.TimeoutExpired:process.kill();process.wait(timeout=5)
                output=(root/'follower.log').read_text()
                if any(secret in output for secret in [token,rotated_token,admin]):
                    raise RuntimeError('persistent follower exposed credentials')
            print('PASS: 19 owned TLS source cases including wrong-CA rejection and complete opaque-token pagination; bounded deadlines, no redirect or credential exposure; persistent TLS pool reuse/CA replacement/credential rotation and recovery; no activation')
        finally:server.shutdown();server.server_close();thread.join(timeout=2)
if __name__=='__main__':main()
