#!/usr/bin/env python3
"""Owned Kubernetes read-only source qualification; cleans its own namespace."""
import argparse, base64, json, os, secrets, subprocess, tempfile, socket, time, urllib.request, urllib.error
from pathlib import Path

def main():
    parser=argparse.ArgumentParser();parser.add_argument('--binary',required=True);parser.add_argument('--owned-container',default='zerotrust-qualification-control-plane');args=parser.parse_args()
    binary=str(Path(args.binary).resolve());namespace='owned-sum-source-'+secrets.token_hex(5)
    prefix=['docker','exec','-i',args.owned_container,'kubectl','--kubeconfig','/etc/kubernetes/admin.conf']
    def kubectl(*words,document=None):
        result=subprocess.run(prefix+list(words),input=None if document is None else json.dumps(document),text=True,capture_output=True,timeout=20)
        if result.returncode:raise RuntimeError('owned Kubernetes fixture command failed')
        return result.stdout
    os.umask(0o077)
    kubectl('create','namespace',namespace)
    try:
        objects=[{'apiVersion':'v1','kind':'ServiceAccount','metadata':{'name':'reader','namespace':namespace}},
                 {'apiVersion':'rbac.authorization.k8s.io/v1','kind':'Role','metadata':{'name':'reader','namespace':namespace},'rules':[{'apiGroups':['networking.k8s.io'],'resources':['networkpolicies'],'verbs':['list']}]},
                 {'apiVersion':'rbac.authorization.k8s.io/v1','kind':'RoleBinding','metadata':{'name':'reader','namespace':namespace},'subjects':[{'kind':'ServiceAccount','name':'reader','namespace':namespace}],'roleRef':{'apiGroup':'rbac.authorization.k8s.io','kind':'Role','name':'reader'}},
                 {'apiVersion':'networking.k8s.io/v1','kind':'NetworkPolicy','metadata':{'name':'default-deny','namespace':namespace},'spec':{'podSelector':{},'policyTypes':['Ingress']}}]
        kubectl('create','-f','-',document={'apiVersion':'v1','kind':'List','items':objects})
        token=kubectl('create','token','reader','-n',namespace,'--duration=600s').strip()
        kubeconfig=json.loads(kubectl('config','view','--raw','-o','json'))
        ca=base64.b64decode(kubeconfig['clusters'][0]['cluster']['certificate-authority-data'])
        address=subprocess.check_output(['docker','port',args.owned_container,'6443/tcp'],text=True).strip().splitlines()[0]
        if not address.startswith('127.0.0.1:'):raise RuntimeError('owned API must be loopback')
        with tempfile.TemporaryDirectory(prefix='owned-sum-source-') as root:
            root=Path(root);(root/'ca.pem').write_bytes(ca)
            config={'api':'https://'+address,'namespace':namespace,'ca':str(root/'ca.pem'),'token_env':'OWNED_SUM_SOURCE_TOKEN'}
            path=root/'source.json';path.write_text(json.dumps(config))
            def observe(secret):
                return subprocess.run([binary,'--observe-kubernetes-policy',str(path)],env=dict(os.environ,OWNED_SUM_SOURCE_TOKEN=secret),capture_output=True,text=True,timeout=5)
            result=observe(token)
            if result.returncode:raise RuntimeError('owned authenticated source compilation failed')
            report=json.loads(result.stdout)
            if report.get('policies')!=1 or report.get('activated') is not False:raise RuntimeError('source report mismatch')
            extra=[{'apiVersion':'networking.k8s.io/v1','kind':'NetworkPolicy',
                    'metadata':{'name':'page-policy-'+str(index),'namespace':namespace},
                    'spec':{'podSelector':{},'policyTypes':['Ingress']}} for index in range(128)]
            kubectl('create','-f','-',document={'apiVersion':'v1','kind':'List','items':extra})
            page=json.loads(kubectl('get','--raw','/apis/networking.k8s.io/v1/namespaces/'+namespace+'/networkpolicies?limit=128'))
            if len(page.get('items',[]))!=128 or not page.get('metadata',{}).get('continue'):
                raise RuntimeError('owned API pagination was not exercised')
            result=observe(token)
            if result.returncode or json.loads(result.stdout).get('policies')!=129:
                raise RuntimeError('actual complete paginated collection failed')
            paginated_revision=json.loads(result.stdout)['resource_version']
            old=json.loads(kubectl('get','networkpolicy','default-deny','-n',namespace,'-o','json'))
            kubectl('delete','networkpolicy','default-deny','-n',namespace)
            result=observe(token)
            if result.returncode or json.loads(result.stdout).get('policies')!=128:
                raise RuntimeError('policy deletion missing from next collection')
            kubectl('create','-f','-',document=objects[-1])
            new=json.loads(kubectl('get','networkpolicy','default-deny','-n',namespace,'-o','json'))
            if old['metadata']['uid']==new['metadata']['uid']:
                raise RuntimeError('owned policy UID did not change on recreation')
            result=observe(token)
            if result.returncode or json.loads(result.stdout).get('policies')!=129 or json.loads(result.stdout).get('resource_version')==paginated_revision:
                raise RuntimeError('policy recreation missing from next collection')
            if observe('owned-invalid-token').returncode==0:raise RuntimeError('invalid token accepted')
            config['namespace']='default';path.write_text(json.dumps(config))
            if observe(token).returncode==0:raise RuntimeError('namespace RBAC boundary bypass')
            config['namespace']=namespace;path.write_text(json.dumps(config))
            deleting={'apiVersion':'networking.k8s.io/v1','kind':'NetworkPolicy',
                'metadata':{'name':'deleting-policy','namespace':namespace,'finalizers':['example.test/owned-qualification']},
                'spec':{'podSelector':{},'ingress':[{}]}}
            kubectl('create','-f','-',document=deleting)
            try:
                kubectl('delete','networkpolicy','deleting-policy','-n',namespace,'--wait=false')
                item=json.loads(kubectl('get','networkpolicy','deleting-policy','-n',namespace,'-o','json'))
                if not item['metadata'].get('deletionTimestamp'):raise RuntimeError('owned deletion boundary not exercised')
                if observe(token).returncode==0:raise RuntimeError('deleting source policy accepted')
            finally:
                kubectl('patch','networkpolicy','deleting-policy','-n',namespace,'--type=merge','-p','{"metadata":{"finalizers":[]}}')

            admin=secrets.token_hex(32);collector=secrets.token_hex(32)
            with socket.socket() as listener:
                listener.bind(('127.0.0.1',0));port=listener.getsockname()[1]
            with (root/'server.log').open('wb') as log:
                process=subprocess.Popen([binary,'--listen','127.0.0.1:'+str(port),'--database',str(root/'server.sqlite3'),'--kubernetes-policy-source',str(path)],
                    env=dict(os.environ,OWNED_SUM_SOURCE_TOKEN=token,OWNED_SUM_BAD_TOKEN='owned-invalid-token',HANGANG_GUARD_ADMIN_TOKEN=admin,HANGANG_GUARD_COLLECTOR_TOKEN=collector),stdout=log,stderr=log)
                try:
                    def call(endpoint,credential=admin,body=None):
                        request=urllib.request.Request('http://127.0.0.1:'+str(port)+endpoint,
                            headers={'Authorization':'Bearer '+credential,'Content-Type':'application/json'},
                            data=None if body is None else json.dumps(body).encode())
                        try:
                            with urllib.request.urlopen(request,timeout=1) as response:return response.status,json.load(response)
                        except urllib.error.HTTPError as error:return error.code,json.load(error)
                    query={'namespace':namespace,'labels':{},'direction':'Ingress','peer':'192.0.2.1','protocol':'TCP','port':443}
                    def wait_for_decision():
                        deadline=time.monotonic()+5
                        while time.monotonic()<deadline:
                            if process.poll() is not None:raise RuntimeError('owned follower server exited')
                            try:
                                status,body=call('/v1/kubernetes/evaluate',body=query)
                                if status==200 and body.get('decision')=='denied' and body.get('activated') is False:return
                            except OSError:pass
                            time.sleep(.05)
                        raise RuntimeError('owned follower did not publish diagnostic candidate')
                    wait_for_decision()
                    if call('/v1/kubernetes/status',credential='owned-invalid-admin')[0]!=401:raise RuntimeError('follower admin authentication bypass')
                    config['token_env']='OWNED_SUM_BAD_TOKEN'
                    replacement=root/'replacement.json';replacement.write_text(json.dumps(config));replacement.replace(path)
                    time.sleep(1.1)
                    for _ in range(8):
                        if call('/v1/kubernetes/evaluate',body=query)[0]!=503:raise RuntimeError('follower retained authority after source failure')
                        status,body=call('/v1/kubernetes/status')
                        if status!=503 or body.get('state') not in ['failed','collecting'] or body.get('activated') is not False:
                            raise RuntimeError('follower failure state missing or misleading')
                        time.sleep(.1)
                    config['token_env']='OWNED_SUM_SOURCE_TOKEN';replacement.write_text(json.dumps(config));replacement.replace(path)
                    wait_for_decision()
                finally:
                    process.terminate()
                    try:process.wait(timeout=5)
                    except subprocess.TimeoutExpired:process.kill();process.wait(timeout=5)
        print('PASS: actual namespaced CA-pinned 129-policy pagination, deletion/UID recreation/deletion-in-progress refusal, invalid-token/RBAC refusal and live follower withdrawal/recovery/admin boundary; no activation')
    finally:
        kubectl('delete','namespace',namespace,'--wait=false')
if __name__=='__main__':main()
