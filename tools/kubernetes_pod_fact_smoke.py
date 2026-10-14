#!/usr/bin/env python3
"""Read-only parsing qualification using an explicitly authorized kubectl wrapper."""
import argparse,json,os,subprocess,tempfile
from urllib.parse import quote
from pathlib import Path

parser=argparse.ArgumentParser();parser.add_argument('--binary',required=True);parser.add_argument('--kubectl',required=True);parser.add_argument('--namespace',required=True);args=parser.parse_args()
os.umask(0o077)
wrapper=str(Path(args.kubectl).resolve());binary=str(Path(args.binary).resolve())
def read(*words):
    result=subprocess.run([wrapper,*words],capture_output=True,text=True,timeout=20)
    if result.returncode:raise RuntimeError('authorized source read failed')
    return json.loads(result.stdout)
namespace=read('get','--raw','/api/v1/namespaces?fieldSelector='+quote('metadata.name='+args.namespace,safe=''))
pods=read('get','--raw','/api/v1/namespaces/'+quote(args.namespace,safe='')+'/pods')
if len(namespace.get('items',[]))!=1 or not pods.get('items'):raise RuntimeError('qualification requires one existing namespace and live Pods')
with tempfile.TemporaryDirectory(prefix='owned-pod-facts-')as root:
    path=Path(root)/'facts.json';path.write_text(json.dumps({'namespaces':namespace,'pods':pods}))
    result=subprocess.run([binary,'--check-kubernetes-pod-facts',str(path)],capture_output=True,text=True,timeout=5)
    if result.returncode:raise RuntimeError('actual API fact parsing refused')
    report=json.loads(result.stdout)
    if report.get('pods')!=len(pods['items']) or report.get('coherence_qualified') is not False or report.get('activated') is not False:raise RuntimeError('fact report mismatch')
print('PASS: actual NamespaceList/PodList parsing, UID association and Pod IP consistency; read-only; no coherence or enforcement activation claim')
