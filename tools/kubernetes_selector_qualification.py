#!/usr/bin/env python3
"""Compare owned-cluster server dry-run with Sumunjang's offline selector parser.
No Kubernetes object is persisted; no operational credentials are emitted.
"""
import argparse
import json
import subprocess
import tempfile
from pathlib import Path


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--binary', required=True)
    parser.add_argument('--owned-container', default='zerotrust-qualification-control-plane')
    args = parser.parse_args()
    binary = str(Path(args.binary).resolve())
    cases = [
        ('basic', 'role', 'client', True),
        ('empty-value', 'role', '', True),
        ('qualified', 'app.example.test/Role_1', 'Client_1', True),
        ('long-dns-component', 'a' * 64 + '/role', 'client', True),
        ('max-prefix', 'a' * 253 + '/role', 'client', True),
        ('oversize-prefix', 'a' * 254 + '/role', 'client', False),
        ('uppercase-prefix', 'UPPER.test/role', 'client', False),
        ('empty-dns-component', 'a..test/role', 'client', False),
        ('extra-slash', 'a/b/c', 'client', False),
        ('oversize-name', 'a' * 64, 'client', False),
        ('invalid-value', 'role', 'bad value', False),
        ('unicode-value', 'role', 'é', False),
    ]
    with tempfile.TemporaryDirectory(prefix='owned-sumunjang-selector-') as root:
        path = Path(root) / 'selector.json'
        for label, key, value, expected in cases:
            selector = {'matchLabels': {key: value}}
            document = {'apiVersion': 'networking.k8s.io/v1', 'kind': 'NetworkPolicy',
                        'metadata': {'name': 'owned-selector-validation', 'namespace': 'default'},
                        'spec': {'podSelector': selector, 'policyTypes': ['Ingress']}}
            api = subprocess.run(['docker', 'exec', '-i', args.owned_container,
                                  'kubectl', '--kubeconfig', '/etc/kubernetes/admin.conf',
                                  'create', '--dry-run=server', '-f', '-', '-o', 'name'],
                                 input=json.dumps(document), text=True, capture_output=True, timeout=15)
            path.write_text(json.dumps(selector))
            local = subprocess.run([binary, '--check-kubernetes-selector', str(path)],
                                   capture_output=True, timeout=5)
            if (api.returncode == 0) != expected or (local.returncode == 0) != expected:
                raise RuntimeError('selector acceptance mismatch: ' + label)
    print('PASS: 12 selector syntax cases agree with owned Kubernetes server dry-run; no objects persisted')


if __name__ == '__main__':
    main()
