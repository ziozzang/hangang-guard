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
        policy_cases = [
            ('default-ingress-deny', {'podSelector': {}}, 'Ingress', 'TCP', 443, 'denied'),
            ('default-egress-open', {'podSelector': {}}, 'Egress', 'TCP', 443, 'not_isolated'),
            ('explicit-egress-deny', {'podSelector': {}, 'policyTypes': ['Egress']}, 'Egress', 'TCP', 443, 'denied'),
            ('empty-rule-allows', {'podSelector': {}, 'ingress': [{}]}, 'Ingress', 'UDP', 53, 'allowed'),
            ('port-default-tcp', {'podSelector': {}, 'ingress': [{'ports': [{'port': 443}]}]}, 'Ingress', 'TCP', 443, 'allowed'),
            ('port-protocol-mismatch', {'podSelector': {}, 'ingress': [{'ports': [{'port': 443}]}]}, 'Ingress', 'UDP', 443, 'denied'),
            ('cidr-exception', {'podSelector': {}, 'ingress': [{'from': [{'ipBlock': {'cidr': '192.0.2.0/24', 'except': ['192.0.2.64/26']}}]}]}, 'Ingress', 'TCP', 443, 'denied'),
            ('range-boundary', {'podSelector': {}, 'ingress': [{'ports': [{'port': 443, 'endPort': 444}]}]}, 'Ingress', 'TCP', 444, 'allowed'),
        ]
        for label, spec, direction, protocol, port, expected in policy_cases:
            document = {'apiVersion': 'networking.k8s.io/v1', 'kind': 'NetworkPolicy',
                        'metadata': {'name': 'owned-policy-evaluation', 'namespace': 'default'}, 'spec': spec}
            api = subprocess.run(['docker', 'exec', '-i', args.owned_container,
                                  'kubectl', '--kubeconfig', '/etc/kubernetes/admin.conf',
                                  'create', '--dry-run=server', '-f', '-', '-o', 'json'],
                                 input=json.dumps(document), text=True, capture_output=True, timeout=15)
            if api.returncode:
                raise RuntimeError('owned API rejected policy fixture: ' + label)
            policy = json.loads(api.stdout)
            path.write_text(json.dumps({'policy': policy, 'namespace': 'default', 'labels': {},
                                        'direction': direction, 'peer': '192.0.2.70',
                                        'protocol': protocol, 'port': port}))
            result = subprocess.run([binary, '--evaluate-kubernetes-policy', str(path)],
                                    text=True, capture_output=True, timeout=5)
            if result.returncode or result.stdout.strip() != expected:
                raise RuntimeError('API-defaulted policy evaluation mismatch: ' + label)
        invalid_peers = [
            ('empty-peer', {}),
            ('ipblock-with-selector', {'ipBlock': {'cidr': '192.0.2.0/24'}, 'podSelector': {}}),
        ]
        for label, peer in invalid_peers:
            document = {'apiVersion': 'networking.k8s.io/v1', 'kind': 'NetworkPolicy',
                        'metadata': {'name': 'owned-policy-invalid-peer', 'namespace': 'default'},
                        'spec': {'podSelector': {}, 'ingress': [{'from': [peer]}]}}
            api = subprocess.run(['docker', 'exec', '-i', args.owned_container,
                                  'kubectl', '--kubeconfig', '/etc/kubernetes/admin.conf',
                                  'create', '--dry-run=server', '-f', '-', '-o', 'json'],
                                 input=json.dumps(document), text=True, capture_output=True, timeout=15)
            if api.returncode == 0 or 'invalid' not in api.stderr:
                raise RuntimeError('owned API did not validate malformed peer: ' + label)
            path.write_text(json.dumps({'policy': document, 'namespace': 'default', 'labels': {},
                                        'direction': 'Ingress', 'peer': '192.0.2.70',
                                        'protocol': 'TCP', 'port': 443}))
            local = subprocess.run([binary, '--evaluate-kubernetes-policy', str(path)],
                                   capture_output=True, timeout=5)
            if local.returncode == 0:
                raise RuntimeError('malformed peer accepted locally: ' + label)
    print('PASS: 12 selector syntax cases and 8 API-defaulted policy evaluations and 2 malformed peer rejections; no objects persisted; CNI enforcement not qualified')



if __name__ == '__main__':
    main()
