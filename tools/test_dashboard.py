#!/usr/bin/env python3
"""Browser regression for the embedded dashboard using exact API-shaped fixtures.

Requires Python Playwright and an existing Chromium installation; never downloads
browsers. Run: python3 tools/test_dashboard.py [--chromium /path/to/chrome]
"""
import argparse, json, threading, time, http.server, socketserver
from pathlib import Path
from playwright.sync_api import sync_playwright
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--chromium', help='Existing Chromium executable')
parser.add_argument('--screenshot', help='Optional mobile screenshot output path')
args = parser.parse_args()
PATH = Path(__file__).resolve().parents[1] / 'crates/guard-server/src/dashboard.html'
chromium = args.chromium
if not chromium:
    browsers = list((Path.home() / '.cache/ms-playwright').glob('chromium-*/chrome-linux64/chrome'))
    if browsers:
        chromium = str(max(browsers, key=lambda p: p.stat().st_mtime))

class Handler(http.server.BaseHTTPRequestHandler):

    def do_GET(self):
        body = open(PATH, 'rb').read()
        self.send_response(200)
        self.send_header('Content-Type', 'text/html')
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass
server = socketserver.TCPServer(('127.0.0.1', 0), Handler)
threading.Thread(target=server.serve_forever, daemon=True).start()
now = int(time.time())
policy = {'mode': 'observe', 'auto_block': False, 'window_secs': 60, 'threshold': 10, 'block_ttl_secs': 900, 'allow': ['192.0.2.7/32'], 'weights': {'honeypot': 10, 'scanner': 5, 'auth_failure': 1, 'invalid_request': 2}}
candidates = [{'ip': f'10.{n // 65536}.{n // 256 % 256}.{n % 256}', 'score': 10 + n % 7, 'events': 2, 'first_seen': now - 10, 'last_seen': now, 'asn': 64512, 'eligible': n % 2 == 0, 'suspicion': 'suspicious' if n % 2 == 0 else 'watch'} for n in range(10000)]
blocks = [{'network': f'172.{n // 65536}.{n // 256 % 256}.{n % 256}/32', 'reason': '<img src=x onerror=alert(1)>', 'expires_at': now + 900} for n in range(100000)]
rules = {'version': 1, 'rules': []}
bad_status = False
requests = []

def route(r):
    global policy, blocks, candidates, rules
    req = r.request
    path = req.url.split('/v1/')[1]
    body = req.post_data_json if req.post_data else None
    requests.append((path, req.method, body))
    if req.headers.get('authorization') != 'Bearer dashboard-test-token':
        r.fulfill(status=401, json={'error': 'invalid credential'})
        return
    if path == 'status' and bad_status:
        r.fulfill(status=200, body='<html>malformed API response</html>')
        return
    if path == 'status':
        data = {'health': 'ok', 'capacity': {'candidates': len(candidates), 'blocks': len(blocks), 'max_candidates': 10000, 'max_blocks': 100000}, 'stats': {'accepted': 20000, 'dropped_capacity': 3, 'block_capacity_rejections': 0}, 'metrics': {'index': 'radix'}, 'geoip': {'country': {'database_type': 'GeoLite2-Country', 'build_epoch': now, 'bytes': 4096}, 'asn': None}}
    elif path == 'update/status':
        data = {'enabled': True, 'phase': 'up_to_date', 'current_version': '0.3.0'}
    elif path == 'update/check':
        data = {'queued': True}
    elif path == 'policy':
        if req.method == 'PUT':
            policy = body
        data = policy
    elif path == 'lookup':
        data = {'ip': body['ip'], 'geoip': {'country_code': 'KR', 'country_name': '대한민국', 'asn': 64512, 'asn_organization': 'test'}, 'inspection': {'ip': body['ip'], 'score': 17, 'signal_score': 12, 'static_rule_score': 5, 'suspicion': 'suspicious', 'matched_rules': ['test-rule'], 'decision': {'version': 1, 'revision': 2, 'action': 'allow', 'mode': 'observe', 'reason': None, 'ttl_ms': 1000}}}
    elif path == 'networks/inspect':
        data = {'network': body['network'], 'score': 39, 'signal_score': 29, 'static_rule_score': 10, 'events': 6, 'unique_ips': 3, 'max_ip_score': 17, 'suspicion': 'suspicious', 'matched_rules': ['test-rule']}
    elif path == 'rules':
        if req.method == 'PUT':
            if body.get('version') != 1 or not isinstance(body.get('rules'), list):
                r.fulfill(status=400, json={'error': 'expected direct RuleSet'})
                return
            rules = body
        data = rules
    elif path == 'rules/validate':
        if 'rules' in body:
            if body['rules'].get('version') != 1:
                r.fulfill(status=400, json={'error': 'unsupported rule version'})
                return
            data = {'valid': True, 'rules': body['rules']}
        elif 'script' in body:
            if 'while true' in body['script']:
                r.fulfill(status=400, json={'error': 'Lua configuration execution budget exceeded'})
                return
            data = {'valid': True, 'rules': {'version': 1, 'rules': []}}
        else:
            r.fulfill(status=400, json={'error': 'exactly one rules or script required'})
            return
    elif path == 'rules/lua':
        rules = {'version': 1, 'rules': []}
        data = rules
    elif path == 'geoip/reload':
        data = {'geoip': {'country': {'database_type': 'GeoLite2-Country', 'build_epoch': now, 'bytes': 4096}, 'asn': None}}
    elif path == 'candidates':
        data = candidates
    elif path == 'candidates/approve':
        blocks.insert(0, {'network': body['ip'] + '/32', 'reason': 'approved', 'expires_at': now + 900})
        data = {'ok': True}
    elif path == 'blocks':
        if req.method == 'POST':
            blocks.insert(0, body)
            data = {'ok': True}
        elif req.method == 'DELETE':
            blocks = [b for b in blocks if b['network'] != body['network']]
            data = {'removed': True}
        else:
            data = blocks
    else:
        r.fulfill(status=400, json={'error': 'unexpected request'})
        return
    r.fulfill(json=data)
with sync_playwright() as p:
    browser = p.chromium.launch(headless=True, executable_path=chromium, args=['--no-sandbox'])
    page = browser.new_page(viewport={'width': 1440, 'height': 1000})
    errors = []
    page.on('pageerror', lambda e: errors.append(str(e)))
    page.route('**/v1/**', route)
    page.goto(f'http://127.0.0.1:{server.server_address[1]}')
    page.locator('#token').fill('dashboard-test-token')
    page.locator('#connect').click()
    page.locator('#message').filter(has_text='연결되었습니다').wait_for(timeout=30000)
    assert page.locator('#token').input_value() == ''
    assert page.locator('#candidates-rows tr').count() == 50
    page.locator('#candidates-controls select[aria-label="candidates 페이지 행 수"]').select_option('100')
    assert page.locator('#candidates-rows tr').count() == 100
    page.locator('#tab-policy').click()
    page.locator('#policy-threshold').fill('77')
    assert '저장하지' in page.locator('#policy-dirty').inner_text()
    page.wait_for_timeout(5500)
    assert page.locator('#policy-threshold').input_value() == '77'
    page.locator('#refresh').click()
    page.locator('#message').filter(has_text='목록을 갱신').wait_for(timeout=30000)
    assert page.locator('#policy-threshold').input_value() == '77'
    page.locator('#tab-allow').click()
    page.locator('#allow-network').fill('203.0.113.9/32')
    page.locator('#allow-form button[type=submit]').click()
    page.locator('#allow-save').click()
    page.locator('#message').filter(has_text='허용 목록을 저장').wait_for(timeout=30000)
    assert policy['threshold'] == 10 and '203.0.113.9/32' in policy['allow']
    page.locator('#tab-policy').click()
    assert page.locator('#policy-threshold').input_value() == '77'
    page.locator('#policy-mode').select_option('enforce')
    page.locator('#policy-auto').check()
    page.locator('#policy-form button[type=submit]').click()
    page.locator('#message').filter(has_text='정책을 저장').wait_for(timeout=30000)
    assert policy['threshold'] == 77 and policy['mode'] == 'enforce' and policy['auto_block']
    page.locator('#tab-candidates').click()
    page.locator('#candidates-controls input[type=search]').fill('10.0.0.0')
    page.locator('#candidates-rows button').click()
    page.locator('#message').filter(has_text='차단을 승인').wait_for(timeout=30000)
    assert any((b['network'] == '10.0.0.0/32' for b in blocks))
    page.locator('#tab-blocks').click()
    assert page.locator('#blocks-rows tr').count() <= 100
    page.locator('#network').fill('192.0.2.0/24')
    page.locator('#ttl').fill('30')
    page.locator('#reason').fill('<img src=x onerror=alert(1)>')
    page.locator('#block-form button[type=submit]').click()
    page.locator('#message').filter(has_text='수동 차단을 추가').wait_for(timeout=30000)
    page.locator('#blocks-controls input[type=search]').fill('192.0.2.0/24')
    assert page.locator('#blocks-rows tr').count() == 1
    assert page.locator('#blocks-rows img').count() == 0
    page.locator('#blocks-rows button').click()
    page.locator('#message').filter(has_text='차단을 해제').wait_for(timeout=30000)
    assert not any((b['network'] == '192.0.2.0/24' for b in blocks))
    page.locator('#tab-inspect').click()
    page.locator('#lookup-ip').fill('192.0.2.8')
    page.locator('#lookup-form button').click()
    page.locator('#message').filter(has_text='IP 위험 정보를 조회').wait_for()
    assert '의심' in page.locator('#lookup-cards').inner_text()
    assert 'KR' in page.locator('#lookup-cards').inner_text()
    assert 'AS64512' in page.locator('#lookup-cards').inner_text()
    page.locator('#inspect-network').fill('192.0.2.0/24')
    page.locator('#inspect-form button').click()
    page.locator('#message').filter(has_text='CIDR 위험 집계를 조회').wait_for()
    assert '최고 점수' in page.locator('#lookup-cards').inner_text()
    assert '17' in page.locator('#lookup-cards').inner_text()
    page.locator('#tab-rules').click()
    page.locator('#rules-load').click()
    page.locator('#message').filter(has_text='저장된 JSON 규칙을 불러').wait_for()
    draft = {'version': 1, 'rules': [{'id': 'test-rule', 'priority': 10, 'network': '192.0.2.0/24', 'countries': [], 'asns': [], 'action': 'observe', 'score': 5, 'expires_at': None, 'description': 'browser test'}]}
    page.locator('#rules-json').fill(json.dumps(draft))
    page.locator('#rules-validate').click()
    page.locator('#message').filter(has_text='JSON 규칙을 검증').wait_for()
    assert rules['rules'] == []
    page.locator('#rules-lua').fill('return { version = 1, rules = {} }')
    page.wait_for_timeout(5500)
    assert json.loads(page.locator('#rules-json').input_value()) == draft
    page.locator('#rules-save').click()
    page.locator('#message').filter(has_text='JSON 동적 규칙을 저장').wait_for()
    assert rules == draft
    assert 'Lua' in page.locator('#rules-dirty').inner_text()
    page.locator('#rules-json').fill('{invalid json')
    page.locator('#rules-validate').click()
    page.locator('#message[data-error=true]').wait_for()
    assert page.locator('#rules-json').input_value() == '{invalid json'
    page.locator('#rules-json').fill(json.dumps(draft))
    page.locator('#rules-lua').fill('while true do end')
    page.locator('#lua-validate').click()
    page.locator('#message').filter(has_text='execution budget exceeded').wait_for()
    assert page.locator('#rules-lua').input_value() == 'while true do end'
    page.locator('#rules-lua').fill('return { version = 1, rules = {} }')
    page.locator('#lua-validate').click()
    page.locator('#message').filter(has_text='Lua 규칙을 검증').wait_for()
    page.locator('#lua-save').click()
    page.locator('#message').filter(has_text='Lua 동적 규칙을 저장').wait_for()
    assert rules == {'version': 1, 'rules': []}
    assert 'JSON' in page.locator('#rules-dirty').inner_text()
    page.locator('#rules-load').click()
    page.locator('#message').filter(has_text='저장된 JSON 규칙을 불러').wait_for()
    assert 'return' in page.locator('#rules-lua').input_value()
    page.locator('#tab-update').click()
    page.locator('#update-fetch').click()
    page.locator('#update-result').filter(has_text='up_to_date').wait_for()
    page.locator('#update-check').click()
    page.locator('#update-result').filter(has_text='queued').wait_for()
    page.locator('#tab-geoip').click()
    page.locator('#geoip-status').click()
    page.locator('#message').filter(has_text='GeoIP 상태를 확인').wait_for()
    assert 'GeoLite2-Country' in page.locator('#geoip-result').inner_text()
    page.locator('#geoip-reload').click()
    page.locator('#message').filter(has_text='GeoIP 데이터베이스를 다시').wait_for()
    bad_status = True
    page.locator('#geoip-status').click()
    page.locator('#message').filter(has_text='서버 응답을 해석할 수 없습니다').wait_for()
    assert 'return' in page.locator('#rules-lua').input_value()
    bad_status = False
    page.set_viewport_size({'width': 390, 'height': 844})
    page.locator('#tab-policy').click()
    assert page.evaluate('document.documentElement.scrollWidth <= window.innerWidth')
    if args.screenshot:
        page.screenshot(path=args.screenshot, full_page=True)
    page.locator('#disconnect').click()
    assert page.evaluate('localStorage.length') == 0
    assert page.evaluate('sessionStorage.length') == 0
    page.locator('#token').fill('wrong')
    page.locator('#connect').click()
    page.locator('#message[data-error=true]').wait_for()
    assert '인증 실패' in page.locator('#message').inner_text()
    assert not errors, errors
    print(json.dumps({'browser': 'Chromium ' + browser.version, 'candidate_rows': 10000, 'block_rows': 100000, 'max_rendered_rows': 100, 'workflows': ['status polling preserves unsaved form', 'refresh preserves draft', 'allow draft/save preserves unsaved policy', 'policy save', 'candidate approve', 'block add/delete', 'XSS-safe rendering', 'mobile390px', 'memory-only credential', '401 feedback', 'IPGeoIP+risk inspection', 'CIDR evidence inspection', 'RuleSet exact API', 'Lua validation/save', 'validation errors preserve drafts', 'GeoIP status/reload', 'malformed API response preserves draft'], 'page_errors': errors}, ensure_ascii=False))
    browser.close()
server.shutdown()
