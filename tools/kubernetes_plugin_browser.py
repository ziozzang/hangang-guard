import pathlib, argparse
from playwright.sync_api import sync_playwright
parser=argparse.ArgumentParser();parser.add_argument('--chromium',required=True);args=parser.parse_args()
root=pathlib.Path(__file__).resolve().parents[1]/'plugins/guard'
with sync_playwright() as p:
 browser=p.chromium.launch(headless=True,executable_path=args.chromium)
 page=browser.new_page();errors=[];page.on('pageerror',lambda e:errors.append(str(e)))
 page.route('http://owned.example.test/',lambda route:route.fulfill(content_type='text/html',body='<html lang="en"><body><div id="root"></div></body></html>'))
 for name,mime in [('index.js','text/javascript'),('panel.html','text/html')]:
  page.route('http://owned.example.test/'+name,lambda route,request,name=name,mime=mime:route.fulfill(content_type=mime,body=(root/name).read_text()))
 page.goto('http://owned.example.test/')
 page.evaluate('''async()=>{const module=await import('/index.js');window.nativeOwned=false;window.nativeAvailable=true;window.offline=false;window.conflict=false;window.unknown=false;window.hold=false;window.refreshFail=false;window.calls=[];window.plugin=await module.mount({root:document.querySelector('#root'),asset:name=>fetch('/'+name),signal:new AbortController().signal,locale:()=>document.documentElement.lang,api:async(path,options)=>{calls.push({path,options});if(path==='policy/document'){if(options.method==='PUT'){if(conflict)throw Object.assign(Error('policy revision conflict; draft preserved.'),{status:409});if(unknown)throw Object.assign(Error('backend unavailable'),{status:unknown==='network'?undefined:503});if(hold)await new Promise(resolve=>window.releasePolicy=resolve);if(!options.json.expected_revision.startsWith('epoch:'))throw Error('wrong revision');return {data:{revision:'epoch:2',policy:options.json.policy}};}return {data:{revision:'epoch:1',policy:{mode:'observe',auto_block:false,window_secs:60,threshold:10,block_ttl_secs:900,allow:[],weights:{honeypot:10,scanner:5,auth_failure:1,invalid_request:2}}}};}if(path==='status'&&refreshFail)throw Error('refresh unavailable');if(path==='candidates'||path==='blocks')return {data:[]};if(path==='kubernetes/authority')return {data:{enabled:nativeOwned,available:nativeAvailable,remaining_ms:nativeAvailable?800:0,resource_version:'opaque-native'}};if(path.startsWith('kubernetes/')){if(offline)throw Error('source failed');return {data:path.endsWith('status')?{mode:'observe',fresh:true,policies:129,activated:false}:{decision:'denied',resource_version:'opaque',activated:false}};}return {data:{}};}});}''')
 page.locator('#tab-policy').click();page.locator('#policy-threshold').fill('77')
 page.evaluate('conflict=true');page.locator('#policy-form button[type=submit]').click()
 page.locator('#message').filter(has_text='conflict').wait_for()
 assert page.locator('#policy-threshold').input_value()=='77'
 assert page.locator('#policy-dirty').inner_text()
 assert page.evaluate("calls.filter(c=>c.options.method==='PUT').length") == 1
 assert page.evaluate("calls.filter(c=>c.path==='policy').length") == 0
 page.evaluate('conflict=false');page.locator('#policy-form button[type=submit]').click()
 page.locator('#message').filter(has_text='정책을 저장').wait_for()
 assert page.locator('#policy-dirty').inner_text()==''
 page.locator('#policy-threshold').fill('88');page.evaluate('hold=true;refreshFail=true')
 page.locator('#policy-form button[type=submit]').click()
 page.wait_for_function('window.releasePolicy !== undefined')
 for selector in ['#policy-threshold','#policy-mode','#policy-auto','#allow-network','#allow-text','#policy-json']:
  assert page.locator(selector).is_disabled()
 page.evaluate('releasePolicy()')
 page.locator('#message').filter(has_text='Change accepted; current-state refresh failed').wait_for()
 assert page.locator('#policy-threshold').input_value()=='88'
 assert page.locator('#policy-dirty').inner_text()==''
 page.evaluate('hold=false;refreshFail=false;unknown=true');page.locator('#policy-threshold').fill('99')
 page.locator('#policy-form button[type=submit]').click();page.locator('#message').filter(has_text='Outcome unknown').wait_for()
 assert page.locator('#policy-threshold').input_value()=='99'
 assert page.locator('#policy-form button[type=submit]').is_disabled()
 assert page.locator('#allow-save').is_disabled()
 before=page.evaluate("calls.filter(c=>c.options.method==='PUT').length")
 page.locator('#policy-form').evaluate("form=>form.dispatchEvent(new Event('submit',{cancelable:true}))")
 assert page.evaluate("calls.filter(c=>c.options.method==='PUT').length")==before
 page.evaluate('unknown=false');page.locator('#policy-reload').click()
 page.locator('#message').filter(has_text='저장된 정책을 불러').wait_for()
 assert not page.locator('#policy-form button[type=submit]').is_disabled()
 page.locator('#tab-allow').click();page.locator('#allow-network').fill('203.0.113.9/32')
 page.locator('#allow-form button[type=submit]').click();page.evaluate("unknown='network'")
 page.locator('#allow-save').click();page.locator('#message').filter(has_text='Outcome unknown').wait_for()
 assert '203.0.113.9/32' in page.locator('#allow-rows').inner_text()
 assert page.locator('#allow-dirty').inner_text()
 assert page.locator('#allow-save').is_disabled()
 page.evaluate('unknown=false');page.locator('#tab-policy').click();page.locator('#policy-reload').click()
 page.locator('#message').filter(has_text='저장된 정책을 불러').wait_for()
 page.locator('#policy-threshold').fill('66')
 page.locator('#tab-allow').click();page.locator('#allow-network').fill('203.0.113.9/32')
 page.locator('#allow-form button[type=submit]').click();page.evaluate('hold=true;refreshFail=true;delete window.releasePolicy')
 page.locator('#allow-save').click();page.wait_for_function('window.releasePolicy !== undefined')
 assert page.locator('#policy-threshold').is_disabled()
 assert page.locator('#allow-text').is_disabled()
 page.evaluate('releasePolicy()');page.locator('#message').filter(has_text='Change accepted; current-state refresh failed').wait_for()
 assert page.locator('#policy-threshold').input_value()=='66'
 assert page.locator('#policy-dirty').inner_text()
 assert page.locator('#allow-dirty').inner_text()==''
 page.evaluate('hold=false;refreshFail=false')
 page.locator('#tab-kubernetes').click();page.locator('#kubernetes-status').click();page.wait_for_function("document.querySelector('#kubernetes-source-result').textContent.includes('129')")
 page.locator('#kubernetes-namespace').fill('example');page.locator('#kubernetes-peer').fill('192.0.2.1');page.locator('#kubernetes-query button').click();page.wait_for_function("document.querySelector('#kubernetes-query-result').textContent.includes('denied')")
 page.evaluate('offline=true');page.locator('#kubernetes-status').click();page.wait_for_function("document.querySelector('#kubernetes-source-result').textContent.includes('source failed')")
 page.evaluate("document.documentElement.lang='ko'");page.wait_for_function("document.querySelector('#kubernetes-status').textContent==='원천 상태 새로고침'")
 page.evaluate('offline=false;nativeOwned=true')
 page.locator('#refresh').click()
 page.wait_for_function("document.querySelector('#native-authority-status').textContent.includes('opaque-native')")
 for selector in ['#policy-form button[type=submit]','#allow-save','#rules-save','#lua-save','#block-form button[type=submit]','#geoip-reload']:
  assert page.locator(selector).is_disabled(),selector
 page.evaluate('nativeAvailable=false');page.locator('#refresh').click()
 page.wait_for_function("document.querySelector('#native-authority-status').textContent.includes('unavailable')")
 assert page.locator('#rules-save').is_disabled()
 assert not errors,errors
 page.evaluate('plugin.dispose()');assert page.locator('#root').inner_text()==''
 browser.close()
print('PASS: actual Chromium plugin mount, policy/allow CAS, pending input freeze, accepted-refresh-failure, unknown replay block, Kubernetes status/query, unavailable-state replacement, Korean switch, native authority freshness/manual mutation lock and disposal; mocked context API')
