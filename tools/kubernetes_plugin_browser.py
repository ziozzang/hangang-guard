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
 page.evaluate('''async()=>{const module=await import('/index.js');window.offline=false;window.calls=[];window.plugin=await module.mount({root:document.querySelector('#root'),asset:name=>fetch('/'+name),signal:new AbortController().signal,locale:()=>document.documentElement.lang,api:async(path,options)=>{calls.push({path,options});if(path==='policy')return {data:{mode:'observe',auto_block:false,window_secs:60,threshold:10,block_ttl_secs:900,allow:[],weights:{honeypot:10,scanner:5,auth_failure:1,invalid_request:2}}};if(path==='candidates'||path==='blocks')return {data:[]};if(path.startsWith('kubernetes/')){if(offline)throw Error('source failed');return {data:path.endsWith('status')?{mode:'observe',fresh:true,policies:129,activated:false}:{decision:'denied',resource_version:'opaque',activated:false}};}return {data:{}};}});}''')
 page.locator('#tab-kubernetes').click();page.locator('#kubernetes-status').click();page.wait_for_function("document.querySelector('#kubernetes-source-result').textContent.includes('129')")
 page.locator('#kubernetes-namespace').fill('example');page.locator('#kubernetes-peer').fill('192.0.2.1');page.locator('#kubernetes-query button').click();page.wait_for_function("document.querySelector('#kubernetes-query-result').textContent.includes('denied')")
 page.evaluate('offline=true');page.locator('#kubernetes-status').click();page.wait_for_function("document.querySelector('#kubernetes-source-result').textContent.includes('source failed')")
 page.evaluate("document.documentElement.lang='ko'");page.wait_for_function("document.querySelector('#kubernetes-status').textContent==='원천 상태 새로고침'")
 assert not errors,errors
 page.evaluate('plugin.dispose()');assert page.locator('#root').inner_text()==''
 browser.close()
print('PASS: actual Chromium plugin mount, Kubernetes status/query, unavailable-state replacement, Korean switch and disposal; mocked context API')
