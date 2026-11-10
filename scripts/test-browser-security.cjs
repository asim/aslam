// Run with jsdom available in NODE_PATH (npm install --prefix /tmp/aslam-tests jsdom).
const {JSDOM} = require('jsdom');
const fs = require('node:fs');
const vm = require('node:vm');
const assert = require('node:assert/strict');
const root = require('node:path').join(__dirname, '../internal/server/html/');
const dom = new JSDOM('<!DOCTYPE html><body></body>', {runScripts:'outside-only', url:'https://aslam.org'});
const w = dom.window;
w.eval(fs.readFileSync(root+'purify.min.js','utf8'));
w.eval(fs.readFileSync(root+'marked.js','utf8'));
const chat = fs.readFileSync(root+'chat.html','utf8');
const helper = chat.slice(chat.indexOf('function safeMarkdown('), chat.indexOf('function isNearBottom('));
w.eval(helper);
for (const payload of ['<img src=x onerror=alert(1)>','[click](javascript:alert%281%29)','<svg onload=alert(1)>','<a href="data:text/html,test">bad</a>','<iframe srcdoc="<script>alert(1)</script>"></iframe>']) {
 const node = w.document.createElement('div'); node.innerHTML = w.safeMarkdown(payload);
 assert.equal(node.querySelector('script,iframe,img,svg'),null);
 for (const el of node.querySelectorAll('*')) for (const attr of el.attributes) {
  assert.ok(!/^on/i.test(attr.name)); assert.ok(!/^(javascript|data):/i.test(attr.value));
 }
}
const el = w.document.createElement('div'); el.className = 'linkify';
el.textContent = 'https://example.com/" onmouseover=alert(1) <img src=x onerror=alert(2)>';
w.document.body.append(el);
w.eval(fs.readFileSync(root+'app.js','utf8'));w.document.dispatchEvent(new w.Event('DOMContentLoaded'));
assert.equal(el.querySelector('img,[onmouseover]'),null);dom.window.close();
const handlers = {};
vm.runInNewContext(fs.readFileSync(root+'sw.js','utf8'), {URL, self:{location:{origin:'https://aslam.org'},addEventListener:(name,fn)=>handlers[name]=fn}});
for (const path of ['/profile/api-keys','/chat/1','/api/profile','/notes','/auth/callback','/quran/2']) {
 let intercepted = false;
 handlers.fetch({request:{method:'GET',url:'https://aslam.org'+path},respondWith:()=>{intercepted=true}});
 assert.equal(intercepted,false,path);
}
console.log('Browser rendering and private-cache boundary tests passed');
