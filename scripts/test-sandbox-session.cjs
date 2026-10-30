// Real UI rendering/completion code with shutdown and legacy-report fixtures.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const app = fs.readFileSync(path.join(__dirname, '../pkg/cmd/analyzer/web/assets/app.js'), 'utf8');
const escape = value => String(value).replace(/[&<>"']/g, ch => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[ch]));
const ui = {e:escape, baseName:s=>s||'', uiLang:'en'};
vm.createContext(ui);
vm.runInContext(app.slice(app.indexOf('function sandboxCompletionMessage('), app.indexOf('var sbxTimerInterval')), ui);
vm.runInContext(app.slice(app.indexOf('function dtable('), app.indexOf('function wireTabs()')), ui);
assert.doesNotMatch(ui.sandboxCompletionMessage(''), /duration|timer/i);
assert.match(ui.sandboxCompletionMessage('duration_elapsed'), /Duration elapsed/);
assert.doesNotMatch(ui.sandboxCompletionMessage('stopped'), /duration|timer/i);
assert.match(ui.sandboxCompletionMessage('interrupted'), /incomplete/);
const report = {
  executed:true, vmware:{incomplete:true}, completion_reason:'interrupted',
  execution_error:{code:'guest_powered_off', message:'Guest powered off <unsafe>'},
  processes:[{pid:42, parent_pid:1, name:'child.exe', command_line:'child --wait'}],
  connections:[{pid:42, protocol:'TCP', remote_addr:'192.0.2.1:80'}],
  activity_count:1, activity_path:'host/activity.jsonl',
  behavior_analysis:{classification:'clean', risk_score:0}
};
const html = ui.renderSandbox(report);
assert.match(html, /INCOMPLETE REPORT/);
assert.doesNotMatch(html, /NO THREATS REPORTED/);
assert.match(html, /child\.exe/);
assert.match(html, /192\.0\.2\.1:80/);
assert.match(html, /host\/activity\.jsonl/);
assert.match(html, /&lt;unsafe&gt;/);
assert.doesNotMatch(html, /<unsafe>/);
assert.match(ui.renderSandbox({...report, execution_error:null}), /INCOMPLETE REPORT/);
ui.uiLang = 'ru';
assert.match(ui.sandboxCompletionMessage('duration_elapsed'), /таймер/);
assert.match(ui.sandboxCompletionMessage('interrupted'), /неполный/);
console.log('PASS: truthful completion causes, incomplete report observations, and escaped guest diagnostics.');
