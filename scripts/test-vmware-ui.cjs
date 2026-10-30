// Exercise the actual UI functions with reordered inspections and file reads.
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const assert = require('node:assert/strict');
const {createDOM} = require('./ui-test-dom.cjs');
const asset = name => fs.readFileSync(path.join(__dirname, '../pkg/cmd/analyzer/web/assets', name), 'utf8');
const source = asset('app.js');
const {document, ids} = createDOM(asset('index.html'));
const requests = [], timers = [];
const request = (url, options) => new Promise((resolve, reject) => requests.push({url, options, resolve, reject}));
const context = {
  document, setTimeout: fn => timers.push(fn), curTarget: null, curMode: 'sandbox', sbxViewPhase: 'setup',
  fetch: request, fetchDiscovery: request, _envPending: false, envFresh: false, envState: "idle", envError: "", ENV: null,
  refreshBtn() {}, refreshHost() {}, syncSandboxWorkbench() {},
  uiText: (id, text) => { ids[id].textContent = text; },
  buildOsMenu() { context.updateVMwarePanel(context.curTarget); },
  window: {confirm() { throw Error('unexpected confirmation'); }, prompt() { throw Error('unexpected prompt'); }},
};
vm.createContext(context);
function section(start, end) {
  const from = source.indexOf(start), to = source.indexOf(end, from);
  assert.ok(from >= 0 && to > from, `Missing production section ${start}`);
  vm.runInContext(source.slice(from, to), context);
}
section('function isVMwareTarget()', 'function stopJob()');
section('var vmwarePanelID=', 'function syncSandboxCapabilities()');
section('function refreshEnv(', 'function startEnvPoll()');
section('function sbxBusy()', 'function mountSandboxWorkbench(');
section('function sbxSetPhase(', 'function prepareSandboxWorkspace()');
const tick = () => new Promise(resolve => setImmediate(resolve));
const flush = () => { while (timers.length) timers.shift()(); };
const response = async (req, data) => { req.resolve({ok: true, json: async () => data}); await tick(); };
const report = running => ({running, suspended: false, guestExecution: true, configurationPass: true, checks: [], snapshots: [], notice: ''});
function select(key, running) {
  context.curTarget = {key, label: key === 'vmware:A' ? 'Windows A' : 'Windows B', kind: 'vm', ico: 'vmware', running, registered: true};
  context.updateVMwarePanel(context.curTarget);
}
const file = data => ({size: 256, text: async () => JSON.stringify(data)});

(async () => {
  // Shutting down the same VM invalidates its old report, preserving credentials.
  select('vmware:A', true); flush();
  await response(requests.at(-1), report(true));
  ids.vmwareUser.value = 'MegaLab'; ids.vmwarePassword.value = ' test-only-+$! ';
  assert.equal(context.vmwareExecutionReady(), true, 'a prepared running guest can restart for analysis');
  context.syncVMwareButtons();
  assert.equal(ids.vmwarePrepare.disabled, true, 'preparation still requires power off');
  assert.equal(ids.vmwareCreate.disabled, true, 'snapshots still require power off');
  context.vmwareReport.suspended = true;
  assert.equal(context.vmwareExecutionReady(), false);
  context.vmwareReport.suspended = false;
  context.vmwareReport.configurationPass = false;
  assert.equal(context.vmwareExecutionReady(), false);
  context.vmwareReport.configurationPass = true;
  select('vmware:A', false);
  assert.equal(context.vmwareReport, null);
  assert.equal(context.vmwareExecutionReady(), false);
  assert.equal(ids.vmwarePassword.value, ' test-only-+$! ');
  flush(); await response(requests.at(-1), report(false));
  assert.equal(context.vmwareExecutionReady(), true);
  const unchanged = requests.length;
  select('vmware:A', false); flush();
  assert.equal(requests.length, unchanged);

  // A power change during an inspection must queue a fresh one, not lose it.
  const first = context.vmwareAction('inspect');
  const stalePower = requests.at(-1);
  select('vmware:A', true); select('vmware:A', false); flush();
  assert.equal(requests.at(-1), stalePower);
  await response(stalePower, report(true)); await first;
  assert.equal(context.vmwareReport, null);
  flush(); assert.notEqual(requests.at(-1), stalePower);
  await response(requests.at(-1), report(false));
  assert.equal(context.vmwareExecutionReady(), true);

  // Switching guests during an inspection clears the old credentials and report.
  const oldRequest = context.vmwareAction('inspect');
  const oldVM = requests.at(-1);
  select('vmware:B', false);
  assert.equal(ids.vmwareUser.value, ''); assert.equal(ids.vmwarePassword.value, '');
  await response(oldVM, report(true)); await oldRequest; flush();
  assert.equal(JSON.parse(requests.at(-1).options.body).id, 'vmware:B');
  await response(requests.at(-1), report(false));

  // Loading the file fills the pair together and preserves password characters.
  const beforeFile = requests.length;
  await context.importVMwareCredentials(file({vm: 'Windows B', username: ' MegaLab ', password: ' test-only-+$! '}));
  assert.equal(ids.vmwareUser.value, 'MegaLab');
  assert.equal(ids.vmwarePassword.value, ' test-only-+$! ');
  assert.equal(requests.length, beforeFile);
  assert.equal(context.vmwareExecutionReady(), true);
  ids.vmwarePassword.value = ''; context.vmwareCredentialsChanged();
  assert.equal(context.vmwareExecutionReady(), false);
  assert.match(context.vmwareReadinessMessage(), /пароль/);

  // Parsing failures never echo the credential JSON, and the wrong VM is rejected.
  await context.importVMwareCredentials({size: 50, text: async () => '{"password":"DO-NOT-ECHO-this-secret",BROKEN'});
  assert.ok(!ids.vmwareCredentialStatus.textContent.includes('DO-NOT-ECHO'));
  await context.importVMwareCredentials(file({vm: 'Windows A', username: 'WrongGuest', password: 'test-only'}));
  assert.equal(ids.vmwareUser.value, 'MegaLab'); assert.equal(ids.vmwarePassword.value, '');
  assert.match(ids.vmwareCredentialStatus.textContent, /другой ВМ/);

  // A slow file read cannot undo a subsequent manual edit or a target change.
  let finishFile;
  const pendingFile = context.importVMwareCredentials({size: 50, text: () => new Promise(resolve => { finishFile = resolve; })});
  ids.vmwareUser.value = 'ManuallyEdited'; context.vmwareCredentialsChanged();
  finishFile(JSON.stringify({username: 'OldFile', password: 'test-only'})); await pendingFile;
  assert.equal(ids.vmwareUser.value, 'ManuallyEdited');
  const swappedFile = context.importVMwareCredentials({size: 50, text: () => new Promise(resolve => { finishFile = resolve; })});
  select('vmware:A', false);
  finishFile(JSON.stringify({username: 'WrongVM', password: 'test-only'})); await swappedFile;
  assert.equal(ids.vmwareUser.value, ''); assert.equal(ids.vmwarePassword.value, '');
  flush(); await response(requests.at(-1), report(false));

  // During analysis, inspections and management wait; completion rechecks state.
  const startedFile = context.importVMwareCredentials({size: 50, text: () => new Promise(resolve => { finishFile = resolve; })});
  context.sbxSetPhase('running');
  finishFile(JSON.stringify({username: 'LateFile', password: 'test-only'})); await startedFile;
  assert.equal(ids.vmwarePassword.value, '');
  assert.equal(ids.vmwareInspect.disabled, true); assert.equal(ids.vmwareLoadCredentials.disabled, true);
  const beforeRun = requests.length;
  context.vmwareInspectQueued = true; context.flushVMwareInspection(); flush();
  await context.vmwareAction('prepare');
  assert.equal(requests.length, beforeRun);
  context.sbxSetPhase('complete');
  assert.equal(context.vmwareReport, null);
  flush(); assert.equal(requests.length, beforeRun + 1);
  await response(requests.at(-1), report(false));
  assert.equal(ids.vmwareLoadCredentials.disabled, false);

  // A manual refresh rechecks unchanged power even while discovery is pending.
  context.refreshEnv();
  const discovery = requests.at(-1);
  context.refreshEnvironments(true);
  assert.equal(context.vmwareReport, null);
  flush(); assert.equal(requests.at(-1).url, '/api/vmware');
  discovery.resolve({host: {os: 'windows'}}); await tick();
  await response(requests.at(-1), report(false));
  assert.equal(context.vmwareReport.running, false);
  console.log('PASS: VMware credentials, empty-password gate, stale power/target responses, queued inspections and session completion.');
})().catch(error => { console.error(error); process.exitCode = 1; });
