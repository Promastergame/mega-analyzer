const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const {createDOM} = require('./ui-test-dom.cjs');
const asset = name => fs.readFileSync(path.join(__dirname, '../pkg/cmd/analyzer/web/assets', name), 'utf8');
const source = asset('app.js'), {document, ids} = createDOM(asset('index.html'));
const requests=[], timers=new Map(), clients=[];
let sequence=0;
class RFB {
  constructor(root,url,options){this.root=root;this.url=url;this.options=options;this.listeners={};clients.push(this);}
  addEventListener(name,fn){this.listeners[name]=fn;}
  blur(){this.blurred=true;}
  disconnect(){this.disconnected=true;this.listeners.disconnect?.();}
  getImageData(){return {width:640,height:480};}
  toDataURL(){return 'data:image/png;base64,last-frame';}
  sendCtrlAltDel(){this.cad=(this.cad||0)+1;}
}
const ctx={document, uiLang:'en', curMode:'sandbox', curEnv:'windows', curTarget:{key:'vmware:A'}, jid:'job-A', sbxRunSerial:1, sbxViewMode:'output', sbxViewPhase:'running', AbortController,
  location:{protocol:'http:',host:'127.0.0.1:7474'},
  isVMwareTarget:()=>ctx.curTarget?.key.startsWith('vmware:'),
  liveStart(){},liveStop(){},
  uiText:(id,text)=>ids[id].textContent=text,
  fetch:(url,options)=>new Promise((resolve,reject)=>requests.push({url,options,resolve,reject})),
  setTimeout:(fn,ms)=>{const id=++sequence;timers.set(id,{fn,ms});return id;},clearTimeout:id=>timers.delete(id)
};
vm.createContext(ctx);
vm.runInContext(source.slice(source.indexOf('function switchSbxView('),source.indexOf('function updateSbxTimerDisplay(')),ctx);
ctx.loadVMwareRFB=()=>Promise.resolve({default:RFB});
const tick=()=>new Promise(resolve=>setImmediate(resolve));
const deliver=async(req)=>{req.resolve({ok:true,json:async()=>({password:'test-VNC'})});await tick();};
(async()=>{
  ctx.syncSbxView();assert.equal(ids.sbxViewScreenBtn.disabled,false);assert.equal(requests.length,0);
  ctx.switchSbxView('screen');
  assert.equal(ids.sbxVMwareScreen.style.display,'flex');assert.equal(ids.sbxAndroidStream.style.display,'none');
  assert.equal(requests.length,1);assert.equal(requests[0].url,'/api/vmware/console-info?job=job-A');
  ctx.syncSbxView();assert.equal(requests.length,1,'re-render created duplicate console');
  await deliver(requests[0]);const first=clients.at(-1);first.listeners.connect();
  assert.equal(first.url,'ws://127.0.0.1:7474/api/vmware/console?job=job-A');
  assert.equal(first.options.credentials.password,'test-VNC');
  assert.equal(first.scaleViewport,true);assert.equal(first.focusOnClick,true);
  assert.equal(ids.vmwareConsole.hidden,false);assert.equal(ids.vmwareCtrlAltDel.disabled,false);
  ctx.vmwareSendCtrlAltDel();assert.equal(first.cad,1);
  ctx.syncSbxView();assert.equal(requests.length,1,'live console must not poll PNG screenshots');
  ctx.switchSbxView('output');assert.equal(ctx.vmwareScreenState.running,false);assert.equal(timers.size,0);
  assert.equal(first.blurred,true);assert.equal(first.disconnected,true);
  assert.equal(ids.vmwareCtrlAltDel.disabled,true);assert.equal(ids.vmwareScreenImage.hidden,false);
  const lastFrame=ids.vmwareScreenImage.src;
  ctx.vmwareSendCtrlAltDel();assert.equal(first.cad,1,'hidden console accepted keyboard input');
  ctx.switchSbxView('screen');const stale=requests.at(-1);
  ctx.sbxViewPhase='stopping';ctx.syncSbxView();assert.equal(stale.options.signal.aborted,true);
  await deliver(stale);assert.equal(clients.length,1,'late response opened a stopped console');
  assert.equal(ids.vmwareScreenImage.src,lastFrame);
  ctx.sbxViewPhase='complete';ctx.syncSbxView();assert.match(ids.vmwareScreenStatus.textContent,/Last captured frame/);
  ctx.stopVMwareScreen(false);assert.equal(ids.vmwareScreenImage.hidden,true);
  ctx.jid='job-B';ctx.sbxRunSerial++;ctx.sbxViewPhase='running';ctx.syncSbxView();
  assert.equal(requests.at(-1).url,'/api/vmware/console-info?job=job-B');
  requests.at(-1).resolve({ok:false});await tick();
  assert.match(ids.vmwareScreenStatus.textContent,/Waiting for the VMware console/);
  assert.equal(ids.vmwareScreenPlaceholder.hidden,false);
  ctx.stopVMwareScreen(false);
  ctx.curTarget={key:'host:host'};ctx.syncSbxView();assert.equal(ids.sbxViewScreenBtn.disabled,true);
  ctx.curEnv='android';ctx.syncSbxView();assert.equal(ids.sbxViewScreenBtn.disabled,false);assert.equal(ids.sbxAndroidStream.style.display,'flex');
  console.log('PASS: live VMware console, job scoping, focus/control release, Ctrl+Alt+Del, stale connections, Stop, retained frame, and Android isolation.');
})().catch(error=>{console.error(error);process.exitCode=1;});

