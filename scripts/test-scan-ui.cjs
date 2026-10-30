// Execute production functions with reordered responses and ignored aborts.
const fs=require('node:fs'),vm=require('node:vm'),path=require('node:path'),assert=require('node:assert/strict');
const {createDOM}=require('./ui-test-dom.cjs');
const asset=name=>fs.readFileSync(path.join(__dirname,'../pkg/cmd/analyzer/web/assets',name),'utf8');
const source=asset('app.js'),{document,ids}=createDOM(asset('index.html'));
const deferred=[],streams=[],messages=[],created=[];
let finalCalls=0;
class EventSource {
 constructor(url){this.url=url;this.handlers={};streams.push(this);}
 addEventListener(name,fn){this.handlers[name]=fn;}
 close(){this.closed=true;}
 emit(name,data){(name==='message'?this.onmessage:this.handlers[name])?.({data});}
}
const context={document,AbortController,URL,EventSource,FormData:class{append(){}},CustomEvent:class{constructor(type,opts){this.type=type;this.detail=opts.detail;}},
 window:{innerWidth:1200,dispatchEvent:e=>created.push(e),matchMedia:()=>({matches:false})},setTimeout:fn=>1,clearTimeout(){},setInterval:()=>1,clearInterval(){},
 MODES:{full:{report:true},decode:{report:false}},curMode:'full',sf:{name:'test.js'},sf2:null,jid:null,ptmr:null,curOut:'',running:false,uiLang:'en',
 uploadAbort:null,scanGeneration:0,resultRequest:0,resultAbort:null,artifactAbort:null,closeScanStream:null,sbxRunSerial:0,
 SO:['CRITICAL','HIGH','MEDIUM','LOW','INFO'],SC:{},e:String,fmtSize:n=>String(n),log:ids.log||document.createElement('div'),
 bldFlags:()=>[],syncWorkspaceUI(){},syncEnvRow(){},cleanupSbxDashboard(){},liveStop(){},refreshBtn(){},show(){},lp:s=>messages.push(s),ll:s=>messages.push(s),lc:()=>'',
 _sbxStopped:false,loadFinal:()=>finalCalls++,
 fetch:(url,opts)=>new Promise((resolve,reject)=>deferred.push({url,opts,resolve,reject}))};
vm.createContext(context);
function section(start,end){vm.runInContext(source.slice(source.indexOf(start),source.indexOf(end,source.indexOf(start))),context);}
section('function preferredScrollBehavior()','function uiText(');
section('function scanIsCurrent','var curEnv=');
section('function run(){','// ── Sandbox Live Detonation Dashboard State');
section('function bundleResultSummary','// ── live android view');
section('function loadArtifacts(id){','function syncStaticOutputFlags');
const tick=()=>new Promise(r=>setImmediate(r));
const answer=async(req,data)=>{req.resolve({ok:true,json:async()=>data});await tick();};
const pending=url=>deferred.findLast(r=>r.url===url);
const own=id=>{context.invalidateScanView();context.curMode='full';context.jid=id;context.curOut='output/'+id;};
(async()=>{
 own('A');context.loadRes('A');const oldResult=pending('/api/result/A'),oldFiles=deferred.findLast(r=>r.url.startsWith('/api/artifacts/A'));
 own('B');context.loadRes('B');
 await answer(pending('/api/result/B'),{findings:[{severity:'HIGH',title:'Result B'}]});const expected=ids.fw.innerHTML;
 await answer(oldResult,{findings:[{severity:'CRITICAL',title:'Result A'}]});assert.equal(ids.fw.innerHTML,expected);assert.equal(ids.openbtn.href,'/api/report/B');
 await answer(oldFiles,{files:[],done:true,exit_code:1,reports:{'REPORT.html':false}});assert.equal(ids.fw.innerHTML,expected);
 const currentFiles=deferred.findLast(r=>r.url.startsWith('/api/artifacts/B'));
 await answer(currentFiles,{files:[{path:'A.txt',size:1}],truncated:true,next_offset:2000,done:true,reports:{'REPORT.html':true},archive_limit:200000});
 assert.equal(ids.openbtn.style.display,'');const wrap=document.getElementById('artifactResults');
 const next=wrap.querySelectorAll('button').find(b=>b.textContent==='Next');assert.ok(next);next.dispatchEvent({type:'click'});
 assert.ok(deferred.at(-1).url.includes('offset=2000'));
 const page=deferred.at(-1);await answer(page,{files:[{path:'REPORT.html',size:10}],truncated:false,next_offset:2001,done:true,reports:{'REPORT.html':true}});
 const input=wrap.querySelector('input');input.value='REPORT';wrap.querySelector('form').dispatchEvent({type:'submit'});assert.ok(deferred.at(-1).url.includes('q=REPORT'));
 await answer(deferred.at(-1),{files:[],reports:{'REPORT.html':true}});assert.equal(ids.openbtn.style.display,'');
 // A failed obsolete request must not erase B's preview either.
 own('C');context.loadRes('C');const failed=pending('/api/result/C');own('D');context.loadRes('D');
 await answer(pending('/api/result/D'),{findings:[{severity:'HIGH',title:'Result D'}]});const latest=ids.fw.innerHTML;failed.reject(Error('late failure'));await tick();assert.equal(ids.fw.innerHTML,latest);
 // Stale SSE message, done and reconnect callbacks cannot affect a new scan.
 own('stream-A');context.running=true;context.streamEvt('stream-A');const a=streams.at(-1);
 own('stream-B');context.running=true;context.streamEvt('stream-B');const b=streams.at(-1),count=messages.length;
 a.emit('message','old output');a.emit('done','0');a.onerror();assert.equal(messages.length,count);assert.equal(context.running,true);assert.equal(finalCalls,0);
 b.emit('gap','{"from":0,"to":10}');assert.match(messages.at(-1),/10 earlier lines/);
 b.emit('done','0');assert.equal(context.running,false);assert.equal(finalCalls,1);
 // A late upload response must be stopped without adopting its job ID.
 own('before-upload');context.running=false;context.run();const upload=pending('/api/scan');
 context.invalidateScanView();context.curMode='decode';context.jid='new-job';context.running=true;
 await answer(upload,{id:'obsolete-upload',output:'wrong'});assert.equal(context.jid,'new-job');assert.equal(context.running,true);
 assert.ok(deferred.some(r=>r.url==='/api/stop/obsolete-upload'));assert.equal(created.length,0);
 // A stopped sandbox still has a collected report; a cancelled static scan does not.
 own('stopped-static');context.running=true;context.streamEvt('stopped-static');const stoppedStatic=streams.at(-1);
 stoppedStatic.emit('state','stopped');stoppedStatic.emit('done','130');assert.equal(finalCalls,1);
 Object.assign(context,{sbxFailure:null,sbxOutcome:'',appendConsole(){},sbxEngineLog(){},captureSandboxFailure:data=>{context.sbxFailure=data;}});
 context.MODES.sandbox={report:true};own('stopped-sandbox');context.curMode='sandbox';context.running=true;context.streamEvt('stopped-sandbox');const stoppedSandbox=streams.at(-1);
 stoppedSandbox.emit('state','stopped');stoppedSandbox.emit('done','130');
 assert.equal(context.sbxOutcome,'Stopped');assert.equal(context.sbxFailure,null);assert.equal(finalCalls,2);
 stoppedSandbox.emit('done','130');assert.equal(finalCalls,2);
 console.log('PASS: stale result/artifact/upload/SSE responses, stop and rerun, report visibility, pagination and search.');
})().catch(e=>{console.error(e);process.exitCode=1;});
