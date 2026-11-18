// Run the production bridge and worker with the real WASM and browser-only FS.
const fs=require('node:fs'),path=require('node:path'),vm=require('node:vm'),assert=require('node:assert/strict'),crypto=require('node:crypto');
const {MessageChannel}=require('node:worker_threads');
const root=path.resolve(process.argv[2]||'dist/web'),staticRoot=path.join(root,'static');
const assets=name=>fs.readFileSync(path.join(staticRoot,name));
const wasm=assets('analyzer.wasm'),contexts=[];let engineLoads=0,holdWorkers=false;
class Worker {
 constructor(url){assert.equal(url,'/static/wasm-worker.js');this.timers=new Set();this.ports=[];this.dead=false;}
 terminate(){this.dead=true;for(const timer of this.timers)clearTimeout(timer);for(const port of this.ports)port.close();}
 postMessage(data){this.ports.push(...(data.ports||[]),...(data.port?[data.port]:[]));queueMicrotask(()=>{
  if(this.dead||holdWorkers)return;
  const scope={console,WebAssembly,Uint8Array,Uint32Array,DataView,TextEncoder,TextDecoder,performance,crypto:crypto.webcrypto,Blob,
   setTimeout:(fn,ms)=>{const timer=setTimeout(fn,ms);this.timers.add(timer);return timer;},clearTimeout,
   fetch:async url=>{assert.equal(url,'/static/analyzer.wasm.gz','analysis must not access the network');return new Response(wasm,{headers:{'Content-Type':'application/wasm'}});},
   postMessage:message=>{if(!this.dead)this.onmessage?.({data:message});}};
  scope.self=scope;const context=vm.createContext(scope);contexts.push(context);
  scope.importScripts=(...urls)=>{for(const url of urls){assert.ok(url.startsWith('/static/'));vm.runInContext(assets(url.slice(8)).toString(),context);}};
  vm.runInContext(assets('wasm-worker.js').toString(),context);scope.onmessage({data}).catch(error=>this.onerror?.({message:String(error)}));
 });}
}
const scope={console,WebAssembly,crypto:crypto.webcrypto,URL,Response,Blob,File,FormData,Worker,MessageChannel,EventTarget,Event,MessageEvent,DOMException,CustomEvent,TextEncoder,TextDecoder,setTimeout,clearTimeout,queueMicrotask,
 location:{href:'https://example.test/',origin:'https://example.test'},
 document:{addEventListener(){}},
 fetch:async url=>{if(url==='/static/analyzer.wasm.gz'){engineLoads++;return new Response(wasm,{headers:{'Content-Type':'application/wasm'}});}if(url==='/static/gnn.wasm.gz')return new Response(assets('gnn.wasm'),{headers:{'Content-Type':'application/wasm'}});if(url==='/static/gnn_weights.json')return new Response(assets('gnn_weights.json'));throw Error('Unexpected network request: '+url);},EventSource:class{}};
scope.window=scope;const bridge=vm.createContext(scope);vm.runInContext(assets('wasm-bridge.js').toString(),bridge);
async function scan(mode,file,flags=[],file2,options={workers:1,timeout:300}){
 const form=new FormData();form.set('mode',mode);form.set('file',file);form.set('flags',JSON.stringify(flags));if(file2)form.set('file2',file2);
 form.set('workers',String(options.workers));form.set('timeout',String(options.timeout));
 const response=await scope.fetch('/api/scan',{method:'POST',body:form});assert.ok(response.ok,await response.clone().text());const job=await response.json();
 const done=new Promise((resolve,reject)=>{const events=new scope.EventSource('/api/events/'+job.id),timer=setTimeout(()=>reject(Error('WASM test timed out')),60000);events.addEventListener('done',event=>{clearTimeout(timer);events.close();resolve(Number(event.data));});});
 assert.equal(await done,0,scope.MegaWasm.jobs.get(job.id).lines.slice(-8).join('\n'));
 return scope.MegaWasm.jobs.get(job.id);
}
function storedZip(files){
 const chunks=[],central=[];let offset=0;
 for(const [name,raw]of files){const data=Buffer.from(raw),filename=Buffer.from(name);let crc=0xffffffff;for(const byte of data){crc^=byte;for(let k=0;k<8;k++)crc=crc&1?0xedb88320^(crc>>>1):crc>>>1;}crc=(crc^0xffffffff)>>>0;
  const h=Buffer.alloc(30+filename.length);h.writeUInt32LE(0x04034b50);h.writeUInt16LE(20,4);h.writeUInt32LE(crc,14);h.writeUInt32LE(data.length,18);h.writeUInt32LE(data.length,22);h.writeUInt16LE(filename.length,26);filename.copy(h,30);
  const c=Buffer.alloc(46+filename.length);c.writeUInt32LE(0x02014b50);c.writeUInt16LE(20,4);c.writeUInt16LE(20,6);c.writeUInt32LE(crc,16);c.writeUInt32LE(data.length,20);c.writeUInt32LE(data.length,24);c.writeUInt16LE(filename.length,28);c.writeUInt32LE(offset,42);filename.copy(c,46);central.push(c);chunks.push(h,data);offset+=h.length+data.length;
 }
 const end=Buffer.alloc(22);end.writeUInt32LE(0x06054b50);end.writeUInt16LE(files.size,8);end.writeUInt16LE(files.size,10);end.writeUInt32LE(central.reduce((n,c)=>n+c.length,0),12);end.writeUInt32LE(offset,16);return Buffer.concat([...chunks,...central,end]);
}
(async()=>{
 const manifest='<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="example.wasm"><uses-sdk android:minSdkVersion="21"/><application android:label="WASM test"/></manifest>';
 const smali='.class public Lexample/Value;\n.super Ljava/lang/Object;\n.method public static value()I\n.registers 1\nconst/4 v0, 7\nreturn v0\n.end method\n.method public static delta(I)I\n.registers 2\nconst/4 v0, 1\nadd-int v0, v0, p0\nreturn v0\n.end method\n.method public static endpoint()Ljava/lang/String;\n.registers 2\nconst-string v0, "http://api.example.test/status"\nconst/4 v1, 0\nreturn-object v0\n.end method\n';
 const project=new File([storedZip(new Map([['AndroidManifest.xml',manifest],['smali/example/Value.smali',smali]]))],'project.zip');
 const build=await scan('build',project);assert.ok(build.files.has('app.apk'));
 const apk=new File([build.files.get('app.apk')],'app.apk');
 if(process.env.MEGA_WEB_TEST_APK)fs.writeFileSync(process.env.MEGA_WEB_TEST_APK,Buffer.from(await apk.arrayBuffer()));
 const decode=await scan('decode',apk);assert.match(await decode.files.get('smali/example/Value.smali').text(),/const\/4 v0, (?:0x)?7/);assert.ok(decode.files.has('META-INF/CERT.RSA'));
 const full=await scan('full',apk,['-profile','balanced','-report','all']);assert.ok(full.files.has('REPORT.html'));const analysis=JSON.parse(await full.files.get('analysis.json').text());assert.ok(Array.isArray(analysis.findings));
 assert.ok(full.lines.some(line=>line.includes('GNN model: gnn-trained-v2')),'real trained Rust GNN must load');
 assert.ok(analysis.gnn_diagnostics.methods_inferred>0,'Go graph tensors must reach real Rust inference');
 assert.equal(analysis.gnn_diagnostics.status,'complete');
 const pooled=await scan('full',apk,['-profile','balanced','-report','all'],undefined,{workers:4,timeout:0});
 assert.equal(pooled.workers.length,4);assert.equal(pooled.timer,undefined);assert.ok(pooled.workers.every(worker=>worker.dead));
 assert.ok(pooled.helperTasks>0,'helper workers must perform real file scans');
 assert.deepEqual(JSON.parse(await pooled.files.get('analysis.json').text()).stats,analysis.stats);
 assert.ok(pooled.lines.some(line=>line.includes('4 browser workers')));
 const zipResponse=await scope.fetch('/api/artifacts/'+decode.id+'/archive.zip'),zip=Buffer.from(await zipResponse.arrayBuffer());assert.equal(zip.readUInt32LE(),0x04034b50);assert.ok(zip.includes(Buffer.from('.mega-analyzer-decode-cache.json')),'decode ZIP must preserve rebuild metadata');
 const listing=await (await scope.fetch('/api/workspace/list?path='+encodeURIComponent(decode.path+'/results'))).json();assert.ok(listing.entries.some(e=>e.name==='smali'&&e.directory));
 const file=await scope.fetch('/api/workspace/file?path='+encodeURIComponent(decode.path+'/results/smali/example/Value.smali'));assert.equal(await file.text(),await decode.files.get('smali/example/Value.smali').text());
 await scan('version-diff',apk,[],apk);
 assert.equal(engineLoads,1,'the compiled engine must be reused across fresh workers');
 assert.ok(contexts.length>=4,'each job must still have an isolated Go runtime');
 const bad=new FormData();bad.set('mode','sandbox');bad.set('file',apk);assert.equal((await scope.fetch('/api/scan',{method:'POST',body:bad})).status,403);
 bad.set('mode','full');bad.set('output','../escape');assert.equal((await scope.fetch('/api/scan',{method:'POST',body:bad})).status,400);
 bad.delete('output');
 for(const value of ['0','5','-1','1.5']){bad.set('workers',value);assert.equal((await scope.fetch('/api/scan',{method:'POST',body:bad})).status,400);}
 bad.set('workers','4');
 for(const value of ['-1','3601','1.5']){bad.set('timeout',value);assert.equal((await scope.fetch('/api/scan',{method:'POST',body:bad})).status,400);}
 holdWorkers=true;bad.set('timeout','300');const started=await (await scope.fetch('/api/scan',{method:'POST',body:bad})).json();await new Promise(resolve=>setTimeout(resolve,20));await scope.fetch('/api/stop/'+started.id,{method:'POST'});const stopped=scope.MegaWasm.jobs.get(started.id);assert.equal(stopped.status,'stopped');assert.equal(stopped.workers.length,4);assert.ok(stopped.workers.every(worker=>worker.dead));
 bad.set('timeout','1');const timed=await (await scope.fetch('/api/scan',{method:'POST',body:bad})).json();await new Promise(resolve=>setTimeout(resolve,1100));const expired=scope.MegaWasm.jobs.get(timed.id);assert.equal(expired.status,'failed');assert.ok(expired.lines.some(line=>line.includes('1-second timeout')));assert.ok(expired.workers.every(worker=>worker.dead));
 console.log('PASS: real Go WASM build, Smali decode, static analysis, version diff, ZIP metadata, workspace files, rejected modes/paths and Stop.');
 process.exit(0);
})().catch(error=>{console.error(error.stack);process.exit(1);});
