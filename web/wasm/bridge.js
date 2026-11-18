"use strict";
(function(){
  const nativeFetch=window.fetch.bind(window),NativeEventSource=window.EventSource;
  let enginePromise;
  let gnnPromise;
  function loadGNN(){
    if(!gnnPromise)gnnPromise=Promise.all([
      nativeFetch("/static/gnn.wasm.gz").then(async r=>{if(!r.ok)throw Error("Cannot load Rust GNN.");return WebAssembly.compile(await r.arrayBuffer());}),
      nativeFetch("/static/gnn_weights.json").then(async r=>{if(!r.ok)throw Error("Cannot load trained GNN weights.");return new Uint8Array(await r.arrayBuffer());})
    ]).then(([engine,weights])=>({engine,weights})).catch(e=>{gnnPromise=null;throw e;});
    return gnnPromise;
  }
  function loadEngine(){
    if(!enginePromise)enginePromise=(async()=>{
      const response=await nativeFetch("/static/analyzer.wasm.gz");
      if(!response.ok)throw Error("Cannot load the analysis engine (HTTP "+response.status+").");
      if(WebAssembly.compileStreaming){try{return await WebAssembly.compileStreaming(response.clone());}catch{}}
      return WebAssembly.compile(await response.arrayBuffer());
    })().catch(error=>{enginePromise=null;throw error;});
    return enginePromise;
  }
  const jobs=new Map(),folders=new Set(["","Scans"]),allowed=new Set(["full","minecraft","decode","build","machine-code","firmware","version-diff","js-deobf","js-patch"]);
  const json=(data,status=200)=>new Response(JSON.stringify(data),{status,headers:{"Content-Type":"application/json","Cache-Control":"no-store"}});
  const fail=(message,status=400)=>new Response(message,{status});
  const mime=path=>/\.html?$/i.test(path)?"text/html;charset=utf-8":/\.json$/i.test(path)?"application/json":/\.(txt|md|log|smali|js|xml|csv)$/i.test(path)?"text/plain;charset=utf-8":"application/octet-stream";
  const parent=path=>path.slice(0,path.lastIndexOf("/"))||"";
  function folder(path){if(path&&(!/^[^\\:]*$/.test(path)||path.split("/").some(p=>!p||p==="."||p===".."||p.startsWith("."))))throw Error("Choose a relative folder name.");if(!folders.has(path)){folder(parent(path));folders.add(path);}}
  function emit(job,type,data){for(const subscriber of [...job.subscribers])subscriber(type,String(data));}
  const isProgress=line=>/^\s*[a-z_]+\s+\d+%\s+\[\d+\/\d+\]/.test(line);
  function log(job,line){job.lines.push(line);if(job.lines.length>10000)job.lines.shift();emit(job,isProgress(line)?"progress":"message",JSON.stringify(line).slice(1,-1));}
  function finish(job,code,files){if(job.done)return;job.done=true;clearTimeout(job.timer);for(const cancel of job.onFinish)cancel();job.onFinish=[];for(const worker of job.workers)worker.terminate();job.code=code;job.finished=new Date().toISOString();job.status=job.stopped?"stopped":code?"failed":"completed";job.files=new Map((files||[]).map(f=>[f.path,new Blob([f.bytes],{type:mime(f.path)})]));job.files.set("scan.log",new Blob([job.lines.join("\n")],{type:"text/plain"}));emit(job,"state",job.status);emit(job,"done",code);}
  function create(form){
    const mode=form.get("mode")||"full";if(!allowed.has(mode))return fail("This tool requires the desktop analyzer.",403);
    if([...jobs.values()].some(j=>!j.done))return fail("Finish or stop the current analysis first.",429);
    const files=[form.get("file")];if(mode==="version-diff")files.push(form.get("file2"));
    if(files.some(f=>!(f instanceof Blob)||!f.size||f.size>512*1024*1024))return fail("Choose a file between 1 byte and 512 MiB.");
    let flags;try{flags=JSON.parse(form.get("flags")||"[]");if(!Array.isArray(flags))throw Error();}catch{return fail("Invalid options.");}
    const workerCount=Number(form.get("workers")??2),timeout=Number(form.get("timeout")??300);
    if(!Number.isInteger(workerCount)||workerCount<1||workerCount>4)return fail("Choose between 1 and 4 workers.");
    if(!Number.isInteger(timeout)||timeout<0||timeout>3600)return fail("Choose a timeout from 0 to 3600 seconds.");
    const id=Array.from(crypto.getRandomValues(new Uint8Array(16)),b=>b.toString(16).padStart(2,"0")).join("");
    const group=String(form.get("output")||"Scans");try{folder(group);}catch(e){return fail(e.message);}
    const started=new Date().toISOString(),stamp=started.slice(0,19).replace("T","_").replace(/:/g,"");
    const path=group+"/"+stamp+"_"+id,output="/workspace/"+path+"/results";
    folder(path);folder(path+"/results");
    const worker=new Worker("/static/wasm-worker.js"),job={id,mode,path,output,started,name:String(form.get("outname")||files[0].name||mode),status:"running",lines:[],files:new Map(),subscribers:new Set(),worker,workers:[worker],workerCount,timeout,onFinish:[],done:false,code:0};jobs.set(id,job);
    worker.onmessage=({data})=>{if(data.type==="log")log(job,data.line);else if(data.type==="done"){job.helperTasks=data.helperTasks||0;job.helperTaskCounts=data.helperTaskCounts||[];finish(job,data.code,data.files);}else if(data.type==="error"){log(job,"[error] "+data.error);finish(job,1);}};
    worker.onerror=event=>{log(job,"[error] "+event.message);finish(job,1);};
    if(timeout>0)job.timer=setTimeout(()=>{log(job,"[error] Analysis reached the selected "+timeout+"-second timeout.");finish(job,1);},timeout*1000);
    log(job,"Preparing the Go engine. The compiled engine is reused in this tab.");
    Promise.all([loadEngine(),(mode==="full"||mode==="minecraft")&&!flags.includes("-skip-gnn")?loadGNN():null]).then(async ([engine,gnn])=>{
      if(job.done)return;
      const ports=[],ready=[];
      // The coordinator is one of the selected workers, so total count never
      // exceeds four. Other tools perform one indivisible transformation.
      if(mode==="full"||mode==="minecraft")for(let i=1;i<workerCount;i++){
        const helper=new Worker("/static/wasm-worker.js"),channel=new MessageChannel();job.workers.push(helper);ports.push(channel.port1);
        ready.push(new Promise((resolve,reject)=>{
          job.onFinish.push(()=>reject(Error("Analysis ended.")));
          helper.onmessage=({data})=>{if(data.type==="ready")resolve();else if(data.type==="error"){reject(Error(data.error));if(!job.done){log(job,"[error] "+data.error);finish(job,1);}}};
          helper.onerror=event=>{const error=Error(event.message||"File scanner failed.");reject(error);if(!job.done){log(job,"[error] "+error.message);finish(job,1);}};
        }));
        helper.postMessage({role:"file-scanner",engine,port:channel.port2},[channel.port2]);
      }
      await Promise.all(ready);
      if(!job.done){log(job,"Using "+job.workers.length+" browser worker"+(job.workers.length===1?"":"s")+". Global analysis runs once.");worker.postMessage({mode,files,flags,output,engine,gnn,ports,workers:workerCount,timeout},ports);}
    })
      .catch(error=>{if(!job.done){log(job,"[error] "+error.message);finish(job,1);}});
    return json({id,output,mode,workspace_path:path,status:"running"});
  }
  function workspaceFile(path){for(const job of jobs.values()){if(path===job.path+"/scan.log")return new Blob([job.lines.join("\n")],{type:"text/plain"});const prefix=job.path+"/results/";if(path.startsWith(prefix))return job.files.get(path.slice(prefix.length));}return null;}
  function workspaceList(path,offset){
    if(!folders.has(path))return fail("Folder not found.",404);
    const entries=new Map();for(const dir of folders)if(dir!==path&&parent(dir)===path)entries.set(dir,{name:dir.split("/").pop(),path:dir,directory:true,size:0,modified:new Date().toISOString()});
    for(const job of jobs.values()){
      if(parent(job.path)===path&&entries.has(job.path))Object.assign(entries.get(job.path),{modified:job.started,scan:{id:job.id,name:job.name,mode:job.mode,started:job.started,finished:job.finished,status:job.status,exit_code:job.code,report_dir:job.path+"/results",report_path:job.files.has("REPORT.html")?job.path+"/results/REPORT.html":""}});
      if(path===job.path)entries.set(path+"/scan.log",{name:"scan.log",path:path+"/scan.log",directory:false,size:job.lines.join("\n").length,modified:job.finished||job.started});
      for(const [file,blob]of job.files){const p=job.path+"/results/"+file;if(parent(p)===path)entries.set(p,{name:file.split("/").pop(),path:p,directory:false,size:blob.size,modified:job.finished||job.started});else if(p.startsWith(path?path+"/":"")){const rest=p.slice(path?path.length+1:0),first=rest.split("/")[0];if(rest.includes("/")){const dir=(path?path+"/":"")+first;entries.set(dir,{name:first,path:dir,directory:true,size:0,modified:job.finished||job.started});folders.add(dir);}}}
    }
    const all=[...entries.values()].sort((a,b)=>Number(b.directory)-Number(a.directory)||a.name.localeCompare(b.name));return json({path,entries:all.slice(offset,offset+200),more:all.length>offset+200,next_offset:offset+200});
  }
  async function api(url,options){
    const p=url.pathname,method=options.method||"GET";
    if(p==="/api/meta")return json({version:"1.0.0-beta.2",wasm:true,uploadMaxBytes:512*1024*1024});
    const host={os:"browser",family:"any",arch:"wasm",label:"This browser",cpuCount:1,sandbox:{ready:false}};
    if(p==="/api/host")return json(host);if(p==="/api/env")return json({host,devices:[],avds:[],vbox:[],vmware:[],warnings:[]});if(p==="/api/pkg-version")return json({installed:false});
    if(p==="/api/scan"&&method==="POST")return create(options.body);
    if(p==="/api/workspace/list")return workspaceList(url.searchParams.get("path")||"",Number(url.searchParams.get("offset")||0));
    if(p==="/api/workspace/mkdir"&&method==="POST"){try{const path=JSON.parse(options.body).path;folder(path);return json({path});}catch(e){return fail(e.message);}}
    if(p==="/api/workspace/file"){const blob=workspaceFile(url.searchParams.get("path")||"");return blob?new Response(blob,{headers:{"Content-Type":blob.type}}):fail("File not found.",404);}
    const match=p.match(/^\/api\/(result|report|evidence|artifacts|stop)\/([^/]+)(?:\/(.*))?$/);if(!match)return fail("This tool requires the desktop analyzer.",403);
    const [,kind,id,sub=""]=match,job=jobs.get(id);if(!job)return fail("Result not found in this tab.",404);
    if(kind==="stop"){job.stopped=true;finish(job,130);return json({stopped:true});}
    if(kind==="result"||kind==="report"){if(!job.done)return fail("Analysis is running.",202);const file=job.files.get(kind==="result"?"analysis.json":"REPORT.html");return file?new Response(file,{headers:{"Content-Type":file.type}}):fail("Report unavailable.",404);}
    if(kind==="evidence"){const file=job.files.get("analysis.json");if(!file)return fail("Evidence unavailable.",404);const result=JSON.parse(await file.text());return json(result.evidence_graph||result.EvidenceGraph||{});}
    if(kind==="artifacts"){
      if(sub.startsWith("files/")){const file=job.files.get(decodeURIComponent(sub.slice(6)));return file?new Response(file,{headers:{"Content-Type":file.type}}):fail("File not found.",404);}
      if(sub==="archive.zip"){if(!job.done)return fail("Wait for the analysis to finish.",409);return new Response(await zip(job.files),{headers:{"Content-Type":"application/zip"}});}
      const q=(url.searchParams.get("q")||"").toLowerCase(),offset=Number(url.searchParams.get("offset")||0),all=[...job.files].filter(([path])=>path.toLowerCase().includes(q)).map(([path,b])=>({path,size:b.size}));
      const reports=Object.fromEntries(["REPORT.html","REPORT.md","analysis.json","analysis.sarif"].map(p=>[p,job.files.has(p)]));let stages;try{stages=JSON.parse(await job.files.get("static_outputs.json")?.text());}catch{}
      return json({files:all.slice(offset,offset+2000),truncated:all.length>offset+2000,next_offset:offset+2000,done:job.done,exit_code:job.code,reports,stages,archive_limit:20000});
    }
    return fail("Unknown result endpoint.",404);
  }
  window.fetch=(input,options={})=>{
    const url=new URL(typeof input==="string"?input:input.url,location.href);
    if(url.origin!==location.origin||!url.pathname.startsWith("/api/"))return nativeFetch(input,options);
    if(options.signal?.aborted)return Promise.reject(new DOMException("Aborted","AbortError"));
    return api(url,options).catch(e=>fail(e.message));
  };
  class LocalEvents extends EventTarget{
    constructor(url){super();this.readyState=0;const id=new URL(url,location.href).pathname.split("/").pop(),job=jobs.get(id);this.job=job;
      this.subscriber=(type,data)=>{if(this.readyState===2)return;const e=new MessageEvent(type,{data});this.dispatchEvent(e);if(type==="message")this.onmessage?.(e);};
      queueMicrotask(()=>{if(this.readyState===2)return;if(!job){this.onerror?.(new Event("error"));return;}this.readyState=1;job.subscribers.add(this.subscriber);this.subscriber("state",job.status);for(const line of job.lines)this.subscriber(isProgress(line)?"progress":"message",JSON.stringify(line).slice(1,-1));if(job.done)this.subscriber("done",job.code);});
    }
    close(){this.readyState=2;this.job?.subscribers.delete(this.subscriber);}
  }
  window.EventSource=function(url,options){return new URL(url,location.href).pathname.startsWith("/api/events/")?new LocalEvents(url):new NativeEventSource(url,options);};
  window.EventSource.CONNECTING=0;window.EventSource.OPEN=1;window.EventSource.CLOSED=2;
  const resourceURLs=new Map();
  async function prepareLink(a,url){
    const download=a.hasAttribute("download")||url.searchParams.has("dl");
    const key=url.href+"|"+download;
    if(!resourceURLs.has(key))resourceURLs.set(key,(async()=>{
      const response=await window.fetch(url.href);if(!response.ok)throw Error("Cannot open result (HTTP "+response.status+").");
      const blob=await response.blob(),src=URL.createObjectURL(blob);
      if(download||!blob.type.startsWith("text/html"))return {src,download:true};
      const page=new Blob(['<!doctype html><meta charset="utf-8"><title>Analysis report</title><style>html,body{margin:0;background:#1e1e1e}iframe{border:0;display:block;width:100vw;height:100vh}</style><iframe sandbox="allow-scripts allow-downloads" src="'+src+'"></iframe>'],{type:"text/html"});
      return {src:URL.createObjectURL(page),download:false};
    })());
    const result=await resourceURLs.get(key);
    if(a.href!==url.href)return;
    a.href=result.src;
    if(result.download)a.download=a.getAttribute("download")||((url.pathname.includes("/report/")?"report.html":url.pathname.split("/").pop())||"result");
  }
  // Native Blob links also work with the browser's Save/Download controls.
  if(typeof MutationObserver!=="undefined")new MutationObserver(()=>{
    for(const a of document.querySelectorAll('a[href]')){
      const url=new URL(a.href,location.href);
      if(url.origin!==location.origin||!url.pathname.startsWith("/api/")||a.dataset.megaPreparing===url.href)continue;
      a.dataset.megaPreparing=url.href;prepareLink(a,url).catch(()=>{});
    }
  }).observe(document.documentElement,{subtree:true,childList:true,attributes:true,attributeFilter:["href"]});
  document.addEventListener("click",async event=>{
    const a=event.target.closest("a[href]");if(!a)return;const url=new URL(a.href,location.href);if(url.origin!==location.origin||!url.pathname.startsWith("/api/"))return;
    event.preventDefault();try{await prepareLink(a,url);a.click();}catch(error){console.error(error.message);}
  });
  async function zip(files){
    const chunks=[],central=[];let offset=0;const enc=new TextEncoder(),table=Array.from({length:256},(_,n)=>{for(let k=0;k<8;k++)n=n&1?0xedb88320^(n>>>1):n>>>1;return n>>>0;});
    for(const [path,blob]of files){const bytes=new Uint8Array(await blob.arrayBuffer()),name=enc.encode(path);let crc=0xffffffff;for(const b of bytes)crc=table[(crc^b)&255]^(crc>>>8);crc=(crc^0xffffffff)>>>0;
      const header=new Uint8Array(30+name.length),h=new DataView(header.buffer);h.setUint32(0,0x04034b50,true);h.setUint16(4,20,true);h.setUint16(6,0x800,true);h.setUint32(14,crc,true);h.setUint32(18,bytes.length,true);h.setUint32(22,bytes.length,true);h.setUint16(26,name.length,true);header.set(name,30);
      const record=new Uint8Array(46+name.length),r=new DataView(record.buffer);r.setUint32(0,0x02014b50,true);r.setUint16(4,20,true);r.setUint16(6,20,true);r.setUint16(8,0x800,true);r.setUint32(16,crc,true);r.setUint32(20,bytes.length,true);r.setUint32(24,bytes.length,true);r.setUint16(28,name.length,true);r.setUint32(42,offset,true);record.set(name,46);central.push(record);chunks.push(header,bytes);offset+=header.length+bytes.length;
    }
    const size=central.reduce((n,b)=>n+b.length,0),end=new Uint8Array(22),e=new DataView(end.buffer);e.setUint32(0,0x06054b50,true);e.setUint16(8,central.length,true);e.setUint16(10,central.length,true);e.setUint32(12,size,true);e.setUint32(16,offset,true);return new Blob([...chunks,...central,end],{type:"application/zip"});
  }
  window.MegaWasm={allowed, jobs};
})();
