"use strict";
importScripts("/static/memfs.js");
self.onmessage=async ({data})=>{
  const engineFetch=self.fetch.bind(self);
  self.fetch=async()=>{throw Error("Network access is disabled during browser analysis.");};
  let pending="";
  const decoder=new TextDecoder();
  const flush=()=>{if(pending){self.postMessage({type:"log",line:pending});pending="";}};
  const helper=data.role==="file-scanner";
  const fs=new MegaMemoryFS(bytes=>{if(helper)return;pending+=decoder.decode(bytes,{stream:true});const lines=pending.split(/\r\n|\n|\r/);pending=lines.pop();for(const line of lines)if(line.trim())self.postMessage({type:"log",line});});
  self.fs=fs;self.process=fs.process();self.path={resolve:(...p)=>fs.resolve(...p)};
  try{
    const targets=[];
    for(let i=0;i<(data.files||[]).length;i++){
      const file=data.files[i];if(!(file instanceof Blob)||file.size>512*1024*1024)throw Error("Maximum input size is 512 MiB.");
      const name=String(file.name||"input.bin").split(/[\\/]/).pop().replace(/[^\p{L}\p{N}._ -]/gu,"_").slice(0,180)||"input.bin";
      const target="/inputs/"+i+"/"+name;fs.put(target,new Uint8Array(await file.arrayBuffer()));targets.push(target);
    }
    if(data.output)fs.mkdirSync(data.output);
    if(data.gnn){
      importScripts("/static/gnn.js");
      const rust=await WebAssembly.instantiate(data.gnn.engine,{});
      new MegaRustGNN(rust).bind();
      fs.put("/home/.analyzer/models/gnn_weights.json",data.gnn.weights);
    }
    importScripts("/static/wasm_exec.js");const go=new Go();go.env={HOME:"/home",XDG_CONFIG_HOME:"/config",TMPDIR:"/tmp",MEGA_ANALYZER_NO_BROWSER:"1"};
    let instance;
    let pool;
    if(!helper&&data.ports?.length){importScripts("/static/wasm-pool.js");pool=new MegaFilePool(data.ports);}
    self.megaDone=code=>{pool?.close();flush();const files=fs.snapshot(data.output);self.postMessage({type:"done",code,files,memoryBytes:instance.exports.mem.buffer.byteLength,helperTasks:pool?.completed||0,helperTaskCounts:pool?.slots.map(slot=>slot.completed)||[]},files.map(f=>f.bytes.buffer));};
    if(!helper)self.postMessage({type:"log",line:"Loading the Go analysis engine. Files stay in this tab."});
    let engine=data.engine;
    if(!engine){
      const response=await engineFetch("/static/analyzer.wasm.gz");if(!response.ok)throw Error("Cannot load the analysis engine (HTTP "+response.status+").");
      if(WebAssembly.compileStreaming){try{engine=await WebAssembly.compileStreaming(response.clone());}catch{}}
      if(!engine)engine=await WebAssembly.compile(await response.arrayBuffer());
    }
    instance=await WebAssembly.instantiate(engine,go.importObject);
    go.run(instance).catch(error=>self.postMessage({type:"error",error:String(error)}));
    if(helper){
      const port=data.port;
      self.megaFileReply=(id,result,error)=>port.postMessage({type:"file-result",id,result,error});
      port.onmessage=({data:task})=>{
        if(task.type!=="file-scan")return;
        if(typeof self.megaScanFile!=="function"||!self.megaScanFile(task.configuration,task.metadata,task.content,task.id))
          self.megaFileReply(task.id,"{}","File scanner rejected the task.");
      };
      port.start();self.postMessage({type:"ready"});return;
    }
    if(typeof self.megaRun!=="function"||!self.megaRun(JSON.stringify({mode:data.mode,targets,output:data.output,flags:data.flags,workers:data.workers||1,timeout:data.timeout??300})))throw Error("Unsupported analysis options.");
  }catch(error){flush();self.postMessage({type:"error",error:error.message||String(error)});}
};
