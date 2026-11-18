const fs=require('node:fs'),vm=require('node:vm'),assert=require('node:assert/strict');
const scope={Uint8Array,Date,Map};vm.createContext(scope);vm.runInContext(fs.readFileSync('web/wasm/memfs.js','utf8'),scope);
const mem=new scope.MegaMemoryFS(()=>{},1024*1024);
function call(name,...args){let result,error;mem[name](...args,(e,v)=>{error=e;result=v;});if(error)throw error;return result;}
const fd=call('open','/workspace/report.txt',66,448),chunk=new Uint8Array(1024).fill(90);let buffers=new Set();
for(let i=0;i<512;i++){call('write',fd,chunk,0,chunk.length,null);buffers.add(mem.get('/workspace/report.txt').storage.buffer);}
assert.ok(buffers.size<20,'append must grow geometrically');assert.equal(mem.used,512*1024);assert.ok(mem.allocated<=mem.limit);
call('ftruncate',fd,1024);call('ftruncate',fd,2048);assert.ok(mem.get('/workspace/report.txt').data.subarray(1024).every(b=>b===0),'regrowth must zero truncated bytes');
const hole=new Uint8Array([1,2]);call('write',fd,hole,0,2,4096);assert.ok(mem.get('/workspace/report.txt').data.subarray(2048,4096).every(b=>b===0));
mem.put('/workspace/other',new Uint8Array(mem.limit-4098));assert.equal(mem.used,mem.limit);assert.ok(mem.allocated<=mem.limit,'spare buffers must compact under quota pressure');
assert.throws(()=>call('write',fd,hole,0,2,4098),{code:'ENOSPC'});assert.equal(mem.used,mem.limit);
call('unlink','/workspace/other');call('rename','/workspace/report.txt','/workspace/report.txt');assert.equal(mem.used,4098);
const snapshot=mem.snapshot('/workspace');assert.equal(snapshot[0].bytes.buffer.byteLength,4098,'transfer only logical file bytes');
call('ftruncate',fd,0);assert.equal(mem.used,0);assert.equal(mem.allocated,0);call('close',fd);
console.log('PASS: amortized append, zero-filled holes/truncation, quota, compaction, rename and exact-size snapshots.');
