// Compare browser ABI against the native Rust ABI using the same trained model.
const fs=require('node:fs'),path=require('node:path'),vm=require('node:vm'),assert=require('node:assert/strict'),{spawnSync}=require('node:child_process');
const root=path.resolve(process.argv[2]||'dist/web'),source=path.resolve(__dirname,'..');
const weights=fs.readFileSync(path.join(root,'static/gnn_weights.json'));
const dim=JSON.parse(weights).config.layers[0].features_in;
const graphs=[3,7,25].map(n=>({n,dim,rows:Array.from({length:n+1},(_,i)=>Math.min(i,n-1)),cols:Array.from({length:n-1},(_,i)=>i+1),types:Array.from({length:n-1},(_,i)=>i%3),features:Array.from({length:n*dim},(_,i)=>(i%11)/10)}));
function pack(g){const b=Buffer.alloc(16+8*(g.rows.length+g.cols.length)+4*(g.types.length+g.features.length));b.writeUInt32LE(g.n);b.writeUInt32LE(g.dim,4);b.writeUInt32LE(g.cols.length,8);b.writeUInt32LE(g.types.length,12);let o=16;for(const v of [...g.rows,...g.cols]){b.writeBigUInt64LE(BigInt(v),o);o+=8;}for(const v of g.types){b.writeUInt32LE(v,o);o+=4;}for(const v of g.features){b.writeFloatLE(v,o);o+=4;}return b;}
const python=String.raw`
import ctypes as c,json,sys
lib=c.CDLL(sys.argv[1])
class Graph(c.Structure):
 _fields_=[('rows',c.POINTER(c.c_uint64)),('row_len',c.c_uint64),('cols',c.POINTER(c.c_uint64)),('col_len',c.c_uint64),('types',c.POINTER(c.c_uint32)),('type_len',c.c_uint64),('features',c.POINTER(c.c_float)),('nodes',c.c_uint64),('dim',c.c_uint64)]
lib.gnn_model_load.argtypes=[c.c_char_p];lib.gnn_model_load.restype=c.c_void_p
lib.gnn_model_infer.argtypes=[c.c_void_p,c.POINTER(Graph),c.POINTER(c.c_uint64)];lib.gnn_model_infer.restype=c.POINTER(c.c_float)
lib.gnn_free_result.argtypes=[c.POINTER(c.c_float)];lib.gnn_model_free.argtypes=[c.c_void_p]
model=lib.gnn_model_load(sys.argv[2].encode());assert model
out=[]
for g in json.load(sys.stdin):
 rows=(c.c_uint64*len(g['rows']))(*g['rows']);cols=(c.c_uint64*len(g['cols']))(*g['cols']);types=(c.c_uint32*len(g['types']))(*g['types']);features=(c.c_float*len(g['features']))(*g['features'])
 graph=Graph(rows,len(rows),cols,len(cols),types,len(types),features,g['n'],g['dim']);count=c.c_uint64()
 result=lib.gnn_model_infer(model,c.byref(graph),c.byref(count));assert result and count.value==8
 out.append([result[i] for i in range(8)]);lib.gnn_free_result(result)
lib.gnn_model_free(model);print(json.dumps(out))
`;
(async()=>{
 const native=spawnSync('python',['-c',python,path.join(source,'rust/target/release/omnisec_ml_gnn.dll'),path.join(root,'static/gnn_weights.json')],{input:JSON.stringify(graphs),encoding:'utf8'});assert.equal(native.status,0,native.stderr);
 const expected=JSON.parse(native.stdout),scope={WebAssembly,Uint8Array,Float32Array,DataView};scope.self=scope;vm.createContext(scope);vm.runInContext(fs.readFileSync(path.join(root,'static/gnn.js'),'utf8'),scope);
 const {instance}=await WebAssembly.instantiate(fs.readFileSync(path.join(root,'static/gnn.wasm')),{});const engine=new scope.MegaRustGNN(instance),model=engine.load(weights);assert.ok(model);
 graphs.forEach((g,k)=>{const got=engine.infer(model,pack(g));assert.equal(got.length,8);got.forEach((p,i)=>assert.ok(Math.abs(p-expected[k][i])<1e-5,`graph ${k} class ${i}: ${p} vs ${expected[k][i]}`));});
 const invalid={...graphs[0],rows:[0,2,1,2]};assert.equal(engine.infer(model,pack(invalid)),null);
 assert.equal(engine.infer(model,pack({...graphs[0],cols:[999,1]})),null);
 assert.equal(engine.infer(model,pack({...graphs[0],features:graphs[0].features.map(()=>NaN)})),null);
 assert.equal(engine.load(new TextEncoder().encode('{}')),0);engine.close(model);
 console.log('PASS: Rust WASM/native trained GNN probabilities agree; invalid CSR, columns, features and weights rejected.');
})().catch(e=>{console.error(e);process.exitCode=1;});
