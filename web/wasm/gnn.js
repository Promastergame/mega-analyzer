"use strict";
class MegaRustGNN {
  constructor(instance) { this.exports=instance.exports; }
  load(bytes) {
    const e=this.exports,p=e.gnn_wasm_alloc(bytes.length);if(!p)return 0;
    try { new Uint8Array(e.memory.buffer,p,bytes.length).set(bytes);return e.gnn_model_load_bytes(p,bytes.length); }
    finally { e.gnn_wasm_free(p,bytes.length); }
  }
  close(model) { this.exports.gnn_model_free(model); }
  infer(model,bytes) {
    if(bytes.length<16)return null;
    const header=new DataView(bytes.buffer,bytes.byteOffset,bytes.byteLength),n=header.getUint32(0,true),dim=header.getUint32(4,true),cols=header.getUint32(8,true),types=header.getUint32(12,true);
    if(!n||n>65536||!dim||dim>256||cols>1000000||(types!==0&&types!==cols)||bytes.length!==16+8*(n+1+cols)+4*(types+n*dim))return null;
    const e=this.exports,allocation=bytes.length+96,p=e.gnn_wasm_alloc(allocation);if(!p)return null;
    let result=0;
    try {
      new Uint8Array(e.memory.buffer,p,bytes.length).set(bytes);
      const view=new DataView(e.memory.buffer);
      let offset=p+16;const rows=offset;offset+=8*(n+1);const columns=offset;offset+=8*cols;const edges=offset;offset+=4*types;const features=offset;
      const graph=(p+bytes.length+7)&~7,out=graph+72;
      new Uint8Array(e.memory.buffer,graph,80).fill(0);
      view.setUint32(graph,rows,true);view.setBigUint64(graph+8,BigInt(n+1),true);
      view.setUint32(graph+16,columns,true);view.setBigUint64(graph+24,BigInt(cols),true);
      view.setUint32(graph+32,edges,true);view.setBigUint64(graph+40,BigInt(types),true);
      view.setUint32(graph+48,features,true);view.setBigUint64(graph+56,BigInt(n),true);view.setBigUint64(graph+64,BigInt(dim),true);
      result=e.gnn_model_infer(model,graph,out);if(!result)return null;
      // Inference may grow memory. Recreate views after the Rust call.
      if(Number(new DataView(e.memory.buffer).getBigUint64(out,true))!==8)return null;
      return Array.from(new Float32Array(e.memory.buffer,result,8));
    } finally { if(result)e.gnn_free_result(result);e.gnn_wasm_free(p,allocation); }
  }
  bind() {
    self.megaGNNLoad=bytes=>this.load(bytes);self.megaGNNClose=model=>this.close(model);self.megaGNNInfer=(model,bytes)=>this.infer(model,bytes);
  }
}
self.MegaRustGNN=MegaRustGNN;
