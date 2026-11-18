"use strict";

// Node-style file callbacks consumed by Go's js/wasm standard library.
// Every byte stays in this worker; this object has no disk or network access.
class MegaMemoryFS {
  constructor(onOutput, limit = 1024 * 1024 * 1024) {
    this.constants = {O_RDONLY:0,O_WRONLY:1,O_RDWR:2,O_CREAT:64,O_EXCL:128,O_TRUNC:512,O_APPEND:1024,O_DIRECTORY:65536};
    this.nodes = new Map(); this.fds = new Map(); this.nextFd = 3; this.nextIno = 1;
    this.cwd = "/workspace"; this.limit = limit; this.used = 0; this.allocated = 0; this.onOutput = onOutput;
    ["/", "/workspace", "/tmp", "/config", "/home"].forEach(p => this.nodes.set(p, this.node(true)));
  }
  error(code) { return Object.assign(new Error(code), {code}); }
  node(dir) { const data=new Uint8Array(0);return {dir, data, storage:data, mode:(dir?0o040000:0o100000)|0o700, ino:this.nextIno++, time:Date.now()}; }
  resolve(...parts) {
    let p = parts.filter(Boolean).join("/"); if (!p.startsWith("/")) p = this.cwd + "/" + p;
    const out=[]; for(const piece of p.split("/")){if(!piece||piece===".")continue;if(piece==="..")out.pop();else out.push(piece);}
    return "/" + out.join("/");
  }
  parent(p) { return p.slice(0,p.lastIndexOf("/")) || "/"; }
  get(p) { const n=this.nodes.get(this.resolve(p)); if(!n)throw this.error("ENOENT");return n; }
  descriptor(fd) { const f=this.fds.get(fd);if(!f)throw this.error("EBADF");return f; }
  operation(callback, fn) { try { callback(null,fn()); } catch(e) { callback(e); } }
  stats(n) {
    return {dev:1,ino:n.ino,mode:n.mode,nlink:1,uid:1000,gid:1000,rdev:0,size:n.dir?0:n.data.length,blksize:4096,blocks:Math.ceil(n.data.length/512),atimeMs:n.time,mtimeMs:n.time,ctimeMs:n.time,
      isDirectory:()=>n.dir,isFile:()=>!n.dir,isSymbolicLink:()=>false};
  }
  compact(exclude,required) {
    if(this.allocated+required<=this.limit)return;
    for(const node of this.nodes.values()){
      if(node===exclude||node.storage.length===node.data.length)continue;
      this.allocated-=node.storage.length-node.data.length;
      node.data=node.data.slice();node.storage=node.data;
      if(this.allocated+required<=this.limit)return;
    }
  }
  resize(n,size) {
    if(!Number.isSafeInteger(size)||size<0)throw this.error("EINVAL");
    const used=this.used-n.data.length+size;if(used>this.limit)throw this.error("ENOSPC");
    const oldSize=n.data.length,oldCapacity=n.storage.length;
    if(size===0){n.data=new Uint8Array(0);n.storage=n.data;this.allocated-=oldCapacity;}
    else if(size>oldCapacity){
      this.compact(n,size-oldCapacity);
      const available=this.limit-this.allocated+oldCapacity;
      if(size>available)throw this.error("ENOSPC");
      // Geometric growth makes repeated template/log writes amortized linear.
      const capacity=Math.min(available,Math.max(size,4096,Math.ceil(oldCapacity*1.5)));
      const storage=new Uint8Array(capacity);storage.set(n.data);n.storage=storage;
      this.allocated+=capacity-oldCapacity;n.data=storage.subarray(0,size);
    }else{
      if(size<oldSize)n.storage.fill(0,size,oldSize);
      else if(size>oldSize)n.storage.fill(0,oldSize,size);
      n.data=n.storage.subarray(0,size);
    }
    this.used=used;n.time=Date.now();
  }
  mkdirSync(p) {
    p=this.resolve(p);if(this.nodes.has(p)){if(!this.get(p).dir)throw this.error("ENOTDIR");return;}
    this.mkdirSync(this.parent(p));if(this.nodes.size>=20000)throw this.error("ENOSPC");this.nodes.set(p,this.node(true));
  }
  put(p,bytes) {p=this.resolve(p);this.mkdirSync(this.parent(p));const old=this.nodes.get(p);if(old?.dir)throw this.error("EISDIR");if(!old&&this.nodes.size>=20000)throw this.error("ENOSPC");const used=this.used-(old?.data.length||0)+bytes.length;if(used>this.limit)throw this.error("ENOSPC");this.compact(old,bytes.length-(old?.storage.length||0));const n=this.node(false);n.data=new Uint8Array(bytes);n.storage=n.data;this.allocated+=bytes.length-(old?.storage.length||0);this.nodes.set(p,n);this.used=used;}
  open(p,flags,mode,cb) {this.operation(cb,()=>{
    p=this.resolve(p);let n=this.nodes.get(p);
    if(n&&(flags&128)&&(flags&64))throw this.error("EEXIST");
    if(!n){if(!(flags&64))throw this.error("ENOENT");if(!this.get(this.parent(p)).dir)throw this.error("ENOTDIR");if(this.nodes.size>=20000)throw this.error("ENOSPC");n=this.node(false);n.mode=0o100000|mode;this.nodes.set(p,n);}
    if((flags&65536)&&!n.dir)throw this.error("ENOTDIR");if(n.dir&&(flags&3))throw this.error("EISDIR");
    if(flags&512)this.resize(n,0);const fd=this.nextFd++;this.fds.set(fd,{node:n,path:p,flags,pos:flags&1024?n.data.length:0});return fd;
  });}
  close(fd,cb) {this.operation(cb,()=>{this.descriptor(fd);this.fds.delete(fd);});}
  stat(p,cb) {this.operation(cb,()=>this.stats(this.get(p)));}
  lstat(p,cb) {this.stat(p,cb);}
  fstat(fd,cb) {this.operation(cb,()=>this.stats(this.descriptor(fd).node));}
  read(fd,buffer,offset,length,position,cb) {this.operation(cb,()=>{
    if(fd===0)return 0;const f=this.descriptor(fd);if(f.node.dir)throw this.error("EISDIR");
    const pos=position===null?f.pos:position;const count=Math.max(0,Math.min(length,f.node.data.length-pos));buffer.set(f.node.data.subarray(pos,pos+count),offset);if(position===null)f.pos+=count;return count;
  });}
  writeSync(fd,buffer) {if(fd===1||fd===2){this.onOutput(new Uint8Array(buffer));return buffer.length;}throw this.error("EBADF");}
  write(fd,buffer,offset,length,position,cb) {this.operation(cb,()=>{
    if(fd===1||fd===2){this.onOutput(new Uint8Array(buffer.subarray(offset,offset+length)));return length;}
    const f=this.descriptor(fd);if(!(f.flags&3))throw this.error("EBADF");
    const pos=f.flags&1024?f.node.data.length:(position===null?f.pos:position);if(pos+length>f.node.data.length)this.resize(f.node,pos+length);
    f.node.data.set(buffer.subarray(offset,offset+length),pos);if(position===null)f.pos=pos+length;f.node.time=Date.now();return length;
  });}
  mkdir(p,mode,cb) {this.operation(cb,()=>{p=this.resolve(p);if(this.nodes.has(p))throw this.error("EEXIST");if(!this.get(this.parent(p)).dir)throw this.error("ENOTDIR");if(this.nodes.size>=20000)throw this.error("ENOSPC");const n=this.node(true);n.mode=0o040000|mode;this.nodes.set(p,n);});}
  readdir(p,cb) {this.operation(cb,()=>{p=this.resolve(p);if(!this.get(p).dir)throw this.error("ENOTDIR");return [...this.nodes.keys()].filter(k=>k!==p&&this.parent(k)===p).map(k=>k.slice(k.lastIndexOf("/")+1)).sort();});}
  unlink(p,cb) {this.operation(cb,()=>{p=this.resolve(p);const n=this.get(p);if(n.dir)throw this.error("EISDIR");this.used-=n.data.length;this.allocated-=n.storage.length;this.nodes.delete(p);});}
  rmdir(p,cb) {this.operation(cb,()=>{p=this.resolve(p);if(!this.get(p).dir)throw this.error("ENOTDIR");if([...this.nodes.keys()].some(k=>k!==p&&this.parent(k)===p))throw this.error("ENOTEMPTY");this.nodes.delete(p);});}
  rename(from,to,cb) {this.operation(cb,()=>{from=this.resolve(from);to=this.resolve(to);this.get(from);this.get(this.parent(to));if(from===to)return;if(to.startsWith(from+"/"))throw this.error("EINVAL");const old=this.nodes.get(to);if(old&&!old.dir){this.used-=old.data.length;this.allocated-=old.storage.length;}for(const [p,n] of [...this.nodes])if(p===from||p.startsWith(from+"/")){this.nodes.delete(p);this.nodes.set(to+p.slice(from.length),n);}});}
  chmod(p,mode,cb) {this.operation(cb,()=>{const n=this.get(p);n.mode=(n.dir?0o040000:0o100000)|mode;});}
  fchmod(fd,mode,cb) {this.operation(cb,()=>{const n=this.descriptor(fd).node;n.mode=(n.dir?0o040000:0o100000)|mode;});}
  truncate(p,size,cb) {this.operation(cb,()=>this.resize(this.get(p),size));}
  ftruncate(fd,size,cb) {this.operation(cb,()=>this.resize(this.descriptor(fd).node,size));}
  fsync(fd,cb) {cb(null);}
  utimes(p,atime,mtime,cb) {this.operation(cb,()=>{this.get(p).time=mtime*1000;});}
  chown(p,uid,gid,cb) {this.operation(cb,()=>{this.get(p);});}
  lchown(p,uid,gid,cb) {this.chown(p,uid,gid,cb);}
  fchown(fd,uid,gid,cb) {this.operation(cb,()=>{this.descriptor(fd);});}
  link(p,link,cb) {cb(this.error("ENOSYS"));}
  symlink(p,link,cb) {cb(this.error("ENOSYS"));}
  readlink(p,cb) {cb(this.error("EINVAL"));}
  snapshot(root) {root=this.resolve(root);return [...this.nodes].filter(([p,n])=>!n.dir&&p.startsWith(root+"/")).map(([p,n])=>({path:p.slice(root.length+1),bytes:n.data.slice()}));}
  process() {return {argv0:"/analyzer",argv:["/analyzer"],pid:1,ppid:0,getuid:()=>1000,getgid:()=>1000,geteuid:()=>1000,getegid:()=>1000,getgroups:()=>[1000],umask:()=>0o077,cwd:()=>this.cwd,chdir:p=>{p=this.resolve(p);if(!this.get(p).dir)throw this.error("ENOTDIR");this.cwd=p;}};}
}
globalThis.MegaMemoryFS=MegaMemoryFS;
