// Execute the shipped hooks against bounded synthetic pointers and Java calls.
// No sample executable, device, or Frida installation is required.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const read = file => fs.readFileSync(path.join(__dirname, '..', file), 'utf8');
const win = read('pkg/internal/sandbox/frida_windows_default.js');
const android = read('pkg/internal/sandbox/frida_default.js');
const key = Buffer.from('000102030405060708090a0b0c0d0e0f', 'hex');
class Pointer {
  constructor(value = 0, data = null, offset = 0) { this.value = value; this.data = data; this.offset = offset; }
  isNull() { return !this.value; }
  toUInt32() { return this.value >>> 0; }
  toString() { return '0x' + this.value.toString(16); }
  add(n) { return new Pointer(this.value + n, this.data, this.offset + n); }
  readU32() { return this.data.readUInt32LE(this.offset); }
  readByteArray(n) {
    if (!this.data || this.offset + n > this.data.length) throw Error('unreadable');
    return Uint8Array.from(this.data.subarray(this.offset, this.offset + n)).buffer;
  }
}
const p = n => new Pointer(n), memory = b => new Pointer(100, b), output = n => ({target: p(n)});
const hooks = new Map();
const ctx = {
  Map, Uint8Array, attachExport: (cat, dll, name, spec) => hooks.set(name, spec),
  fmtPtr: v => v.toString(), readPointerSafe: out => out.target, readUtf16Safe: s => typeof s === 'string' ? s : '',
  fmtNTStatus() {}, fmtWin32Bool() {}, fmtU32Hex: v => v.toString(), readU32Safe: () => 0
};
vm.createContext(ctx);
vm.runInContext(win.slice(win.indexOf('/* ---- Category: Crypto'), win.indexOf('/* ---- Category: Registry')), ctx);
function call(name, args, status = '0x00000000') {
  const hook = hooks.get(name), state = {_params: [], _extra: {}};
  // attachExport preserves hook stability if a target pointer is unreadable.
  try { hook.onEnter?.call(state, args); } catch {}
  hook.onLeave?.call(state, p(0), status);
  return Object.fromEntries(state._params.map(v => [v.name, v.value]));
}
call('BCryptOpenAlgorithmProvider', [output(1), 'AES']);
let captured = call('BCryptGenerateSymmetricKey', [p(1), output(2), p(0), p(0), memory(key), p(key.length)]);
assert.equal(captured.KeyHex, key.toString('hex'));
assert.equal(captured.Algorithm, 'AES');
assert.equal(captured.hKey, '0x2');
assert.equal(call('BCryptGenerateSymmetricKey', [p(1), output(2), p(0), p(0), memory(key), p(16)], '0xC0000001').KeyHex, undefined);
assert.equal(call('BCryptGenerateSymmetricKey', [p(1), output(2), p(0), p(0), memory(key), p(257)]).KeyHex, undefined);
assert.equal(ctx.cryptoReadHex(p(0), 16), '');
assert.equal(ctx.cryptoReadHex(p(4), 16), '');
const blob = Buffer.alloc(28);
blob.writeUInt32LE(0x4d42444b, 0); blob.writeUInt32LE(1, 4); blob.writeUInt32LE(16, 8); key.copy(blob, 12);
const imported = data => call('BCryptImportKey', [p(1), p(0), 'KeyDataBlob', output(3), p(0), p(0), memory(data), p(data.length)]);
assert.equal(imported(blob).KeyHex, key.toString('hex'));
for (const offset of [0, 4, 8]) { const bad = Buffer.from(blob); bad.writeUInt32LE(999, offset); assert.equal(imported(bad).KeyHex, undefined); }
assert.equal(imported(Buffer.alloc(8)).KeyHex, undefined);
assert.equal(call('BCryptImportKey', [p(1), p(0), 'OpaqueKeyBlob', output(3), p(0), p(0), memory(blob), p(blob.length)]).KeyHex, undefined);
const iv = Buffer.alloc(16, 17);
const encryption = call('BCryptEncrypt', [p(2), p(0), p(16), p(0), memory(iv), p(16), p(9), p(16), p(0), p(0)]);
iv.fill(0); assert.equal(encryption.IVHex, '11'.repeat(16)); assert.equal(encryption.OutputPresent, 'true');
const query = call('BCryptEncrypt', [p(2), p(0), p(16), p(0), p(0), p(0), p(0), p(0), p(0), p(0)]);
assert.equal(query.OutputPresent, 'false');
call('BCryptCloseAlgorithmProvider', [p(1)]);
assert.equal(call('BCryptGenerateSymmetricKey', [p(1), output(2), p(0), p(0), memory(key), p(16)]).Algorithm, 'unknown');

// Android overloads must call the original first; failures cannot emit keys.
const events = [], overloads = new Map();
function overload(...args) {
  const id = args.join(',');
  if (!overloads.has(id)) overloads.set(id, {call(self, ...values) { if (self.fail) throw Error('original failed'); self.called = true; return 123; }});
  return overloads.get(id);
}
const cipherInit = {argumentTypes: [{className:'int'}, {className:'java.security.Key'}],
  apply(self) { if (self.fail) throw Error('original failed'); self.called = true; return 456; }};
const cipher = {getInstance: {overload}, init: {overloads: [cipherInit]}};
const androidCtx = {Process:{id:42}, Date, console:{log:line => events.push(JSON.parse(line.slice('FRIDA_EVT '.length)))}, send() {},
  emit() {}, safeHook(label, fn) { fn(); }, Java: {use(name) { if (name === 'javax.crypto.Cipher') return cipher; if (name === 'javax.crypto.spec.SecretKeySpec') return {$init:{overload}}; throw Error(name); }}};
vm.createContext(androidCtx);
vm.runInContext(android.slice(android.indexOf('function cryptoBytesHex'), android.indexOf('Java.perform')), androidCtx);
vm.runInContext(android.slice(android.indexOf('    /* ---- Crypto:'), android.indexOf("    safeHook('MessageDigest'")), androidCtx);
const signedKey = Array.from(key, b => b > 127 ? b-256 : b);
const constructor = overloads.get('[B,java.lang.String');
assert.equal(constructor.implementation.call({}, signedKey, 'AES'), 123);
assert.equal(events.at(-1).key_hex, key.toString('hex'));
const sliced = overloads.get('[B,int,int,java.lang.String');
sliced.implementation.call({}, [99, -1, -128, 0, 9], 1, 3, 'unknown');
assert.equal(events.at(-1).key_hex, 'ff8000');
const beforeFailure = events.length;
assert.throws(() => constructor.implementation.call({fail:true}, signedKey, 'AES'), /original failed/);
assert.equal(events.length, beforeFailure);
const instance = {getIV:()=>Array(16).fill(-1), getAlgorithm:()=>'AES/CBC/PKCS5Padding'};
assert.equal(cipherInit.implementation.call(instance, 2, {getEncoded:()=>signedKey}), 456);
assert.equal(events.at(-1).operation, 'decrypt'); assert.equal(events.at(-1).iv_hex, 'ff'.repeat(16));
const beforeKeystore = events.length;
assert.equal(cipherInit.implementation.call(instance, 1, {getEncoded:()=>null}), 456);
assert.equal(events.length, beforeKeystore);
assert.equal(androidCtx.cryptoBytesHex([1], 0, 2), '');
assert.equal(androidCtx.cryptoBytesHex(Array(257).fill(1), 0, 257), '');

// Render actual report HTML and verify sample-supplied strings stay text.
const app = read('pkg/cmd/analyzer/web/assets/app.js');
const escape = value => String(value).replace(/[&<>"']/g, ch => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[ch]));
const ui = {e:escape, baseName:s=>s||'', uiLang:'en'}; vm.createContext(ui);
vm.runInContext(app.slice(app.indexOf('function dtable('), app.indexOf('function wireTabs()')), ui);
const report = {executed:true, crypto_analysis:{status:'captured', rejected:1, truncated:true, materials:[{
  algorithm:'<img src=x onerror=alert(1)>', pid:42, key_hex:key.toString('hex'), key_bytes:16, iv_hex:'11'.repeat(16),
  function:'BCryptGenerateSymmetricKey', source:'frida-windows', operation:'key_creation', observations:2}]}};
const html = ui.renderSandbox(report);
assert.match(html, /Crypto keys/); assert.match(html, /Key material captured/); assert.match(html, /capture is partial/i);
assert.match(html, /&lt;img/); assert.doesNotMatch(html, /<img/); assert.match(html, /decryption has not been verified/);
assert.match(html, new RegExp(key.toString('hex')));
assert.match(ui.renderSandbox({crypto_analysis:{status:'not_instrumented'}}), /Enable API tracing/);
assert.match(ui.renderSandbox({crypto_analysis:{status:'no_material'}}), /No key material captured/);
assert.match(ui.renderSandbox({...report, execution_error:{code:'canceled'}}), new RegExp(key.toString('hex')));
console.log('PASS: CNG and Android key hooks, bounds, failure semantics, IV capture, report states and HTML escaping.');
