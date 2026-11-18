const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const {createDOM} = require('./ui-test-dom.cjs');
const assets = path.join(__dirname, '../pkg/cmd/analyzer/web/assets');
const source = fs.readFileSync(path.join(assets, 'app.js'), 'utf8');
const {document, ids} = createDOM(fs.readFileSync(path.join(assets, 'index.html'), 'utf8'));
const timers = new Map(), intervals = new Map(), clients = [], decoders = [], requests = [], imageURLs = [];
let sequence = 0, draws = 0;
const img = ids.liveScreen;
Object.defineProperty(img, 'src', {
  get() { return this.attributes.src || ''; },
  set(value) { this.attributes.src = value; imageURLs.push(value); },
});
img.naturalWidth = 640; img.naturalHeight = 480;
ids.liveCanvas.getContext = () => ({
  drawImage() { draws++; },
  getImageData() { return {data: new Uint8Array(100).fill(255)}; },
});
class Decoder {
  constructor(callbacks) { this.callbacks = callbacks; decoders.push(this); }
  configure(config) {
    this.config = config;
    if (config.description) throw new Error('Annex-B is not an avcC configuration record');
  }
  decode(chunk) { if (this.rejectDecode) throw new Error('Unsupported video frame'); this.chunk = chunk; }
  close() { this.closed = true; }
}
class Socket {
  constructor(url) { this.url = url; clients.push(this); }
  close() { this.closed = true; this.onclose?.(); }
}
const ctx = {
  document, window: {VideoDecoder: Decoder}, VideoDecoder: Decoder, WebSocket: Socket,
  EncodedVideoChunk: class { constructor(data) { Object.assign(this, data); } },
  AbortController, Uint8Array, Date, uiLang: 'en', sbxHasFrame: false,
  curMode: 'sandbox', curEnv: 'android', sbxViewPhase: 'setup', sbxViewMode: 'output',
  isVMwareTarget: () => false, stopVMwareScreen() {}, startVMwareScreen() {}, vmwareScreenState: {},
  jid: 'job-A', curTarget: {serial: 'phone-A'}, location: {protocol: 'http:', host: '127.0.0.1:7474'},
  uiText: (id, value) => { ids[id].textContent = value; }, _attachLiveEvents() {},
  fetch: (url, options) => new Promise(resolve => requests.push({url, options, resolve})),
  setTimeout: (fn, ms) => { const id = ++sequence; timers.set(id, {fn, ms}); return id; },
  clearTimeout: id => timers.delete(id),
  setInterval: (fn, ms) => { const id = ++sequence; intervals.set(id, {fn, ms}); return id; },
  clearInterval: id => intervals.delete(id),
};
vm.createContext(ctx);
vm.runInContext(source.slice(source.indexOf('// ── live android view'), source.indexOf('// Attach pointer events once')), ctx);
vm.runInContext(source.slice(source.indexOf('function nalContains('), source.indexOf('var _lpTimer=')), ctx);
vm.runInContext(source.slice(source.indexOf('function switchSbxView('), source.indexOf('var vmwareScreenState=')), ctx);
const accessUnit = new Uint8Array([0, 0, 0, 1, 0x67, 0x42, 0xc0, 0x1e, 0x80, 0, 0, 1, 0x68, 0x80, 0, 0, 1, 0x65, 0x80]);
function startVideo() { ctx.liveStop(false); ctx.sbxHasFrame = false; ctx.liveStreaming = true; ctx.startVideo(); }
function fireTimer(ms) {
  const timer = [...timers.entries()].find(([, entry]) => entry.ms === ms);
  assert.ok(timer, `Missing ${ms} ms timer`); timers.delete(timer[0]); timer[1].fn();
}
const tick = () => new Promise(resolve => setImmediate(resolve));

(async () => {
  startVideo();
  clients.at(-1).onmessage({data: accessUnit.buffer});
  const decoder = decoders.at(-1), socket = clients.at(-1);
  assert.equal(ctx.liveMode, 'video', 'Annex-B configuration fell back before decoding');
  assert.equal(decoder.config.description, undefined);
  assert.equal(decoder.config.codec, 'avc1.42c01e');
  assert.ok(decoder.chunk);
  decoder.callbacks.error(new Error('Decoder failed after configuration'));
  assert.equal(ctx.liveMode, 'mjpeg', 'Configured decoder errors must switch to screenshots');
  assert.equal(socket.closed, true); assert.equal(decoder.closed, true);
  assert.match(img.src, /\/api\/live\/stream\?.*job=job-A/);
  img.onerror();
  assert.equal(ctx.liveMode, 'png');
  assert.match(img.src, /\/api\/live\/screen\?job=job-A&t=/);
  img.onload();
  assert.equal(ctx.sbxHasFrame, true); assert.equal(ids.sbxStreamPlaceholder.hidden, true);
  const before = imageURLs.length; fireTimer(500);
  assert.equal(imageURLs.length, before + 1, 'PNG fallback must keep refreshing');
  const lateLoad = img.onload;
  ctx.liveStop(true);
  assert.equal(img.src, '', 'Stop must release the ADB multipart/image connection');
  assert.equal(ids.liveCanvas.style.display, ''); assert.ok(draws > 0);
  assert.equal(timers.size, 0); lateLoad(); assert.equal(timers.size, 0);

  // Android 14 can close the multipart response before the job's done event.
  // The decoded image then disappears, but its last captured pixels must stay.
  startVideo(); decoders.at(-1).callbacks.error(new Error('Use multipart frames'));
  img.naturalWidth = 1080; img.naturalHeight = 1920; img.onload();
  const retainInterval = [...intervals.values()].find(timer => timer.ms === 500);
  assert.ok(retainInterval, 'Multipart frames must be retained while decodable');
  retainInterval.fn();
  assert.equal(ids.liveCanvas.width, 1080); assert.equal(ids.liveCanvas.height, 1920);
  img.naturalWidth = 0; img.naturalHeight = 0; img.removeAttribute('src');
  ctx.liveStop(true); ctx.liveStop(true);
  assert.equal(ids.liveCanvas.style.display, '', 'Repeated completion handlers must keep the recorded frame');
  assert.equal(ctx.sbxHasFrame, true); assert.equal(ids.sbxStreamPlaceholder.hidden, true);
  assert.equal(intervals.size, 0, 'Stop must release the multipart retention timer');
  ctx.liveStop(false); assert.equal(ctx.liveCanvasHasFrame, false);

  // No decoded pixels must be reported as no frame, including failed captures.
  startVideo(); ctx.sbxHasFrame = true; ctx.liveStop(true);
  assert.equal(ctx.sbxHasFrame, false); assert.equal(ids.sbxStreamPlaceholder.hidden, false);
  img.naturalWidth = 640; img.naturalHeight = 480;

  startVideo();
  decoders.at(-1).callbacks.output({displayWidth: 640, displayHeight: 480, close() {}});
  ctx.liveStop(true);
  assert.equal(ids.liveCanvas.style.display, '', 'A decoded video frame must also survive Stop');
  assert.equal(ctx.sbxHasFrame, true);

  startVideo(); fireTimer(12000);
  assert.equal(ctx.liveMode, 'mjpeg', 'A socket with no frames must time out');
  fireTimer(12000);
  assert.equal(ctx.liveMode, 'png', 'An empty multipart stream must fall back to individual frames');
  img.onerror(); const staleRetry = [...timers.values()].find(t => t.ms === 1000).fn;
  ctx.liveStop(false); staleRetry();
  assert.equal(img.src, ''); assert.equal(timers.size, 0, 'A stopped session must not reconnect');

  startVideo(); clients.at(-1).onclose();
  assert.equal(ctx.liveMode, 'mjpeg', 'Closed video sockets must use the working fallback');
  startVideo(); const oldClose = clients.at(-1).onclose;
  startVideo(); oldClose();
  assert.equal(ctx.liveMode, 'video', 'A stale connection must not interrupt a newer session');
  decoders.at(-1).rejectDecode = true; clients.at(-1).onmessage({data: accessUnit.buffer});
  assert.equal(ctx.liveMode, 'mjpeg', 'Synchronous decode failures must use the fallback');
  ctx.liveStop(false);

  const clientCount = clients.length;
  ctx.liveStart(); const staleStatus = requests.at(-1); ctx.liveTick();
  assert.equal(requests.length, 1, 'Slow status polls must not overlap');
  ctx.liveStop(false);
  assert.equal(staleStatus.options.signal.aborted, true);
  staleStatus.resolve({ok: true, json: async () => ({serial: 'phone-A', booted: true, scrcpy: true})});
  await tick();
  assert.equal(clients.length, clientCount, 'Late status responses must not revive a stopped screen');
  assert.equal(intervals.size, 0); assert.equal(timers.size, 0);

  requests.length = 0; ctx.jid = null;
  ctx.switchSbxView('screen');
  assert.equal(ids.sbxAndroidStream.style.display, 'flex');
  assert.equal(ids.sbxVmIdle.style.display, 'none');
  assert.match(requests.at(-1).url, /serial=phone-A$/);
  assert.equal(ctx.jid, null, 'Opening Screen must not start an analysis');
  requests.at(-1).resolve({ok:true, json:async()=>({serial:'phone-A',booted:true,scrcpy:false})});
  await tick(); ctx.syncSbxView();
  assert.equal(requests.length, 1, 'Screen re-renders must not restart the same preview');
  ctx.curTarget = {serial:'phone-B'}; ctx.syncSbxView();
  assert.match(requests.at(-1).url, /serial=phone-B$/);
  assert.equal(img.src, '', 'Selecting another device must release the old screen');
  const pendingPreview = requests.at(-1);
  ctx.switchSbxView('output');
  assert.equal(ids.sbxAndroidStream.style.display, 'none');
  assert.equal(ids.sbxVmIdle.style.display, 'flex');
  assert.equal(pendingPreview.options.signal.aborted, true);
  pendingPreview.resolve({ok:true,json:async()=>({serial:'phone-B',booted:true,scrcpy:true})});
  await tick();
  assert.equal(ctx.liveTimer, null); assert.equal(timers.size, 0); assert.equal(img.src, '');
  console.log('PASS: Android preview before analysis, device switching, Annex-B video, decoder failures, missing frames, socket closure, PNG fallback, retained frames after multipart closure/repeated completion, Stop, and stale callbacks.');
})().catch(error => { console.error(error); process.exitCode = 1; });
