## dainim — the System One Transformer hot path in Nim (v1.12).
##
## Go keeps tokenisation, embeddings lookup and all decision logic; this library runs
## the expensive part (embedding LayerNorm + every encoder layer) on float32 buffers
## owned by Go. Exported with the C ABI so `semai` can call it through cgo
## (build tag `nim`, see semai/accel_nim.go). Same math as semai/encoder.go.
##
##   nim c --app:staticlib --noMain --mm:arc -d:danger --opt:speed \
##         --passC:-O3 --passC:-ffast-math --passC:-march=x86-64-v3 -o:libdainim.a nim/dainim.nim
## v1.15 FASM kernel (any AVX CPU, 2011+): fasm fagemm.asm fagemm.o, then add -d:fasm and
## append the object to the archive (ar rcs libdainim.a fagemm.o) — see BUILD-NIM-WINDOWS.cmd.
import std/math

const ompMinTokens = 32  ## v1.16 -d:omp: below this a forward pass stays single-threaded

when defined(fasm):
  ## v1.15: hand-written AVX GEMM in flat assembler (nim/fagemm.asm), linked as fagemm.o / fagemm.obj.
  ## Build with -d:fasm; weights are repacked into 8-output panels once, at load time.
  proc fa_gemm(x: ptr float32, n, inp: cint, wp, b: ptr float32, outp: cint, y: ptr float32) {.importc, cdecl.}

proc fexp(x: float32): float32 {.inline, raises: [].} =
  ## Cephes-style expf: 2^n · p(r), |rel err| ≲ 2e-7, branch-free so gcc vectorises the loops using it
  let xc = min(max(x, -87.0'f32), 88.0'f32)
  let fx = floor(xc * 1.44269504'f32 + 0.5'f32)
  let r = xc - fx * 0.693359375'f32 + fx * 2.12194440e-4'f32
  var y = 1.9875691500e-4'f32
  y = y * r + 1.3981999507e-3'f32
  y = y * r + 8.3334519073e-3'f32
  y = y * r + 4.1665795894e-2'f32
  y = y * r + 1.6666665459e-1'f32
  y = y * r + 5.0000001201e-1'f32
  y = y * r * r + r + 1'f32
  y * cast[float32]((int32(fx) + 127'i32) shl 23)

proc ferf(x: float32): float32 {.inline.} =
  ## Abramowitz–Stegun 7.1.26, |abs err| ≤ 1.5e-7
  let a = abs(x); let t = 1'f32 / (1'f32 + 0.3275911'f32 * a)
  let p = ((((1.061405429'f32 * t - 1.453152027'f32) * t + 1.421413741'f32) * t - 0.284496736'f32) * t + 0.254829592'f32) * t
  let e = 1'f32 - p * fexp(-a * a)
  if x < 0: -e else: e

{.push checks: off, boundChecks: off, overflowChecks: off, rangeChecks: off, nilChecks: off, stackTrace: off, lineTrace: off.}

type
  F32Arr = ptr UncheckedArray[float32]
  Lin = object
    w, b: seq[float32]
    wp: seq[float32]  # -d:fasm: W in panels of 8 outputs, wp[(p·in + i)·8 + j] = W[p·8 + j][i]
    inp, outp: int
  LN = object
    w, b: seq[float32]
  Layer = object
    q, k, v, o, f1, f2: Lin
    ln1, ln2: LN
  Model = object
    hidden, heads, inter: int
    eps: float32
    embLN: LN
    layers: seq[Layer]

var models: seq[ref Model]

proc dn_new(hidden, heads, inter, nlayers: cint, eps: cfloat): cint {.exportc, dynlib, cdecl.} =
  let m = new Model
  m.hidden = hidden; m.heads = heads; m.inter = inter; m.eps = eps
  m.layers = newSeq[Layer](nlayers)
  models.add m
  cint(models.len - 1)

proc copyIn(dst: var seq[float32], src: F32Arr, n: int) =
  dst = newSeq[float32](n)
  if n > 0: copyMem(addr dst[0], src, n * sizeof(float32))

proc dn_set(h, layer: cint, name: cstring, data: F32Arr, n, inp, outp: cint): cint {.exportc, dynlib, cdecl.} =
  ## name: emb_ln.w|b, or per layer q|k|v|o|f1|f2 .w|.b and ln1|ln2 .w|.b ; returns 0 on success
  if h < 0 or h >= cint(models.len): return 1
  let m = models[h]
  let s = $name
  if s == "emb_ln.w": copyIn(m.embLN.w, data, n); return 0
  if s == "emb_ln.b": copyIn(m.embLN.b, data, n); return 0
  if layer < 0 or layer >= cint(m.layers.len): return 2
  template L: untyped = m.layers[layer]
  template lin(x: untyped) =
    if s == astToStr(x) & ".w":
      L.x.inp = inp; L.x.outp = outp
      when defined(fasm):
        if outp mod 8 == 0 and n == inp * outp:
          # Pack directly from the caller buffer. dn_set completes the copy
          # before returning; no Go-owned pointer is retained in Nim.
          L.x.wp = newSeq[float32](n)
          for p in 0 ..< int(outp) div 8:
            for i in 0 ..< int(inp):
              for j in 0 ..< 8: L.x.wp[(p * inp + i) * 8 + j] = data[(p * 8 + j) * inp + i]
          L.x.w = @[]
        else:
          L.x.wp = @[]
          copyIn(L.x.w, data, n)
      else:
        copyIn(L.x.w, data, n)
      return 0
    if s == astToStr(x) & ".b": copyIn(L.x.b, data, n); return 0
  lin(q); lin(k); lin(v); lin(o); lin(f1); lin(f2)
  if s == "ln1.w": copyIn(L.ln1.w, data, n); return 0
  if s == "ln1.b": copyIn(L.ln1.b, data, n); return 0
  if s == "ln2.w": copyIn(L.ln2.w, data, n); return 0
  if s == "ln2.b": copyIn(L.ln2.b, data, n); return 0
  3

when defined(fasm):
  proc linChunk(c, n, ni, no: int, xa, ya: uint, wa, ba: ptr float32) {.raises: [], gcsafe.} =
    let t0 = c * 16
    fa_gemm(cast[ptr float32](xa + uint(t0 * ni * 4)), cint(min(16, n - t0)), cint(ni), wa, ba, cint(no),
            cast[ptr float32](ya + uint(t0 * no * 4)))

proc applyLin(l: Lin, x: openArray[float32], n: int, y: var seq[float32]) =
  ## y[n×out] = x[n×in]·Wᵀ + b ; 4 tokens share every weight-row load (register blocking)
  let ni = l.inp; let no = l.outp
  if y.len < n * no: y.setLen(n * no)
  when defined(fasm):
    if l.wp.len > 0:
      when defined(omp):
        if n >= ompMinTokens:
          # v1.16: rows are independent, so 16-token chunks run on all cores bit-exactly
          let xa = cast[uint](unsafeAddr x[0]); let ya = cast[uint](addr y[0])
          let wa = unsafeAddr l.wp[0]; let ba = unsafeAddr l.b[0]
          let chunks = (n + 15) div 16
          for c in `||`(0, chunks - 1, "parallel for schedule(static)"):
            linChunk(c, n, ni, no, xa, ya, wa, ba)
          return
      fa_gemm(unsafeAddr x[0], cint(n), cint(ni), unsafeAddr l.wp[0], unsafeAddr l.b[0], cint(no), addr y[0])
      return
  let w = cast[F32Arr](unsafeAddr l.w[0]); let xs = cast[F32Arr](unsafeAddr x[0])
  var t = 0
  while t + 4 <= n:
    let x0 = t * ni; let x1 = x0 + ni; let x2 = x1 + ni; let x3 = x2 + ni
    for o in 0 ..< no:
      let wr = o * ni
      var s0, s1, s2, s3: float32
      for i in 0 ..< ni:
        let wv = w[wr + i]
        s0 += xs[x0 + i] * wv; s1 += xs[x1 + i] * wv
        s2 += xs[x2 + i] * wv; s3 += xs[x3 + i] * wv
      let bo = l.b[o]
      y[t * no + o] = s0 + bo; y[(t + 1) * no + o] = s1 + bo
      y[(t + 2) * no + o] = s2 + bo; y[(t + 3) * no + o] = s3 + bo
    t += 4
  while t < n:
    let x0 = t * ni
    for o in 0 ..< no:
      let wr = o * ni
      var s: float32
      for i in 0 ..< ni: s += xs[x0 + i] * w[wr + i]
      y[t * no + o] = s + l.b[o]
    inc t

proc applyLN(p: LN, x: var openArray[float32], rows, d: int, eps: float32) =
  for r in 0 ..< rows:
    let o = r * d
    var mean = 0'f32
    for i in 0 ..< d: mean += x[o + i]
    mean /= float32(d)
    var vr = 0'f32
    for i in 0 ..< d:
      let z = x[o + i] - mean
      vr += z * z
    let inv = 1'f32 / sqrt(vr / float32(d) + eps)
    for i in 0 ..< d: x[o + i] = (x[o + i] - mean) * inv * p.w[i] + p.b[i]

when defined(fasm):
  proc headBody(hh, nn, hd, d, np, hdp: int, scale: float32, qa, ka, sa, va, oa, qq, kk, vv, cx: F32Arr,
                bza: ptr float32) {.raises: [], gcsafe.} =
    let off = hh * hd
    let qh = cast[F32Arr](addr qa[hh * nn * hd]); let kp = cast[F32Arr](addr ka[hh * np * hd])
    let sp = cast[F32Arr](addr sa[hh * nn * np]); let vp = cast[F32Arr](addr va[hh * np * hdp])
    let oh = cast[F32Arr](addr oa[hh * nn * hdp])
    for i in 0 ..< nn:
      for c in 0 ..< hd: qh[i * hd + c] = qq[i * d + off + c] * scale
    for i in 0 ..< np * hd: kp[i] = 0
    for j in 0 ..< nn:
      let pb = (j div 8) * hd * 8 + (j mod 8)
      for c in 0 ..< hd: kp[pb + c * 8] = kk[j * d + off + c]
    fa_gemm(addr qh[0], cint(nn), cint(hd), addr kp[0], bza, cint(np), addr sp[0])
    for i in 0 ..< nn:
      let r = i * np
      var mx = -1e30'f32
      for j in 0 ..< nn: mx = max(mx, sp[r + j])
      var z = 0'f32
      for j in 0 ..< nn:
        let e = fexp(sp[r + j] - mx); sp[r + j] = e; z += e
      let iz = 1'f32 / z
      for j in 0 ..< nn: sp[r + j] *= iz
      for j in nn ..< np: sp[r + j] = 0
    for i in 0 ..< np * hdp: vp[i] = 0
    for j in 0 ..< nn:
      for c in 0 ..< hd: vp[((c div 8) * np + j) * 8 + (c mod 8)] = vv[j * d + off + c]
    fa_gemm(addr sp[0], cint(nn), cint(np), addr vp[0], bza, cint(hdp), addr oh[0])
    for i in 0 ..< nn:
      for c in 0 ..< hd: cx[i * d + off + c] = oh[i * hdp + c]

proc dn_forward(h: cint, xp: F32Arr, n: cint): cint {.exportc, dynlib, cdecl.} =
  ## xp: n×hidden embeddings (word+pos+type), overwritten with the last hidden states
  if h < 0 or h >= cint(models.len) or n <= 0: return 1
  template m: untyped = models[h]  # no ref copy: refcounts are not atomic and Go calls from many threads
  let d = m.hidden; let nn = int(n); let hd = d div m.heads
  let scale = 1'f32 / sqrt(float32(hd))
  var x = newSeq[float32](nn * d)
  copyMem(addr x[0], xp, nn * d * sizeof(float32))
  applyLN(m.embLN, x, nn, d, m.eps)
  var q, k, v, ctx, a, f, g: seq[float32]
  var sc = newSeq[float32](nn)
  var kt = newSeq[float32](nn * d)   # keys transposed per head: [head][c][j] → contiguous over j
  when defined(fasm):
    let np = (nn + 7) div 8 * 8; let hdp = (hd + 7) div 8 * 8
    let nh = m.heads
    var qhA = newSeq[float32](nh * nn * hd); var kpA = newSeq[float32](nh * np * hd); var spA = newSeq[float32](nh * nn * np)
    var vpA = newSeq[float32](nh * np * hdp); var ohA = newSeq[float32](nh * nn * hdp); var bz = newSeq[float32](max(np, hdp))
  for L in m.layers:
    applyLin(L.q, x, nn, q); applyLin(L.k, x, nn, k); applyLin(L.v, x, nn, v)
    ctx.setLen(nn * d)
    for i in 0 ..< nn * d: ctx[i] = 0
    when defined(fasm):
      # per head: S = (Q·scale)·Kᵀ and ctx = softmax(S)·V as two packed GEMMs (keys padded to 8, head dim to 8)
      let qa = cast[F32Arr](addr qhA[0]); let ka = cast[F32Arr](addr kpA[0]); let sa = cast[F32Arr](addr spA[0])
      let va = cast[F32Arr](addr vpA[0]); let oa = cast[F32Arr](addr ohA[0]); let bza = addr bz[0]
      let qq = cast[F32Arr](addr q[0]); let kk = cast[F32Arr](addr k[0]); let vv = cast[F32Arr](addr v[0])
      let cx = cast[F32Arr](addr ctx[0])
      when defined(omp):
        if nn >= ompMinTokens:
          for hh in `||`(0, nh - 1, "parallel for schedule(static)"): headBody(hh, nn, hd, d, np, hdp, scale, qa, ka, sa, va, oa, qq, kk, vv, cx, bza)
        else:
          for hh in 0 ..< nh: headBody(hh, nn, hd, d, np, hdp, scale, qa, ka, sa, va, oa, qq, kk, vv, cx, bza)
      else:
        for hh in 0 ..< nh: headBody(hh, nn, hd, d, np, hdp, scale, qa, ka, sa, va, oa, qq, kk, vv, cx, bza)
    else:
      for hh in 0 ..< m.heads:
        let off = hh * hd
        for c in 0 ..< hd:
          for j in 0 ..< nn: kt[(off + c) * nn + j] = k[j * d + off + c]
        for i in 0 ..< nn:
          for j in 0 ..< nn: sc[j] = 0
          for c in 0 ..< hd:
            let qv = q[i * d + off + c]
            let kr = (off + c) * nn
            for j in 0 ..< nn: sc[j] += qv * kt[kr + j]
          var mx = -1e30'f32
          for j in 0 ..< nn:
            sc[j] *= scale
            if sc[j] > mx: mx = sc[j]
          var z = 0'f32
          for j in 0 ..< nn:
            sc[j] = fexp(sc[j] - mx); z += sc[j]
          let iz = 1'f32 / z
          for j in 0 ..< nn:
            let p = sc[j] * iz
            let vo = j * d + off; let co = i * d + off
            for c in 0 ..< hd: ctx[co + c] += p * v[vo + c]
    applyLin(L.o, ctx, nn, a)
    for i in 0 ..< nn * d: a[i] += x[i]
    applyLN(L.ln1, a, nn, d, m.eps)
    applyLin(L.f1, a, nn, f)
    for i in 0 ..< f.len:
      let t = f[i]
      f[i] = 0.5'f32 * t * (1'f32 + ferf(t * 0.70710678'f32))
    applyLin(L.f2, f, nn, g)
    for i in 0 ..< nn * d: g[i] += a[i]
    applyLN(L.ln2, g, nn, d, m.eps)
    x = g
  copyMem(xp, addr x[0], nn * d * sizeof(float32))
  0

proc dn_kind(): cint {.exportc, dynlib, cdecl.} =
  ## v1.16.1: bit 1 = FASM AVX kernel linked, bit 2 = OpenMP multi-core forward
  result = 0
  when defined(fasm): result = result or 1
  when defined(omp): result = result or 2

{.pop.}
