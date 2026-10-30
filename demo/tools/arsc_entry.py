import sys, collections
import arsc_dump as A

# Resolves string-typed resource entries to their actual values.
# Only handles the plain (non-sparse, non-offset16) entry layout, which is what
# all sampled files use.

def parse(path):
    b = open(path, 'rb').read()
    hs = A.u16(b, 2); sz = A.u32(b, 4)
    off = hs; gp = None; po = None
    while off < min(sz, len(b)):
        ct = A.u16(b, off); csz = A.u32(b, off + 4)
        if csz == 0: break
        if ct == 0x0001 and gp is None: gp = A.pool(b, off)
        if ct == 0x0200 and po is None: po = off
        off += csz
    phs = A.u16(b, po + 2); end = po + A.u32(b, po + 4)
    tp = A.pool(b, po + A.u32(b, po + 268))
    kp = A.pool(b, po + A.u32(b, po + 276))
    out = collections.defaultdict(list)
    o = po + phs
    while o < end:
        ct = A.u16(b, o); csz = A.u32(b, o + 4)
        if csz == 0: break
        if ct == 0x0201:
            tid = b[o + 8]; fl = b[o + 9]
            ec = A.u32(b, o + 12); es = A.u32(b, o + 16)
            thdr = A.u16(b, o + 2)
            tn = tp['s'][tid - 1] if 0 < tid <= tp['count'] else '?%d' % tid
            _, lang, ctry, _, _ = A.cfg(b, o + 20)
            loc = (lang + ('-' + ctry if ctry else '')) or 'default'
            if not (fl & 3):
                for i in range(ec):
                    eo = A.u32(b, o + thdr + 4 * i)
                    if eo == 0xFFFFFFFF: continue
                    ep = o + es + eo
                    if ep + 8 > len(b): continue
                    esz = A.u16(b, ep); efl = A.u16(b, ep + 2); ki = A.u32(b, ep + 4)
                    if efl & 1: continue
                    key = kp['s'][ki] if ki < kp['count'] else '?%d' % ki
                    vp = ep + esz
                    if vp + 8 > len(b): continue
                    dt = b[vp + 3]; data = A.u32(b, vp + 4)
                    if dt == 0x03 and data < gp['count']:
                        out[(tn, key)].append((loc, gp['s'][data]))
        o += csz
    return out

WANT = ('app_name', 'application_name', 'app_label', 'title', 'launcher_name')
BRAND = ('SandCraft', 'Sandboxels', 'sandboxels', 'sandcraft')

for path in sys.argv[1:]:
    print('== %s' % path)
    try:
        out = parse(path)
    except Exception as ex:
        print('   FAIL %r' % (ex,)); continue
    for (tn, key), vals in out.items():
        if tn == 'string' and key in WANT:
            print('   %s/%s default=%r locales=%d' % (
                tn, key, dict(vals).get('default'), len(vals)))
    hits = []
    for (tn, key), vals in out.items():
        for loc, v in vals:
            if v in BRAND:
                hits.append((tn, key, loc, v))
    print('   brand hits: %s' % (sorted(set(hits))[:8],))
    print('   string entries resolved: %d keys' % sum(
        1 for (tn, k) in out if tn == 'string'))
