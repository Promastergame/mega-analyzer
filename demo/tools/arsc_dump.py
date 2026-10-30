import struct, sys, collections, os

def u16(b,o): return struct.unpack_from('<H',b,o)[0]
def u32(b,o): return struct.unpack_from('<I',b,o)[0]

UTF8 = 1<<8
SORTED = 1

def pool(b, off):
    hs = u16(b,off+2); size = u32(b,off+4)
    cnt = u32(b,off+8); scnt = u32(b,off+12); flags = u32(b,off+16)
    ss = u32(b,off+20)
    utf8 = bool(flags & UTF8)
    offs = [u32(b,off+hs+4*i) for i in range(cnt)]
    base = off+ss
    out = []
    for o in offs:
        p = base+o
        try:
            if utf8:
                if b[p] & 0x80: p += 2
                else: p += 1
                n = b[p]
                if n & 0x80:
                    n = ((n & 0x7f)<<8)|b[p+1]; p += 2
                else: p += 1
                out.append(b[p:p+n].decode('utf-8','replace'))
            else:
                n = u16(b,p)
                if n & 0x8000:
                    n = ((n & 0x7fff)<<16)|u16(b,p+2); p += 4
                else: p += 2
                out.append(b[p:p+2*n].decode('utf-16-le','replace'))
        except Exception:
            out.append('<ERR>')
    return {'hs':hs,'size':size,'count':cnt,'styles':scnt,'flags':flags,
            'utf8':utf8,'sorted':bool(flags&SORTED),'s':out}

def unpack_lang(x, base):
    if x[0]==0 and x[1]==0: return ''
    if x[0] & 0x80:
        v = (x[1]<<8)|x[0]
        return chr(base+(v&0x1f))+chr(base+((v>>5)&0x1f))+chr(base+((v>>10)&0x1f))
    return bytes(x).decode('ascii','replace').rstrip('\x00')

def cfg(b,o):
    sz = u32(b,o)
    lang = unpack_lang(b[o+8:o+10], 0x61)
    ctry = unpack_lang(b[o+10:o+12], 0x30)
    dens = u16(b,o+14) if sz>=16 else 0
    sdk = u16(b,o+24) if sz>=26 else 0
    return sz, lang, ctry, dens, sdk

def main(path):
    b = open(path,'rb').read()
    print('===== %s  %d bytes' % (os.path.basename(path), len(b)))
    t = u16(b,0); hs = u16(b,2); sz = u32(b,4); pc = u32(b,8)
    print('ResTable type=0x%04x hdr=%d size=%d pkgCount=%d trailing=%d' % (t,hs,sz,pc,len(b)-sz))
    off = hs; gp = None; pkgs = []; other = []
    while off < min(sz,len(b)):
        ct = u16(b,off); csz = u32(b,off+4)
        if csz == 0: break
        if ct == 0x0001 and gp is None: gp = pool(b,off)
        elif ct == 0x0200: pkgs.append(off)
        else: other.append(hex(ct))
        off += csz
    if other: print('other top chunks: %s' % other[:8])
    if gp:
        d = collections.Counter(gp['s'])
        dup = sum(v-1 for v in d.values() if v>1)
        print('globalPool n=%d utf8=%s sorted=%s styles=%d dups=%d chars=%d' % (
            gp['count'],gp['utf8'],gp['sorted'],gp['styles'],dup,sum(len(x) for x in gp['s'])))
        res = [x for x in gp['s'] if x.startswith('res/')]
        flat = sum(1 for x in res if '/' not in x[4:])
        print('res paths=%d flat=%d sample=%s' % (len(res),flat,res[:3]))
        urls = sorted(set(x for x in gp['s'] if x.startswith('http')))
        print('urls=%d %s' % (len(urls), urls[:5]))
    for po in pkgs:
        pid = u32(b,po+8)
        name = b[po+12:po+12+256].decode('utf-16-le','replace').split('\x00')[0]
        phs = u16(b,po+2); end = po + u32(b,po+4)
        ts = u32(b,po+268); lpt = u32(b,po+272); ks = u32(b,po+276); lpk = u32(b,po+280)
        tio = u32(b,po+284) if phs > 0x011c else None
        print('PKG id=0x%02x name=%s hdr=%d lastPubType=%d lastPubKey=%d typeIdOffset=%s' % (
            pid,name,phs,lpt,lpk,tio))
        tp = pool(b,po+ts); kp = pool(b,po+ks)
        print('  typeStr=%d(utf8=%s) keyStr=%d(utf8=%s sorted=%s)' % (
            tp['count'],tp['utf8'],kp['count'],kp['utf8'],kp['sorted']))
        types = collections.defaultdict(lambda: {'cfgs':0,'entries':0,'loc':set(),'sp':0,'o16':0})
        libs=[]; staged=0; ovl=0; specs=0; sdks=set(); dens=set()
        o = po + phs
        while o < end:
            ct = u16(b,o); csz = u32(b,o+4)
            if csz==0: break
            if ct==0x0201:
                tid = b[o+8]; fl = b[o+9]; ec = u32(b,o+12)
                _,l,c,dn,sdk = cfg(b,o+20)
                nm = tp['s'][tid-1] if 0 < tid <= tp['count'] else '?%d'%tid
                e = types[nm]; e['cfgs']+=1; e['entries']=max(e['entries'],ec)
                if l: e['loc'].add(l+('-'+c if c else ''))
                if fl & 1: e['sp']+=1
                if fl & 2: e['o16']+=1
                if sdk: sdks.add(sdk)
                if dn: dens.add(dn)
            elif ct==0x0202: specs+=1
            elif ct==0x0203:
                n = u32(b,o+8)
                for i in range(n):
                    e = o+12+i*260
                    libs.append((u32(b,e), b[e+4:e+260].decode('utf-16-le','replace').split('\x00')[0]))
            elif ct==0x0206: staged+=1
            elif ct in (0x0204,0x0205): ovl+=1
            o += csz
        sp = sum(e['sp'] for e in types.values()); o16 = sum(e['o16'] for e in types.values())
        print('  specs=%d types=%d libs=%d staged=%d overlayable=%d sparse=%d offset16=%d' % (
            specs,len(types),len(libs),staged,ovl,sp,o16))
        for lid,ln in libs[:8]: print('   LIB 0x%02x %s' % (lid,ln))
        locs = set()
        for e in types.values(): locs |= e['loc']
        print('  locales=%d %s' % (len(locs), sorted(locs)[:12]))
        print('  sdks=%s densities=%s' % (sorted(sdks)[:10], sorted(dens)[:10]))
        for nm,e in sorted(types.items(), key=lambda kv:-kv[1]['cfgs'])[:10]:
            print('   %-13s entries=%-6d cfgs=%-4d loc=%d' % (nm,e['entries'],e['cfgs'],len(e['loc'])))

if __name__ == '__main__':
    for p in sys.argv[1:]:
        try: main(p)
        except Exception as ex: print('FAIL %s: %r' % (p,ex))
        print()
