import sys, struct, collections
import arsc_dump as A

# Binary AndroidManifest.xml (AXML) parser.
# Chunk types: 0x0003 root, 0x0001 string pool, 0x0180 resource map,
# 0x0100/0x0101 namespace, 0x0102/0x0103 element, 0x0104 cdata.

DT = {0x00: 'null', 0x01: 'ref', 0x02: 'attr', 0x03: 'str', 0x04: 'float',
      0x05: 'dim', 0x06: 'frac', 0x10: 'int', 0x11: 'hex', 0x12: 'bool'}


def sval(dt, data, sp):
    if dt == 0x03:
        return sp[data] if 0 <= data < len(sp) else '?%d' % data
    if dt == 0x12:
        return 'true' if data else 'false'
    if dt == 0x01:
        return '@0x%08x' % data
    if dt == 0x10:
        return str(data - 0x100000000 if data >= 0x80000000 else data)
    if dt == 0x11:
        return '0x%x' % data
    if dt == 0x04:
        return '%g' % struct.unpack('<f', struct.pack('<I', data))[0]
    return '%s:0x%x' % (DT.get(dt, hex(dt)), data)


def parse(path):
    b = open(path, 'rb').read()
    rtype = A.u16(b, 0); rhs = A.u16(b, 2); rsz = A.u32(b, 4)
    info = {'path': path, 'size': len(b), 'root_type': rtype,
            'declared': rsz, 'trailing': len(b) - rsz}
    off = rhs
    sp = None; spmeta = None; resmap = []
    events = []
    ns = []
    while off + 8 <= min(rsz, len(b)):
        ct = A.u16(b, off); chs = A.u16(b, off + 2); csz = A.u32(b, off + 4)
        if csz == 0:
            break
        if ct == 0x0001 and sp is None:
            p = A.pool(b, off); sp = p['s']; spmeta = p
        elif ct == 0x0180:
            n = (csz - chs) // 4
            resmap = [A.u32(b, off + chs + 4 * i) for i in range(n)]
        elif ct == 0x0100:
            pre = A.u32(b, off + chs); uri = A.u32(b, off + chs + 4)
            ns.append((sp[pre] if pre < len(sp) else '', sp[uri] if uri < len(sp) else ''))
        elif ct == 0x0102:
            ax = off + chs
            nsi = A.u32(b, ax); nmi = A.u32(b, ax + 4)
            astart = A.u16(b, ax + 8); asize = A.u16(b, ax + 10)
            acount = A.u16(b, ax + 12)
            name = sp[nmi] if nmi < len(sp) else '?'
            attrs = []
            for i in range(acount):
                ap = ax + astart + i * asize
                if ap + 20 > len(b):
                    break
                ani = A.u32(b, ap); anm = A.u32(b, ap + 4)
                dt = b[ap + 15]; data = A.u32(b, ap + 16)
                an = sp[anm] if anm < len(sp) else '?%d' % anm
                pfx = ''
                if ani != 0xFFFFFFFF and ani < len(sp):
                    u = sp[ani]
                    pfx = 'android:' if u.endswith('/android') else 'ns:'
                attrs.append((pfx + an, sval(dt, data, sp), dt))
            events.append(('start', name, attrs))
        elif ct == 0x0103:
            nmi = A.u32(b, off + chs + 4)
            events.append(('end', sp[nmi] if nmi < len(sp) else '?', None))
        off += csz
    info['pool'] = spmeta
    info['resmap'] = len(resmap)
    info['ns'] = ns
    return info, events


def summarize(info, events):
    out = collections.OrderedDict()
    perms = []; feats = []; comps = collections.Counter()
    authorities = []; flags = {}; sdk = {}
    classes = []
    for kind, name, attrs in events:
        if kind != 'start':
            continue
        d = dict((k, v) for k, v, _ in attrs)
        if name == 'manifest':
            for k in ('package', 'platformBuildVersionName', 'platformBuildVersionCode',
                      'android:compileSdkVersion', 'android:compileSdkVersionCodename',
                      'android:versionCode', 'android:versionName'):
                if k in d:
                    out[k] = d[k]
        elif name == 'uses-sdk':
            for k in ('android:minSdkVersion', 'android:targetSdkVersion'):
                if k in d:
                    sdk[k] = d[k]
        elif name == 'uses-permission':
            perms.append(d.get('android:name', '?'))
        elif name == 'uses-feature':
            feats.append(d.get('android:name', d.get('android:glEsVersion', '?')))
        elif name == 'application':
            for k in ('android:debuggable', 'android:testOnly', 'android:allowBackup',
                      'android:extractNativeLibs', 'android:usesCleartextTraffic',
                      'android:networkSecurityConfig', 'android:name',
                      'android:hardwareAccelerated', 'android:appComponentFactory'):
                if k in d:
                    flags[k] = d[k]
        elif name in ('activity', 'service', 'receiver', 'provider', 'activity-alias'):
            comps[name] += 1
            cn = d.get('android:name', '')
            if cn:
                classes.append(cn)
            if name == 'provider' and 'android:authorities' in d:
                authorities.append(d['android:authorities'])
    return out, sdk, perms, feats, flags, comps, authorities, classes


if __name__ == '__main__':
    tree = '--tree' in sys.argv
    for path in [a for a in sys.argv[1:] if not a.startswith('--')]:
        info, events = parse(path)
        p = info['pool']
        dups = 0
        if p:
            c = collections.Counter(p['s'])
            dups = sum(v - 1 for v in c.values() if v > 1)
        print('===== %s  %d bytes' % (path, info['size']))
        print('root=0x%04x declared=%d trailing=%d resourceMap=%d' % (
            info['root_type'], info['declared'], info['trailing'], info['resmap']))
        if p:
            print('pool n=%d utf8=%s sorted=%s dups=%d' % (
                p['count'], p['utf8'], p['sorted'], dups))
        print('namespaces=%s' % (info['ns'],))
        out, sdk, perms, feats, flags, comps, auth, classes = summarize(info, events)
        for k, v in out.items():
            print('  %-38s %s' % (k, v))
        for k, v in sdk.items():
            print('  %-38s %s' % (k, v))
        print('  application flags:')
        for k, v in flags.items():
            print('    %-36s %s' % (k, v))
        print('  components: %s (total %d)' % (dict(comps), sum(comps.values())))
        print('  permissions (%d): %s' % (len(perms), perms[:10]))
        print('  features (%d): %s' % (len(feats), feats[:6]))
        print('  authorities: %s' % (auth[:6],))
        pkg = out.get('package', '')
        foreign = sorted(set(c for c in classes
                             if c.startswith('.') is False and '.' in c
                             and pkg and not c.startswith(pkg)
                             and not c.startswith('android')))
        print('  component classes=%d foreign-prefix=%d' % (len(classes), len(foreign)))
        for c in foreign[:8]:
            print('    ! %s' % c)
        if tree:
            depth = 0
            for kind, name, attrs in events:
                if kind == 'end':
                    depth -= 1
                    continue
                print('  %s<%s%s>' % ('  ' * depth, name,
                      ''.join(' %s=%r' % (k, v) for k, v, _ in attrs)))
                depth += 1
        print()
