/*
 * Default instrumentation for Mega-Analyzer sandbox sessions.
 *
 * Every hook here answers a question an analyst actually asks about an Android
 * sample. Nothing is logged just because it is hookable: high-frequency, low
 * signal surfaces (String operations, SharedPreferences reads, Base64) are
 * deliberately left alone so the transcript stays readable on a real app.
 *
 * Output is one JSON object per line prefixed with FRIDA_EVT so the Go side can
 * count and classify events without parsing free text.
 */

function emit(category, action, detail) {
    try {
        send({ cat: category, act: action, detail: detail });
        console.log('FRIDA_EVT ' + JSON.stringify({
            t: Date.now(),
            cat: category,
            act: action,
            detail: detail
        }));
    } catch (e) {
        /* never let logging break the target */
    }
}

function shortStack() {
    try {
        return Java.use('android.util.Log')
            .getStackTraceString(Java.use('java.lang.Exception').$new())
            .split('\n').slice(1, 4).join(' <- ');
    } catch (e) {
        return '';
    }
}

function safeHook(label, fn) {
    try {
        fn();
    } catch (e) {
        emit('hook', 'unavailable', label + ': ' + e.message);
    }
}

// Only bounded key/IV material is emitted; file and plaintext buffers are not copied.
function cryptoBytesHex(bytes, offset, length) {
    if (!bytes || length <= 0 || length > 256 || offset < 0 || offset + length > bytes.length) return '';
    var out = '';
    for (var i = offset; i < offset + length; i++) out += ('0' + (bytes[i] & 255).toString(16)).slice(-2);
    return out;
}
function emitCryptoKey(action, algorithm, keyHex, ivHex, operation) {
    try {
        if (!keyHex) return;
        console.log('FRIDA_EVT ' + JSON.stringify({t: Date.now(), cat: 'crypto_key', act: action,
            pid: Process.id, algorithm: String(algorithm), key_hex: keyHex, iv_hex: ivHex || '', operation: operation}));
    } catch (e) { /* instrumentation must not change sample execution */ }
}

Java.perform(function () {
    emit('session', 'attached', 'frida ' + Frida.version + ' on ' + Java.androidVersion);

    /* ---- Dynamic code loading -------------------------------------------
     * The single highest value hook for Android malware. Droppers keep the
     * real payload out of the shipped DEX and load it at runtime.
     */
    safeHook('DexClassLoader', function () {
        var DexClassLoader = Java.use('dalvik.system.DexClassLoader');
        DexClassLoader.$init.overload(
            'java.lang.String', 'java.lang.String', 'java.lang.String', 'java.lang.ClassLoader'
        ).implementation = function (dexPath, optDir, libPath, parent) {
            emit('codeload', 'DexClassLoader', dexPath);
            return this.$init(dexPath, optDir, libPath, parent);
        };
    });

    safeHook('InMemoryDexClassLoader', function () {
        var InMem = Java.use('dalvik.system.InMemoryDexClassLoader');
        InMem.$init.overload('java.nio.ByteBuffer', 'java.lang.ClassLoader')
            .implementation = function (buf, parent) {
                emit('codeload', 'InMemoryDexClassLoader', 'in-memory dex, ' +
                    (buf ? buf.remaining() : 0) + ' bytes');
                return this.$init(buf, parent);
            };
    });

    safeHook('System.load', function () {
        var System = Java.use('java.lang.System');
        System.load.implementation = function (path) {
            emit('codeload', 'System.load', path);
            return this.load(path);
        };
        System.loadLibrary.implementation = function (name) {
            emit('codeload', 'System.loadLibrary', name);
            return this.loadLibrary(name);
        };
    });

    /* ---- Command execution ---------------------------------------------- */
    safeHook('Runtime.exec', function () {
        var Runtime = Java.use('java.lang.Runtime');
        Runtime.exec.overload('java.lang.String').implementation = function (cmd) {
            emit('exec', 'Runtime.exec', cmd);
            return this.exec(cmd);
        };
        Runtime.exec.overload('[Ljava.lang.String;').implementation = function (cmds) {
            emit('exec', 'Runtime.exec[]', cmds ? cmds.join(' ') : '');
            return this.exec(cmds);
        };
    });

    safeHook('ProcessBuilder', function () {
        var PB = Java.use('java.lang.ProcessBuilder');
        PB.start.implementation = function () {
            var cmd = '';
            try { cmd = this.command().toString(); } catch (e) { /* ignore */ }
            emit('exec', 'ProcessBuilder.start', cmd);
            return this.start();
        };
    });

    /* ---- Crypto: capture successful construction/init, including per-call IVs. */
    safeHook('Cipher', function () {
        var Cipher = Java.use('javax.crypto.Cipher');
        Cipher.getInstance.overload('java.lang.String').implementation = function (t) {
            emit('crypto', 'Cipher.getInstance', t);
            return this.getInstance(t);
        };
        Cipher.init.overloads.forEach(function (overload) {
            if (overload.argumentTypes.length < 2 || overload.argumentTypes[1].className !== 'java.security.Key') return;
            overload.implementation = function () {
                var result = overload.apply(this, arguments);
                try {
                    var key = arguments[1].getEncoded();
                    var iv = this.getIV();
                    var operation = {1: 'encrypt', 2: 'decrypt', 3: 'wrap', 4: 'unwrap'}[arguments[0]] || 'unknown';
                    emitCryptoKey('Cipher.init', this.getAlgorithm(), cryptoBytesHex(key, 0, key ? key.length : 0),
                        cryptoBytesHex(iv, 0, iv ? iv.length : 0), operation);
                } catch (e) { /* non-exportable/keystore key */ }
                return result;
            };
        });
    });

    safeHook('SecretKeySpec', function () {
        var SKS = Java.use('javax.crypto.spec.SecretKeySpec');
        var init = SKS.$init.overload('[B', 'java.lang.String');
        init.implementation = function (key, alg) {
            var result = init.call(this, key, alg);
            emit('crypto', 'SecretKeySpec', alg + ', ' + (key ? key.length : 0) + ' byte key');
            emitCryptoKey('SecretKeySpec', alg, cryptoBytesHex(key, 0, key ? key.length : 0), '', 'key_creation');
            return result;
        };
        var sliceInit = SKS.$init.overload('[B', 'int', 'int', 'java.lang.String');
        sliceInit.implementation = function (key, offset, length, alg) {
            var result = sliceInit.call(this, key, offset, length, alg);
            emitCryptoKey('SecretKeySpec', alg, cryptoBytesHex(key, offset, length), '', 'key_creation');
            return result;
        };
    });

    safeHook('MessageDigest', function () {
        var MD = Java.use('java.security.MessageDigest');
        MD.getInstance.overload('java.lang.String').implementation = function (alg) {
            emit('crypto', 'MessageDigest', alg);
            return this.getInstance(alg);
        };
    });

    /* ---- Network -------------------------------------------------------- */
    safeHook('URL.openConnection', function () {
        var URL = Java.use('java.net.URL');
        URL.openConnection.overload().implementation = function () {
            emit('net', 'openConnection', this.toString());
            return this.openConnection();
        };
    });

    safeHook('Socket', function () {
        var Socket = Java.use('java.net.Socket');
        Socket.connect.overload('java.net.SocketAddress', 'int')
            .implementation = function (addr, timeout) {
                emit('net', 'Socket.connect', addr ? addr.toString() : '');
                return this.connect(addr, timeout);
            };
    });

    /* ---- Device identifiers and privacy-sensitive reads ----------------- */
    safeHook('TelephonyManager', function () {
        var TM = Java.use('android.telephony.TelephonyManager');
        ['getDeviceId', 'getSubscriberId', 'getSimSerialNumber', 'getLine1Number'].forEach(function (m) {
            if (TM[m]) {
                TM[m].overloads.forEach(function (ovl) {
                    ovl.implementation = function () {
                        emit('privacy', 'TelephonyManager.' + m, shortStack());
                        return ovl.apply(this, arguments);
                    };
                });
            }
        });
    });

    safeHook('SmsManager', function () {
        var SM = Java.use('android.telephony.SmsManager');
        SM.sendTextMessage.implementation = function (dest, sc, text, sent, delivered) {
            emit('privacy', 'SmsManager.sendTextMessage', 'to=' + dest + ' body=' + text);
            return this.sendTextMessage(dest, sc, text, sent, delivered);
        };
    });

    safeHook('ContentResolver.query', function () {
        var CR = Java.use('android.content.ContentResolver');
        CR.query.overload(
            'android.net.Uri', '[Ljava.lang.String;', 'java.lang.String',
            '[Ljava.lang.String;', 'java.lang.String'
        ).implementation = function (uri, proj, sel, args, sort) {
            var u = uri ? uri.toString() : '';
            /* Only report the providers that matter for data theft. */
            if (/contacts|sms|mms|calllog|call_log|calendar|media/i.test(u)) {
                emit('privacy', 'ContentResolver.query', u);
            }
            return this.query(uri, proj, sel, args, sort);
        };
    });

    /* ---- Filesystem writes --------------------------------------------- */
    safeHook('FileOutputStream', function () {
        var FOS = Java.use('java.io.FileOutputStream');
        FOS.$init.overload('java.io.File', 'boolean').implementation = function (f, append) {
            var p = '';
            try { p = f.getAbsolutePath(); } catch (e) { /* ignore */ }
            /* Skip the app's own cache churn; report drops elsewhere. */
            if (p && !/\/cache\/|\/code_cache\//.test(p)) {
                emit('file', 'write', p);
            }
            return this.$init(f, append);
        };
    });

    /* ---- Reflection ----------------------------------------------------- */
    safeHook('Method.invoke', function () {
        var M = Java.use('java.lang.reflect.Method');
        M.invoke.implementation = function (obj, args) {
            try {
                var name = this.getDeclaringClass().getName() + '.' + this.getName();
                /* Reflection on these is how hidden APIs and packers are reached. */
                if (/^(dalvik|libcore|android\.os\.SystemProperties|java\.lang\.Runtime)/.test(name)) {
                    emit('reflect', 'Method.invoke', name);
                }
            } catch (e) { /* ignore */ }
            return this.invoke(obj, args);
        };
    });

    /* ---- Sandbox and root detection ------------------------------------
     * Do not defeat these checks, report them. Knowing the sample probed for
     * an emulator is itself the finding, and silently lying to it makes the
     * rest of the trace impossible to trust.
     */
    safeHook('SystemProperties.get', function () {
        var SP = Java.use('android.os.SystemProperties');
        SP.get.overload('java.lang.String').implementation = function (key) {
            if (/qemu|goldfish|ranchu|kvm|hardware|fingerprint|serialno|debuggable/i.test(key)) {
                emit('evasion', 'SystemProperties.get', key);
            }
            return this.get(key);
        };
    });

    safeHook('File.exists', function () {
        var File = Java.use('java.io.File');
        File.exists.implementation = function () {
            var p = '';
            try { p = this.getAbsolutePath(); } catch (e) { /* ignore */ }
            if (/\/su$|magisk|xposed|frida|busybox|superuser/i.test(p)) {
                emit('evasion', 'root-probe', p);
            }
            return this.exists();
        };
    });

    emit('session', 'ready', 'instrumentation installed');
});
