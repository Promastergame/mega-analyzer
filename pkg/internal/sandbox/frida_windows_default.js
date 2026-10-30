/*
 * Default Windows user-mode WinAPI instrumentation for Mega-Analyzer sandbox sessions.
 *
 * Architectural boundary:
 *   - This script runs inside the target Windows process via Frida (injected while
 *     the target is still suspended with CREATE_SUSPENDED, before resumeProcess()).
 *   - It uses Interceptor.attach on exported Win32 and Native API functions in
 *     kernel32.dll, kernelbase.dll, ntdll.dll, advapi32.dll, bcrypt.dll, and ws2_32.dll.
 *   - ETW (Event Tracing for Windows) observes kernel/provider process, image, file,
 *     and network telemetry; ETW is NOT arbitrary WinAPI interception and is never
 *     represented as hooked WinAPI calls.
 *
 * Wire protocol (stdout lines read by windowsAPITracer):
 *   - FRIDA_SESSION {"type":"ready","pid":1234,"arch":"x64","pointer_size":8,"hooked":[...],"gaps":[...]}
 *   - FRIDA_API {"ts":1700000000000,"pid":1234,"tid":1238,"cat":"Memory","mod":"kernel32.dll","fn":"VirtualAllocEx","params":[{"name":"hProcess","type":"HANDLE","value":"0x1234"},...],"ret":"0x20000","err":0,"stack":[...]}
 *   - FRIDA_CHILD {"parent_pid":1234,"child_pid":5678,"child_tid":5680,"suspended":true,"fn":"CreateProcessW"}
 */

'use strict';

var ENABLED_CATEGORIES = (typeof __MEGA_ENABLED_CATEGORIES !== 'undefined' && Array.isArray(__MEGA_ENABLED_CATEGORIES))
    ? __MEGA_ENABLED_CATEGORIES
    : ['Memory', 'Process', 'Registry', 'File', 'Crypto', 'Network'];

var categorySet = {};
for (var i = 0; i < ENABLED_CATEGORIES.length; i++) {
    categorySet[String(ENABLED_CATEGORIES[i]).toLowerCase()] = true;
}

function categoryEnabled(cat) {
    if (ENABLED_CATEGORIES.length === 0) {
        return true;
    }
    return !!categorySet[String(cat).toLowerCase()];
}

var PTR_SIZE = Process.pointerSize;
var PID = Process.id;

var getLastErrorFn = null;
try {
    var k32 = Process.findModuleByName('kernel32.dll');
    if (k32) {
        var gleAddr = k32.findExportByName('GetLastError');
        if (gleAddr) {
            getLastErrorFn = new NativeFunction(gleAddr, 'uint32', []);
        }
    }
} catch (e) {
    /* fallback to this.lastError */
}

function readLastError(ctx) {
    if (ctx && typeof ctx.lastError === 'number') {
        return ctx.lastError >>> 0;
    }
    if (getLastErrorFn !== null) {
        try {
            return getLastErrorFn() >>> 0;
        } catch (e) {
            return 0;
        }
    }
    return 0;
}

function fmtPtr(p) {
    if (p === null || p === undefined) {
        return '0x0';
    }
    try {
        var ptrVal = ptr(p);
        if (ptrVal.isNull()) {
            return '0x0';
        }
        return ptrVal.toString().toLowerCase();
    } catch (e) {
        return '0x0';
    }
}

function fmtU32Hex(v) {
    try {
        var n = ptr(v).toUInt32() >>> 0;
        if (n === 0) {
            return '0x0';
        }
        return '0x' + n.toString(16).toLowerCase();
    } catch (e) {
        return '0x0';
    }
}

function fmtNTStatus(retval) {
    try {
        var status = ptr(retval).toUInt32() >>> 0;
        var hex = status.toString(16).toUpperCase();
        while (hex.length < 8) {
            hex = '0' + hex;
        }
        return '0x' + hex;
    } catch (e) {
        return '0xC0000001';
    }
}

function fmtWin32Bool(retval) {
    try {
        var v = ptr(retval).toInt32();
        return v !== 0 ? '0x1' : '0x0';
    } catch (e) {
        return '0x0';
    }
}

function fmtFileHandle(retval) {
    try {
        var p = ptr(retval);
        if (p.isNull()) {
            return '0x0';
        }
        var s = p.toString().toLowerCase();
        if (s === '0xffffffff' || s === '0xffffffffffffffff') {
            return 'INVALID_HANDLE_VALUE';
        }
        return s;
    } catch (e) {
        return 'INVALID_HANDLE_VALUE';
    }
}

function fmtLStatus(retval) {
    try {
        var status = ptr(retval).toUInt32() >>> 0;
        if (status === 0) {
            return '0x0';
        }
        return '0x' + status.toString(16).toLowerCase();
    } catch (e) {
        return '0x1';
    }
}

function readUtf16Safe(p, maxChars) {
    try {
        if (!p || ptr(p).isNull()) {
            return '';
        }
        return ptr(p).readUtf16String(maxChars || 512) || '';
    } catch (e) {
        return '';
    }
}

function readAnsiSafe(p, maxChars) {
    try {
        if (!p || ptr(p).isNull()) {
            return '';
        }
        return ptr(p).readAnsiString(maxChars || 512) || '';
    } catch (e) {
        return '';
    }
}

function readPointerSafe(p) {
    try {
        if (!p || ptr(p).isNull()) {
            return ptr(0);
        }
        return ptr(p).readPointer();
    } catch (e) {
        return ptr(0);
    }
}

function readU32Safe(p) {
    try {
        if (!p || ptr(p).isNull()) {
            return 0;
        }
        return ptr(p).readU32() >>> 0;
    } catch (e) {
        return 0;
    }
}

function readUnicodeStringSafe(p) {
    try {
        if (!p || ptr(p).isNull()) {
            return '';
        }
        var u = ptr(p);
        var byteLen = u.readU16();
        if (byteLen === 0) {
            return '';
        }
        var bufOffset = PTR_SIZE === 8 ? 8 : 4;
        var bufPtr = u.add(bufOffset).readPointer();
        if (bufPtr.isNull()) {
            return '';
        }
        return bufPtr.readUtf16String(Math.min(byteLen >> 1, 512)) || '';
    } catch (e) {
        return '';
    }
}

function captureStack(ctx) {
    try {
        return Thread.backtrace(ctx, Backtracer.FUZZY)
            .slice(0, 5)
            .map(function (addr) {
                var sym = DebugSymbol.fromAddress(addr);
                return sym ? sym.toString() : addr.toString();
            });
    } catch (e) {
        return [];
    }
}

function emitAPICall(tid, category, moduleName, fnName, params, retVal, lastErr, stack) {
    try {
        var payload = {
            ts: Date.now(),
            pid: PID,
            tid: tid || 0,
            cat: category,
            mod: moduleName,
            fn: fnName,
            params: params || [],
            ret: String(retVal),
            err: lastErr >>> 0
        };
        if (stack && stack.length > 0) {
            payload.stack = stack;
        }
        console.log('FRIDA_API ' + JSON.stringify(payload));
    } catch (e) {
        /* never disrupt target execution */
    }
}

function emitChildProcess(childPid, childTid, suspended, fnName) {
    try {
        if (!childPid || childPid <= 0) {
            return;
        }
        console.log('FRIDA_CHILD ' + JSON.stringify({
            parent_pid: PID,
            child_pid: childPid >>> 0,
            child_tid: (childTid || 0) >>> 0,
            suspended: !!suspended,
            fn: fnName
        }));
    } catch (e) {
        /* ignore */
    }
}

var hookedExports = [];
var hookGaps = [];
var attachedAddresses = {};

function attachExport(category, dllCandidates, fnName, spec) {
    if (!categoryEnabled(category)) {
        return;
    }
    var resolvedAddr = null;
    var resolvedMod = '';
    for (var i = 0; i < dllCandidates.length; i++) {
        var modName = dllCandidates[i];
        var mod = Process.findModuleByName(modName);
        if (!mod) {
            continue;
        }
        var exp = mod.findExportByName(fnName);
        if (exp) {
            resolvedAddr = exp;
            resolvedMod = modName;
            break;
        }
    }
    if (!resolvedAddr) {
        hookGaps.push({
            category: category,
            module: dllCandidates.join('/'),
            function: fnName,
            reason: 'export not found in loaded modules'
        });
        return;
    }
    var addrKey = resolvedAddr.toString();
    if (attachedAddresses[addrKey + ':' + fnName]) {
        return;
    }
    try {
        Interceptor.attach(resolvedAddr, {
            onEnter: function (args) {
                this._params = [];
                this._extra = {};
                if (spec.onEnter) {
                    try {
                        spec.onEnter.call(this, args);
                    } catch (e) {
                        /* preserve hook stability */
                    }
                }
            },
            onLeave: function (retval) {
                try {
                    var retStr = spec.formatReturn ? spec.formatReturn.call(this, retval) : fmtPtr(retval);
                    if (spec.onLeave) {
                        spec.onLeave.call(this, retval, retStr);
                    }
                    var lastErr = readLastError(this);
                    var stack = captureStack(this.context);
                    emitAPICall(this.threadId, category, resolvedMod, fnName, this._params, retStr, lastErr, stack);
                } catch (e) {
                    /* preserve hook stability */
                }
            }
        });
        attachedAddresses[addrKey + ':' + fnName] = true;
        hookedExports.push(resolvedMod + '!' + fnName);
    } catch (e) {
        hookGaps.push({
            category: category,
            module: resolvedMod,
            function: fnName,
            reason: e.message || String(e)
        });
    }
}

/* ---- Category: Memory -------------------------------------------------- */

attachExport('Memory', ['kernel32.dll', 'kernelbase.dll'], 'VirtualAllocEx', {
    onEnter: function (args) {
        this._params = [
            { name: 'hProcess', type: 'HANDLE', value: fmtPtr(args[0]) },
            { name: 'lpAddress', type: 'LPVOID', value: fmtPtr(args[1]) },
            { name: 'dwSize', type: 'SIZE_T', value: fmtPtr(args[2]) },
            { name: 'flAllocationType', type: 'DWORD', value: fmtU32Hex(args[3]) },
            { name: 'flProtect', type: 'DWORD', value: fmtU32Hex(args[4]) }
        ];
    },
    formatReturn: fmtPtr
});

attachExport('Memory', ['kernel32.dll', 'kernelbase.dll'], 'VirtualAlloc', {
    onEnter: function (args) {
        this._params = [
            { name: 'lpAddress', type: 'LPVOID', value: fmtPtr(args[0]) },
            { name: 'dwSize', type: 'SIZE_T', value: fmtPtr(args[1]) },
            { name: 'flAllocationType', type: 'DWORD', value: fmtU32Hex(args[2]) },
            { name: 'flProtect', type: 'DWORD', value: fmtU32Hex(args[3]) }
        ];
    },
    formatReturn: fmtPtr
});

attachExport('Memory', ['kernel32.dll', 'kernelbase.dll'], 'VirtualProtectEx', {
    onEnter: function (args) {
        this._params = [
            { name: 'hProcess', type: 'HANDLE', value: fmtPtr(args[0]) },
            { name: 'lpAddress', type: 'LPVOID', value: fmtPtr(args[1]) },
            { name: 'dwSize', type: 'SIZE_T', value: fmtPtr(args[2]) },
            { name: 'flNewProtect', type: 'DWORD', value: fmtU32Hex(args[3]) }
        ];
    },
    formatReturn: fmtWin32Bool
});

attachExport('Memory', ['kernel32.dll', 'kernelbase.dll'], 'VirtualProtect', {
    onEnter: function (args) {
        this._params = [
            { name: 'lpAddress', type: 'LPVOID', value: fmtPtr(args[0]) },
            { name: 'dwSize', type: 'SIZE_T', value: fmtPtr(args[1]) },
            { name: 'flNewProtect', type: 'DWORD', value: fmtU32Hex(args[2]) }
        ];
    },
    formatReturn: fmtWin32Bool
});

attachExport('Memory', ['kernel32.dll', 'kernelbase.dll'], 'WriteProcessMemory', {
    onEnter: function (args) {
        this._params = [
            { name: 'hProcess', type: 'HANDLE', value: fmtPtr(args[0]) },
            { name: 'lpBaseAddress', type: 'LPVOID', value: fmtPtr(args[1]) },
            { name: 'lpBuffer', type: 'LPCVOID', value: fmtPtr(args[2]) },
            { name: 'nSize', type: 'SIZE_T', value: fmtPtr(args[3]) }
        ];
    },
    formatReturn: fmtWin32Bool
});

attachExport('Memory', ['kernel32.dll', 'kernelbase.dll'], 'ReadProcessMemory', {
    onEnter: function (args) {
        this._params = [
            { name: 'hProcess', type: 'HANDLE', value: fmtPtr(args[0]) },
            { name: 'lpBaseAddress', type: 'LPCVOID', value: fmtPtr(args[1]) },
            { name: 'lpBuffer', type: 'LPVOID', value: fmtPtr(args[2]) },
            { name: 'nSize', type: 'SIZE_T', value: fmtPtr(args[3]) }
        ];
    },
    formatReturn: fmtWin32Bool
});

['NtAllocateVirtualMemory', 'ZwAllocateVirtualMemory'].forEach(function (fn) {
    attachExport('Memory', ['ntdll.dll'], fn, {
        onEnter: function (args) {
            this._baseAddrPtr = args[1];
            this._regionSizePtr = args[3];
            this._params = [
                { name: 'ProcessHandle', type: 'HANDLE', value: fmtPtr(args[0]) },
                { name: 'BaseAddress', type: 'PVOID', value: fmtPtr(readPointerSafe(args[1])) },
                { name: 'RegionSize', type: 'SIZE_T', value: fmtPtr(readPointerSafe(args[3])) },
                { name: 'AllocationType', type: 'ULONG', value: fmtU32Hex(args[4]) },
                { name: 'Protect', type: 'ULONG', value: fmtU32Hex(args[5]) }
            ];
        },
        onLeave: function (retval, retStr) {
            if (retStr === '0x00000000' && this._baseAddrPtr) {
                this._params[1].value = fmtPtr(readPointerSafe(this._baseAddrPtr));
            }
        },
        formatReturn: fmtNTStatus
    });
});

['NtWriteVirtualMemory', 'ZwWriteVirtualMemory'].forEach(function (fn) {
    attachExport('Memory', ['ntdll.dll'], fn, {
        onEnter: function (args) {
            this._params = [
                { name: 'ProcessHandle', type: 'HANDLE', value: fmtPtr(args[0]) },
                { name: 'BaseAddress', type: 'PVOID', value: fmtPtr(args[1]) },
                { name: 'Buffer', type: 'PVOID', value: fmtPtr(args[2]) },
                { name: 'NumberOfBytesToWrite', type: 'SIZE_T', value: fmtPtr(args[3]) }
            ];
        },
        formatReturn: fmtNTStatus
    });
});

['NtProtectVirtualMemory', 'ZwProtectVirtualMemory'].forEach(function (fn) {
    attachExport('Memory', ['ntdll.dll'], fn, {
        onEnter: function (args) {
            this._params = [
                { name: 'ProcessHandle', type: 'HANDLE', value: fmtPtr(args[0]) },
                { name: 'BaseAddress', type: 'PVOID', value: fmtPtr(readPointerSafe(args[1])) },
                { name: 'RegionSize', type: 'SIZE_T', value: fmtPtr(readPointerSafe(args[2])) },
                { name: 'NewProtect', type: 'ULONG', value: fmtU32Hex(args[3]) }
            ];
        },
        formatReturn: fmtNTStatus
    });
});

/* ---- Category: Process ------------------------------------------------- */

attachExport('Process', ['kernel32.dll', 'kernelbase.dll'], 'CreateRemoteThread', {
    onEnter: function (args) {
        this._params = [
            { name: 'hProcess', type: 'HANDLE', value: fmtPtr(args[0]) },
            { name: 'lpStartAddress', type: 'LPTHREAD_START_ROUTINE', value: fmtPtr(args[3]) },
            { name: 'lpParameter', type: 'LPVOID', value: fmtPtr(args[4]) },
            { name: 'dwCreationFlags', type: 'DWORD', value: fmtU32Hex(args[5]) }
        ];
    },
    formatReturn: fmtPtr
});

attachExport('Process', ['kernel32.dll', 'kernelbase.dll'], 'CreateRemoteThreadEx', {
    onEnter: function (args) {
        this._params = [
            { name: 'hProcess', type: 'HANDLE', value: fmtPtr(args[0]) },
            { name: 'lpStartAddress', type: 'LPTHREAD_START_ROUTINE', value: fmtPtr(args[3]) },
            { name: 'lpParameter', type: 'LPVOID', value: fmtPtr(args[4]) },
            { name: 'dwCreationFlags', type: 'DWORD', value: fmtU32Hex(args[5]) }
        ];
    },
    formatReturn: fmtPtr
});

function attachCreateProcess(fnName, isWide) {
    attachExport('Process', ['kernel32.dll', 'kernelbase.dll'], fnName, {
        onEnter: function (args) {
            var appName = isWide ? readUtf16Safe(args[0]) : readAnsiSafe(args[0]);
            var cmdLine = isWide ? readUtf16Safe(args[1]) : readAnsiSafe(args[1]);
            var flags = args[5].toUInt32() >>> 0;
            var suspended = (flags & 0x00000004) !== 0;
            var flagsVal = suspended ? 'CREATE_SUSPENDED' : fmtU32Hex(args[5]);
            this._procInfoPtr = args[9];
            this._suspended = suspended;
            this._params = [
                { name: 'lpApplicationName', type: isWide ? 'LPCWSTR' : 'LPCSTR', value: appName },
                { name: 'lpCommandLine', type: isWide ? 'LPWSTR' : 'LPSTR', value: cmdLine },
                { name: 'dwCreationFlags', type: 'DWORD', value: flagsVal }
            ];
            if (suspended && flags !== 0x00000004) {
                this._params.push({ name: 'dwCreationFlagsRaw', type: 'DWORD', value: fmtU32Hex(args[5]) });
            }
        },
        onLeave: function (retval, retStr) {
            if (retStr !== '0x0' && this._procInfoPtr && !ptr(this._procInfoPtr).isNull()) {
                var pi = ptr(this._procInfoPtr);
                var hProcess = readPointerSafe(pi);
                var hThread = readPointerSafe(pi.add(PTR_SIZE));
                var dwProcessId = readU32Safe(pi.add(PTR_SIZE * 2));
                var dwThreadId = readU32Safe(pi.add(PTR_SIZE * 2 + 4));
                this._params.push({ name: 'hProcess', type: 'HANDLE', value: fmtPtr(hProcess) });
                this._params.push({ name: 'hThread', type: 'HANDLE', value: fmtPtr(hThread) });
                if (dwProcessId > 0) {
                    this._params.push({ name: 'dwProcessId', type: 'DWORD', value: String(dwProcessId) });
                    emitChildProcess(dwProcessId, dwThreadId, this._suspended, fnName);
                }
                if (dwThreadId > 0) {
                    this._params.push({ name: 'dwThreadId', type: 'DWORD', value: String(dwThreadId) });
                }
            }
        },
        formatReturn: fmtWin32Bool
    });
}

attachCreateProcess('CreateProcessW', true);
attachCreateProcess('CreateProcessA', false);

attachExport('Process', ['kernel32.dll', 'kernelbase.dll'], 'OpenProcess', {
    onEnter: function (args) {
        this._params = [
            { name: 'dwDesiredAccess', type: 'DWORD', value: fmtU32Hex(args[0]) },
            { name: 'bInheritHandle', type: 'BOOL', value: fmtWin32Bool(args[1]) },
            { name: 'dwProcessId', type: 'DWORD', value: String(args[2].toUInt32() >>> 0) }
        ];
    },
    formatReturn: fmtPtr
});

attachExport('Process', ['kernel32.dll', 'kernelbase.dll'], 'ResumeThread', {
    onEnter: function (args) {
        this._params = [
            { name: 'hThread', type: 'HANDLE', value: fmtPtr(args[0]) }
        ];
    },
    formatReturn: function (retval) {
        var v = ptr(retval).toUInt32() >>> 0;
        if (v === 0xffffffff) {
            return '0xffffffff';
        }
        return '0x' + (v === 0 ? 1 : v).toString(16);
    }
});

['NtUnmapViewOfSection', 'ZwUnmapViewOfSection'].forEach(function (fn) {
    attachExport('Process', ['ntdll.dll'], fn, {
        onEnter: function (args) {
            this._params = [
                { name: 'ProcessHandle', type: 'HANDLE', value: fmtPtr(args[0]) },
                { name: 'BaseAddress', type: 'PVOID', value: fmtPtr(args[1]) }
            ];
        },
        formatReturn: fmtNTStatus
    });
});

['NtCreateThreadEx', 'ZwCreateThreadEx'].forEach(function (fn) {
    attachExport('Process', ['ntdll.dll'], fn, {
        onEnter: function (args) {
            this._threadHandleOut = args[0];
            this._params = [
                { name: 'ProcessHandle', type: 'HANDLE', value: fmtPtr(args[3]) },
                { name: 'StartRoutine', type: 'PVOID', value: fmtPtr(args[4]) },
                { name: 'Argument', type: 'PVOID', value: fmtPtr(args[5]) },
                { name: 'CreateFlags', type: 'ULONG', value: fmtU32Hex(args[6]) }
            ];
        },
        onLeave: function (retval, retStr) {
            if (retStr === '0x00000000' && this._threadHandleOut) {
                this._params.push({
                    name: 'ThreadHandle',
                    type: 'HANDLE',
                    value: fmtPtr(readPointerSafe(this._threadHandleOut))
                });
            }
        },
        formatReturn: fmtNTStatus
    });
});

attachExport('Process', ['ntdll.dll'], 'RtlCreateUserThread', {
    onEnter: function (args) {
        this._params = [
            { name: 'ProcessHandle', type: 'HANDLE', value: fmtPtr(args[0]) },
            { name: 'CreateSuspended', type: 'BOOLEAN', value: fmtWin32Bool(args[2]) },
            { name: 'StartAddress', type: 'PVOID', value: fmtPtr(args[6]) },
            { name: 'StartParameter', type: 'PVOID', value: fmtPtr(args[7]) }
        ];
    },
    formatReturn: fmtNTStatus
});

['NtResumeThread', 'ZwResumeThread'].forEach(function (fn) {
    attachExport('Process', ['ntdll.dll'], fn, {
        onEnter: function (args) {
            this._params = [
                { name: 'ThreadHandle', type: 'HANDLE', value: fmtPtr(args[0]) }
            ];
        },
        formatReturn: fmtNTStatus
    });
});

['NtCreateUserProcess', 'ZwCreateUserProcess'].forEach(function (fn) {
    attachExport('Process', ['ntdll.dll'], fn, {
        onEnter: function (args) {
            this._procHandleOut = args[0];
            this._threadHandleOut = args[1];
            var procFlags = args[6].toUInt32() >>> 0;
            var threadFlags = args[7].toUInt32() >>> 0;
            var suspended = (procFlags & 0x00000200) !== 0 || (threadFlags & 0x00000001) !== 0;
            this._suspended = suspended;
            this._params = [
                { name: 'ProcessDesiredAccess', type: 'ACCESS_MASK', value: fmtU32Hex(args[2]) },
                { name: 'dwCreationFlags', type: 'ULONG', value: suspended ? 'CREATE_SUSPENDED' : fmtU32Hex(args[6]) }
            ];
        },
        onLeave: function (retval, retStr) {
            if (retStr === '0x00000000') {
                var hProc = readPointerSafe(this._procHandleOut);
                var hThr = readPointerSafe(this._threadHandleOut);
                this._params.push({ name: 'ProcessHandle', type: 'HANDLE', value: fmtPtr(hProc) });
                this._params.push({ name: 'ThreadHandle', type: 'HANDLE', value: fmtPtr(hThr) });
            }
        },
        formatReturn: fmtNTStatus
    });
});

/* ---- Category: Crypto -------------------------------------------------- */

function cryptoReadHex(address, length) {
    try {
        if (!address || address.isNull() || length <= 0 || length > 256) return '';
        var bytes = new Uint8Array(address.readByteArray(length));
        var hex = '';
        for (var i = 0; i < bytes.length; i++) hex += ('0' + bytes[i].toString(16)).slice(-2);
        return hex;
    } catch (e) { return ''; }
}

// Provider handles are local to this injected process. Bound bookkeeping even
// when the sample repeatedly creates providers without closing them.
var cryptoProviders = new Map();
attachExport('Crypto', ['bcrypt.dll'], 'BCryptOpenAlgorithmProvider', {
    onEnter: function (args) {
        this._extra.out = args[0];
        this._extra.algorithm = readUtf16Safe(args[1]);
    },
    onLeave: function (retval, status) {
        if (status !== '0x00000000') return;
        var handle = fmtPtr(readPointerSafe(this._extra.out));
        if (cryptoProviders.size >= 1024) cryptoProviders.clear();
        cryptoProviders.set(handle, this._extra.algorithm);
    },
    formatReturn: fmtNTStatus
});
attachExport('Crypto', ['bcrypt.dll'], 'BCryptCloseAlgorithmProvider', {
    onEnter: function (args) { this._extra.handle = fmtPtr(args[0]); },
    onLeave: function (retval, status) { if (status === '0x00000000') cryptoProviders.delete(this._extra.handle); },
    formatReturn: fmtNTStatus
});
function cryptoKeyResult(retval, status) {
    if (status !== '0x00000000') return;
    this._params.push({name: 'hKey', type: 'BCRYPT_KEY_HANDLE', value: fmtPtr(readPointerSafe(this._extra.out))});
    this._params.push({name: 'Algorithm', type: 'string', value: this._extra.algorithm || 'unknown'});
    if (this._extra.key) this._params.push({name: 'KeyHex', type: 'hex', value: this._extra.key});
}
attachExport('Crypto', ['bcrypt.dll'], 'BCryptGenerateSymmetricKey', {
    onEnter: function (args) {
        this._extra.out = args[1];
        this._extra.algorithm = cryptoProviders.get(fmtPtr(args[0]));
        this._extra.key = cryptoReadHex(args[4], args[5].toUInt32());
    },
    onLeave: cryptoKeyResult,
    formatReturn: fmtNTStatus
});
attachExport('Crypto', ['bcrypt.dll'], 'BCryptImportKey', {
    onEnter: function (args) {
        this._extra.out = args[3];
        this._extra.algorithm = cryptoProviders.get(fmtPtr(args[0]));
        // Only the documented plaintext KeyDataBlob layout, never opaque blobs.
        if (readUtf16Safe(args[2]) !== 'KeyDataBlob' || args[7].toUInt32() < 12) return;
        var data = args[6], total = args[7].toUInt32();
        if (data.readU32() !== 0x4d42444b || data.add(4).readU32() !== 1) return;
        var size = data.add(8).readU32();
        if (size > total - 12) return;
        this._extra.key = cryptoReadHex(data.add(12), size);
    },
    onLeave: cryptoKeyResult,
    formatReturn: fmtNTStatus
});
attachExport('Crypto', ['bcrypt.dll'], 'BCryptDestroyKey', {
    onEnter: function (args) { this._params = [{name: 'hKey', type: 'BCRYPT_KEY_HANDLE', value: fmtPtr(args[0])}]; },
    formatReturn: fmtNTStatus
});

attachExport('Crypto', ['advapi32.dll', 'cryptsp.dll'], 'CryptEncrypt', {
    onEnter: function (args) {
        this._params = [
            { name: 'hKey', type: 'HCRYPTKEY', value: fmtPtr(args[0]) },
            { name: 'hHash', type: 'HCRYPTHASH', value: fmtPtr(args[1]) },
            { name: 'Final', type: 'BOOL', value: fmtWin32Bool(args[2]) },
            { name: 'dwFlags', type: 'DWORD', value: fmtU32Hex(args[3]) },
            { name: 'pdwDataLen', type: 'DWORD', value: String(readU32Safe(args[5])) }
        ];
    },
    formatReturn: fmtWin32Bool
});

attachExport('Crypto', ['advapi32.dll', 'cryptsp.dll'], 'CryptDecrypt', {
    onEnter: function (args) {
        this._params = [
            { name: 'hKey', type: 'HCRYPTKEY', value: fmtPtr(args[0]) },
            { name: 'hHash', type: 'HCRYPTHASH', value: fmtPtr(args[1]) },
            { name: 'Final', type: 'BOOL', value: fmtWin32Bool(args[2]) },
            { name: 'dwFlags', type: 'DWORD', value: fmtU32Hex(args[3]) },
            { name: 'pdwDataLen', type: 'DWORD', value: String(readU32Safe(args[5])) }
        ];
    },
    formatReturn: fmtWin32Bool
});

['BCryptEncrypt', 'BCryptDecrypt'].forEach(function (fn) {
    attachExport('Crypto', ['bcrypt.dll'], fn, {
        onEnter: function (args) {
            this._params = [
                { name: 'hKey', type: 'BCRYPT_KEY_HANDLE', value: fmtPtr(args[0]) },
                { name: 'cbInput', type: 'ULONG', value: String(args[2].toUInt32() >>> 0) },
                { name: 'dwFlags', type: 'ULONG', value: fmtU32Hex(args[9]) },
                { name: 'OutputPresent', type: 'bool', value: args[6].isNull() ? 'false' : 'true' }
            ];
            // Capture before the API modifies the caller's IV buffer.
            var iv = cryptoReadHex(args[4], args[5].toUInt32());
            if (iv && iv.length <= 64) this._params.push({name: 'IVHex', type: 'hex', value: iv});
        },
        formatReturn: fmtNTStatus
    });
});

/* ---- Category: Registry ------------------------------------------------ */

function attachRegSetValueEx(fnName, isWide) {
    attachExport('Registry', ['advapi32.dll', 'kernelbase.dll'], fnName, {
        onEnter: function (args) {
            var valName = isWide ? readUtf16Safe(args[1]) : readAnsiSafe(args[1]);
            this._params = [
                { name: 'hKey', type: 'HKEY', value: fmtPtr(args[0]) },
                { name: 'lpValueName', type: isWide ? 'LPCWSTR' : 'LPCSTR', value: valName },
                { name: 'dwType', type: 'DWORD', value: fmtU32Hex(args[3]) },
                { name: 'cbData', type: 'DWORD', value: String(args[5].toUInt32() >>> 0) }
            ];
        },
        formatReturn: fmtLStatus
    });
}

attachRegSetValueEx('RegSetValueExW', true);
attachRegSetValueEx('RegSetValueExA', false);

function attachRegCreateKeyEx(fnName, isWide) {
    attachExport('Registry', ['advapi32.dll', 'kernelbase.dll'], fnName, {
        onEnter: function (args) {
            var subKey = isWide ? readUtf16Safe(args[1]) : readAnsiSafe(args[1]);
            this._phkResult = args[7];
            this._params = [
                { name: 'hKey', type: 'HKEY', value: fmtPtr(args[0]) },
                { name: 'lpSubKey', type: isWide ? 'LPCWSTR' : 'LPCSTR', value: subKey },
                { name: 'samDesired', type: 'REGSAM', value: fmtU32Hex(args[5]) }
            ];
        },
        onLeave: function (retval, retStr) {
            if (retStr === '0x0' && this._phkResult) {
                this._params.push({
                    name: 'phkResult',
                    type: 'HKEY',
                    value: fmtPtr(readPointerSafe(this._phkResult))
                });
            }
        },
        formatReturn: fmtLStatus
    });
}

attachRegCreateKeyEx('RegCreateKeyExW', true);
attachRegCreateKeyEx('RegCreateKeyExA', false);

['NtSetValueKey', 'ZwSetValueKey'].forEach(function (fn) {
    attachExport('Registry', ['ntdll.dll'], fn, {
        onEnter: function (args) {
            this._params = [
                { name: 'KeyHandle', type: 'HANDLE', value: fmtPtr(args[0]) },
                { name: 'ValueName', type: 'PUNICODE_STRING', value: readUnicodeStringSafe(args[1]) },
                { name: 'Type', type: 'ULONG', value: fmtU32Hex(args[3]) },
                { name: 'DataSize', type: 'ULONG', value: String(args[5].toUInt32() >>> 0) }
            ];
        },
        formatReturn: fmtNTStatus
    });
});

/* ---- Category: File ---------------------------------------------------- */

function attachCreateFile(fnName, isWide) {
    attachExport('File', ['kernel32.dll', 'kernelbase.dll'], fnName, {
        onEnter: function (args) {
            var path = isWide ? readUtf16Safe(args[0]) : readAnsiSafe(args[0]);
            this._params = [
                { name: 'lpFileName', type: isWide ? 'LPCWSTR' : 'LPCSTR', value: path },
                { name: 'dwDesiredAccess', type: 'DWORD', value: fmtU32Hex(args[1]) },
                { name: 'dwShareMode', type: 'DWORD', value: fmtU32Hex(args[2]) },
                { name: 'dwCreationDisposition', type: 'DWORD', value: fmtU32Hex(args[4]) },
                { name: 'dwFlagsAndAttributes', type: 'DWORD', value: fmtU32Hex(args[5]) }
            ];
        },
        formatReturn: fmtFileHandle
    });
}

attachCreateFile('CreateFileW', true);
attachCreateFile('CreateFileA', false);

attachExport('File', ['kernel32.dll', 'kernelbase.dll'], 'WriteFile', {
    onEnter: function (args) {
        this._params = [
            { name: 'hFile', type: 'HANDLE', value: fmtPtr(args[0]) },
            { name: 'lpBuffer', type: 'LPCVOID', value: fmtPtr(args[1]) },
            { name: 'nNumberOfBytesToWrite', type: 'DWORD', value: String(args[2].toUInt32() >>> 0) }
        ];
    },
    formatReturn: fmtWin32Bool
});

attachExport('File', ['kernel32.dll', 'kernelbase.dll'], 'DeleteFileW', {
    onEnter: function (args) {
        this._params = [
            { name: 'lpFileName', type: 'LPCWSTR', value: readUtf16Safe(args[0]) }
        ];
    },
    formatReturn: fmtWin32Bool
});

attachExport('File', ['kernel32.dll', 'kernelbase.dll'], 'DeleteFileA', {
    onEnter: function (args) {
        this._params = [
            { name: 'lpFileName', type: 'LPCSTR', value: readAnsiSafe(args[0]) }
        ];
    },
    formatReturn: fmtWin32Bool
});

attachExport('File', ['kernel32.dll', 'kernelbase.dll'], 'MoveFileExW', {
    onEnter: function (args) {
        this._params = [
            { name: 'lpExistingFileName', type: 'LPCWSTR', value: readUtf16Safe(args[0]) },
            { name: 'lpNewFileName', type: 'LPCWSTR', value: readUtf16Safe(args[1]) },
            { name: 'dwFlags', type: 'DWORD', value: fmtU32Hex(args[2]) }
        ];
    },
    formatReturn: fmtWin32Bool
});

/* ---- Category: Network ------------------------------------------------- */

function parseSockaddr(saPtr) {
    try {
        if (!saPtr || ptr(saPtr).isNull()) {
            return '';
        }
        var sa = ptr(saPtr);
        var family = sa.readU16();
        if (family === 2) { /* AF_INET */
            var port = ((sa.add(2).readU8() << 8) | sa.add(3).readU8()) >>> 0;
            var ip = sa.add(4).readU8() + '.' + sa.add(5).readU8() + '.' +
                sa.add(6).readU8() + '.' + sa.add(7).readU8();
            return ip + ':' + port;
        }
        return 'family=' + family;
    } catch (e) {
        return '';
    }
}

['connect', 'WSAConnect'].forEach(function (fn) {
    attachExport('Network', ['ws2_32.dll'], fn, {
        onEnter: function (args) {
            this._params = [
                { name: 's', type: 'SOCKET', value: fmtPtr(args[0]) },
                { name: 'name', type: 'sockaddr', value: parseSockaddr(args[1]) }
            ];
        },
        formatReturn: function (retval) {
            var v = ptr(retval).toInt32();
            return v === 0 ? '0x0' : '0xffffffff';
        }
    });
});

['send', 'recv'].forEach(function (fn) {
    attachExport('Network', ['ws2_32.dll'], fn, {
        onEnter: function (args) {
            this._params = [
                { name: 's', type: 'SOCKET', value: fmtPtr(args[0]) },
                { name: 'len', type: 'int', value: String(args[2].toInt32()) },
                { name: 'flags', type: 'int', value: fmtU32Hex(args[3]) }
            ];
        },
        formatReturn: function (retval) {
            var v = ptr(retval).toInt32();
            return v < 0 ? '0xffffffff' : '0x' + (v === 0 ? 1 : v).toString(16);
        }
    });
});

['WSASend', 'WSARecv'].forEach(function (fn) {
    attachExport('Network', ['ws2_32.dll'], fn, {
        onEnter: function (args) {
            this._params = [
                { name: 's', type: 'SOCKET', value: fmtPtr(args[0]) },
                { name: 'dwBufferCount', type: 'DWORD', value: String(args[2].toUInt32() >>> 0) }
            ];
        },
        formatReturn: fmtLStatus
    });
});

console.log('FRIDA_SESSION ' + JSON.stringify({
    type: 'ready',
    pid: PID,
    arch: Process.arch,
    pointer_size: PTR_SIZE,
    hooked: hookedExports,
    gaps: hookGaps
}));
