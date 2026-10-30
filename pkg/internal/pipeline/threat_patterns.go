package pipeline

import (
	"regexp"
)

// ═══════════════════════════════════════════════════════════════════════════════
// PATTERN DEFINITIONS
// ═══════════════════════════════════════════════════════════════════════════════

// SignalPattern defines a detection pattern
type SignalPattern struct {
	Signal   SignalType
	Patterns [][]byte
	Regex    *regexp.Regexp
	Context  string
}

// PatternGroup organizes patterns by detection area
type PatternGroup struct {
	Name     string
	Patterns []SignalPattern
}

// ═══════════════════════════════════════════════════════════════════════════════
// SMALI PATTERNS
// ═══════════════════════════════════════════════════════════════════════════════

var SmaliPatterns = []PatternGroup{
	{
		Name: "DynamicCodeLoading",
		Patterns: []SignalPattern{
			{
				Signal: SignalDexClassLoader,
				Patterns: [][]byte{
					[]byte("ldalvik/system/dexclassloader;"),
					[]byte("dalvik/system/dexclassloader"),
				},
				Context: "DexClassLoader usage",
			},
			{
				Signal: SignalInMemoryDexClassLoader,
				Patterns: [][]byte{
					[]byte("ldalvik/system/inmemorydexclassloader;"),
					[]byte("dalvik/system/inmemorydexclassloader"),
				},
				Context: "InMemoryDexClassLoader usage",
			},
			{
				Signal: SignalReflectionForName,
				Patterns: [][]byte{
					[]byte("ljava/lang/class;->forname"),
					[]byte("class;->forname("),
				},
				Context: "Reflection Class.forName",
			},
			{
				Signal: SignalReflectionInvoke,
				Patterns: [][]byte{
					[]byte("ljava/lang/reflect/method;->invoke"),
					[]byte("method;->invoke("),
				},
				Context: "Reflection Method.invoke",
			},
			{
				Signal: SignalReflectionLoadClass,
				Patterns: [][]byte{
					[]byte("->loadclass("),
					[]byte("classloader;->loadclass"),
				},
				Context: "ClassLoader.loadClass",
			},
			{
				Signal: SignalReflectionDefineClass,
				Patterns: [][]byte{
					[]byte("->defineclass("),
					[]byte("classloader;->defineclass"),
				},
				Context: "ClassLoader.defineClass",
			},
			{
				Signal: SignalDexFileLoad,
				Patterns: [][]byte{
					[]byte("ldalvik/system/dexfile;"),
					[]byte("dexfile;->loaddex"),
					[]byte("dexfile;->loaddef"),
				},
				Context: "DexFile load",
			},
		},
	},
	{
		Name: "Network",
		Patterns: []SignalPattern{
			{
				Signal:   SignalNetworkHTTP,
				Patterns: [][]byte{[]byte("http://")},
				Context:  "HTTP URL",
			},
			{
				Signal:   SignalNetworkHTTPS,
				Patterns: [][]byte{[]byte("https://")},
				Context:  "HTTPS URL",
			},
			{
				Signal: SignalNetworkURLConnection,
				Patterns: [][]byte{
					[]byte("ljava/net/httpurlconnection;"),
					[]byte("ljava/net/urlconnection;"),
					[]byte("->openconnection("),
				},
				Context: "URLConnection",
			},
			{
				Signal: SignalNetworkOkHttp,
				Patterns: [][]byte{
					[]byte("lokhttp3/okhttpclient;"),
					[]byte("lokhttp3/request;"),
					[]byte("lokhttp3/call;"),
				},
				Context: "OkHttp client",
			},
			{
				Signal: SignalNetworkVolley,
				Patterns: [][]byte{
					[]byte("lcom/android/volley/"),
					[]byte("volley/request;"),
				},
				Context: "Volley network",
			},
			{
				Signal: SignalNetworkRetrofit,
				Patterns: [][]byte{
					[]byte("lretrofit2/"),
					[]byte("retrofit2/call;"),
				},
				Context: "Retrofit client",
			},
		},
	},
	{
		Name: "C2Exfiltration",
		Patterns: []SignalPattern{
			{
				Signal: SignalDiscordWebhook,
				Patterns: [][]byte{
					[]byte("discord.com/api/webhooks"),
					[]byte("discordapp.com/api/webhooks"),
					[]byte("discord.gg/"),
				},
				Context: "Discord webhook",
			},
			{
				Signal: SignalPastebin,
				Patterns: [][]byte{
					[]byte("pastebin.com"),
					[]byte("hastebin.com"),
					[]byte("paste.ee"),
					[]byte("ghostbin."),
				},
				Context: "Pastebin service",
			},
			{
				Signal: SignalGitHubRaw,
				Patterns: [][]byte{
					[]byte("raw.githubusercontent.com"),
					[]byte("gist.githubusercontent.com"),
					[]byte("raw.github.com"),
				},
				Context: "GitHub raw content",
			},
		},
	},
	{
		Name: "GeoFencing",
		Patterns: []SignalPattern{
			{
				Signal: SignalGeoFence,
				Patterns: [][]byte{
					[]byte("geo_fence"),
					[]byte("geofence"),
					[]byte("geo-fence"),
					[]byte("country_code"),
					[]byte("region_filter"),
					[]byte("target_countries"),
					[]byte("country_whitelist"),
					[]byte("country_blacklist"),
				},
				Context: "Geo-fencing / country check",
			},
		},
	},
	{
		Name: "FileOperations",
		Patterns: []SignalPattern{
			{
				Signal: SignalFileWrite,
				Patterns: [][]byte{
					[]byte("->write("),
					[]byte("->writebytes("),
				},
				Context: "File write operation",
			},
			{
				Signal: SignalFileOutputStream,
				Patterns: [][]byte{
					[]byte("ljava/io/fileoutputstream;"),
					[]byte("ljava/io/bufferedoutputstream;"),
				},
				Context: "FileOutputStream",
			},
			{
				Signal: SignalDexSuffix,
				Patterns: [][]byte{
					[]byte(".dex\""),
					[]byte(".dex'"),
					[]byte("classes.dex"),
					[]byte("/dex/"),
				},
				Context: ".dex file reference",
			},
			{
				Signal: SignalExternalStorage,
				Patterns: [][]byte{
					[]byte("getexternalstoragedirectory"),
					[]byte("getexternalfilesdir"),
					[]byte("/sdcard/"),
					[]byte("/storage/emulated/"),
				},
				Context: "External storage access",
			},
		},
	},
	{
		Name: "Obfuscation",
		Patterns: []SignalPattern{
			{
				Signal: SignalBase64Decode,
				Patterns: [][]byte{
					[]byte("landroid/util/base64;->decode"),
					[]byte("ljava/util/base64;->getdecoder"),
					[]byte("base64;->decode("),
				},
				Context: "Base64 decode",
			},
			{
				Signal: SignalXOR,
				Patterns: [][]byte{
					[]byte("xor-int"),
					[]byte("xor-long"),
				},
				Context: "XOR operation",
			},
			{
				Signal: SignalAES,
				Patterns: [][]byte{
					[]byte("aes/cbc/"),
					[]byte("aes/ecb/"),
					[]byte("aes/gcm/"),
					[]byte("\"aes\""),
				},
				Context: "AES encryption",
			},
			{
				Signal: SignalDES,
				Patterns: [][]byte{
					[]byte("\"des\""),
					[]byte("\"desede\""),
					[]byte("des/cbc/"),
				},
				Context: "DES encryption",
			},
			{
				Signal: SignalRC4,
				Patterns: [][]byte{
					[]byte("\"rc4\""),
					[]byte("\"arcfour\""),
				},
				Context: "RC4 encryption",
			},
		},
	},
	{
		Name: "WebViewAbuse",
		Patterns: []SignalPattern{
			{
				Signal: SignalWebViewLoadURL,
				Patterns: [][]byte{
					[]byte("landroid/webkit/webview;->loadurl("),
				},
				Context: "WebView.loadUrl",
			},
			{
				Signal: SignalWebViewLoadData,
				Patterns: [][]byte{
					[]byte("landroid/webkit/webview;->loaddatawithbaseurl("),
					[]byte("landroid/webkit/webview;->loaddata("),
				},
				Context: "WebView.loadData",
			},
			{
				Signal: SignalWebViewJSInterface,
				Patterns: [][]byte{
					[]byte("->addjavascriptinterface("),
					[]byte("addjavascriptinterface"),
				},
				Context: "WebView JavaScript interface",
			},
			{
				Signal: SignalWebViewJSEnabled,
				Patterns: [][]byte{
					[]byte("->setjavascriptenabled("),
					[]byte("setjavascriptenabled"),
				},
				Context: "JavaScript enabled",
			},
			{
				Signal: SignalWebViewOverrideURL,
				Patterns: [][]byte{
					[]byte("shouldoverrideurlloading"),
					[]byte("shouldinterceptrequest"),
				},
				Context: "WebView URL override",
			},
		},
	},
	{
		Name: "AccessibilityAbuse",
		Patterns: []SignalPattern{
			{
				Signal: SignalAccessibilityService,
				Patterns: [][]byte{
					[]byte("landroid/accessibilityservice/accessibilityservice;"),
					[]byte("accessibilityservice;->"),
				},
				Context: "AccessibilityService class",
			},
			{
				Signal: SignalAccessibilityEvent,
				Patterns: [][]byte{
					[]byte("onaccessibilityevent"),
					[]byte("accessibilityevent;"),
				},
				Context: "onAccessibilityEvent",
			},
			{
				Signal: SignalAccessibilityRootWindow,
				Patterns: [][]byte{
					[]byte("getrootinactivewindow"),
					[]byte("->getrootinactivewindow("),
				},
				Context: "getRootInActiveWindow",
			},
			{
				Signal: SignalAccessibilityGlobalAction,
				Patterns: [][]byte{
					[]byte("performglobalaction"),
					[]byte("->performglobalaction("),
				},
				Context: "performGlobalAction",
			},
			{
				Signal: SignalAccessibilityNodeInfo,
				Patterns: [][]byte{
					[]byte("accessibilitynodeinfo;"),
					[]byte("->findaccessibilitynodeinfosbytext("),
					[]byte("->findaccessibilitynodeinfosbyviewid("),
				},
				Context: "AccessibilityNodeInfo",
			},
		},
	},
	{
		Name: "RuntimeLoadDetection",
		Patterns: []SignalPattern{
			{
				Signal: SignalSystemLoadLibrary,
				Patterns: [][]byte{
					[]byte("ljava/lang/system;->loadlibrary("),
					[]byte("ljava/lang/system;->load("),
					[]byte("ljava/lang/runtime;->loadlibrary0("),
					[]byte("system;->loadlibrary("),
					[]byte("system;->load(ljava/lang/string;)v"),
				},
				Context: "System.loadLibrary / System.load",
			},
			{
				Signal: SignalRegisterNatives,
				Patterns: [][]byte{
					[]byte("registernatives"),
					[]byte("registernativemethod"),
					[]byte("jnienv->registernatives"),
					[]byte("->nativeload("),
				},
				Context: "JNI RegisterNatives binding",
			},
			{
				Signal: SignalEncryptedAssetDex,
				Patterns: [][]byte{
					[]byte("getassets()->open("),
					[]byte("assetmanager;->open("),
					[]byte("assets/classes"),
					[]byte("assets/payload"),
					[]byte("assets/dex"),
					[]byte("assets/a.dat"),
					[]byte("res/raw/classes"),
					[]byte(".enc\""),
					[]byte(".bin\""),
				},
				Context: "Encrypted asset payload",
			},
			{
				Signal: SignalContentProviderDex,
				Patterns: [][]byte{
					[]byte("contentprovider;->openfile("),
					[]byte("contentprovider;->call("),
					[]byte("contentresolver;->openinputstream("),
					[]byte("content://"),
				},
				Context: "ContentProvider-based DEX loading",
			},
			{
				Signal: SignalAttachBaseContext,
				Patterns: [][]byte{
					[]byte("->attachbasecontext("),
					[]byte("application;->attachbasecontext(landroid/content/context;)v"),
					[]byte("multidex;->install("),
				},
				Context: "Application.attachBaseContext hook (packer indicator)",
			},
			{
				Signal: SignalMultiDexInstall,
				Patterns: [][]byte{
					[]byte("landroidx/multidex/multidex;->install("),
					[]byte("landroid/support/multidex/multidex;->install("),
					[]byte("multidex;->installinstrumentation("),
				},
				Context: "MultiDex.install override",
			},
		},
	},
}

// ═══════════════════════════════════════════════════════════════════════════════
// MANIFEST PATTERNS
// ═══════════════════════════════════════════════════════════════════════════════

var ManifestPatterns = []PatternGroup{
	{
		Name: "StealerPermissions",
		Patterns: []SignalPattern{
			{
				Signal:   SignalAccessibilityPermission,
				Patterns: [][]byte{[]byte("android.permission.bind_accessibility_service")},
				Context:  "BIND_ACCESSIBILITY_SERVICE permission",
			},
			{
				Signal:   SignalPermissionSMS,
				Patterns: [][]byte{[]byte("android.permission.receive_sms"), []byte("android.permission.read_sms"), []byte("android.permission.send_sms")},
				Context:  "SMS permission",
			},
			{
				Signal:   SignalPermissionContacts,
				Patterns: [][]byte{[]byte("android.permission.read_contacts"), []byte("android.permission.write_contacts")},
				Context:  "Contacts permission",
			},
			{
				Signal:   SignalPermissionCallLog,
				Patterns: [][]byte{[]byte("android.permission.read_call_log"), []byte("android.permission.write_call_log")},
				Context:  "Call log permission",
			},
			{
				Signal:   SignalPermissionCamera,
				Patterns: [][]byte{[]byte("android.permission.camera")},
				Context:  "Camera permission",
			},
			{
				Signal:   SignalPermissionMicrophone,
				Patterns: [][]byte{[]byte("android.permission.record_audio")},
				Context:  "Microphone permission",
			},
			{
				Signal:   SignalPermissionLocation,
				Patterns: [][]byte{[]byte("android.permission.access_fine_location"), []byte("android.permission.access_coarse_location")},
				Context:  "Location permission",
			},
			{
				Signal:   SignalPermissionOverlay,
				Patterns: [][]byte{[]byte("android.permission.system_alert_window")},
				Context:  "Overlay permission",
			},
			{
				Signal:   SignalPermissionInstallPackages,
				Patterns: [][]byte{[]byte("android.permission.request_install_packages")},
				Context:  "Install packages permission",
			},
			{
				Signal:   SignalPermissionQueryPackages,
				Patterns: [][]byte{[]byte("android.permission.query_all_packages")},
				Context:  "Query all packages permission",
			},
			{
				Signal:   SignalPermissionUsageStats,
				Patterns: [][]byte{[]byte("android.permission.package_usage_stats")},
				Context:  "Usage stats permission",
			},
		},
	},
}

// ═══════════════════════════════════════════════════════════════════════════════
// NATIVE PATTERNS (case-sensitive for binary matching)
// ═══════════════════════════════════════════════════════════════════════════════

var NativePatterns = []PatternGroup{
	{
		Name: "AntiAnalysis",
		Patterns: []SignalPattern{
			{
				Signal:   SignalFrida,
				Patterns: [][]byte{[]byte("frida"), []byte("FRIDA"), []byte("gum-js-loop"), []byte("frida-agent")},
				Context:  "Frida detection",
			},
			{
				Signal:   SignalXposed,
				Patterns: [][]byte{[]byte("xposed"), []byte("Xposed"), []byte("de.robv.android.xposed"), []byte("XposedBridge")},
				Context:  "Xposed detection",
			},
			{
				Signal:   SignalSubstrate,
				Patterns: [][]byte{[]byte("substrate"), []byte("Substrate"), []byte("libsubstrate")},
				Context:  "Substrate detection",
			},
			{
				Signal:   SignalPtrace,
				Patterns: [][]byte{[]byte("ptrace"), []byte("PTRACE")},
				Context:  "Ptrace (anti-debug)",
			},
			{
				Signal:   SignalDlopen,
				Patterns: [][]byte{[]byte("dlopen"), []byte("dlsym")},
				Context:  "Dynamic library loading",
			},
			{
				Signal:   SignalDebuggerCheck,
				Patterns: [][]byte{[]byte("isDebuggerConnected"), []byte("TracerPid"), []byte("/proc/self/status")},
				Context:  "Debugger check",
			},
			{
				Signal:   SignalEmulatorCheck,
				Patterns: [][]byte{[]byte("goldfish"), []byte("generic_x86"), []byte("vbox"), []byte("genymotion"), []byte("Andy")},
				Context:  "Emulator check",
			},
			{
				Signal:   SignalRootCheck,
				Patterns: [][]byte{[]byte("/system/app/Superuser"), []byte("/system/xbin/su"), []byte("Magisk"), []byte("magisk")},
				Context:  "Root check",
			},
		},
	},
	{
		Name: "SuspiciousNative",
		Patterns: []SignalPattern{
			{
				Signal:   SignalNativeJNIOnLoad,
				Patterns: [][]byte{[]byte("JNI_OnLoad")},
				Context:  "JNI_OnLoad entry",
			},
			{
				Signal:   SignalNativeDexLoader,
				Patterns: [][]byte{[]byte("DexClassLoader"), []byte("InMemoryDexClassLoader"), []byte("classes.dex"), []byte("/dex/")},
				Context:  "Native DEX loading",
			},
			{
				Signal:   SignalNativeHTTP,
				Patterns: [][]byte{[]byte("http://"), []byte("https://"), []byte("curl_"), []byte("libcurl")},
				Context:  "Native HTTP",
			},
			{
				Signal:   SignalNativeC2,
				Patterns: [][]byte{[]byte("discord.com/api"), []byte("pastebin.com")},
				Context:  "Native C2",
			},
		},
	},
}

// ═══════════════════════════════════════════════════════════════════════════════
// REGEX PATTERNS
// ═══════════════════════════════════════════════════════════════════════════════

var CompiledPatterns = struct {
	IPv4          *regexp.Regexp
	SuspiciousTLD *regexp.Regexp
	Base64Long    *regexp.Regexp
	HexString     *regexp.Regexp
}{
	// Strict IPv4 with word boundaries
	IPv4: regexp.MustCompile(`\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b`),

	// Suspicious TLDs often used by malware
	SuspiciousTLD: regexp.MustCompile(`https?://[a-zA-Z0-9][-a-zA-Z0-9]*\.(ru|xyz|top|online|site|club|pw|cc|ws|tk|ml|ga|cf|gq|work|link|click|download|stream|racing|win|bid|trade|webcam|date|review|party|science|cricket|accountant|faith|loan|men|mom)\b`),

	// Potential Base64 encoded strings (40+ chars, base64 charset)
	Base64Long: regexp.MustCompile(`"[A-Za-z0-9+/=]{40,}"`),

	// Long hex strings (potential obfuscated data)
	HexString: regexp.MustCompile(`"[0-9a-fA-F]{32,}"`),
}

// Reserved IP ranges to exclude from IPv4 detection
var ReservedIPRanges = []string{
	"0.",
	"10.",
	"127.",
	"169.254.",
	"172.16.", "172.17.", "172.18.", "172.19.",
	"172.20.", "172.21.", "172.22.", "172.23.",
	"172.24.", "172.25.", "172.26.", "172.27.",
	"172.28.", "172.29.", "172.30.", "172.31.",
	"192.168.",
	"224.", "225.", "226.", "227.", "228.", "229.",
	"230.", "231.", "232.", "233.", "234.", "235.",
	"236.", "237.", "238.", "239.",
	"240.", "241.", "242.", "243.", "244.", "245.",
	"246.", "247.", "248.", "249.", "250.", "251.",
	"252.", "253.", "254.", "255.",
}

// IsReservedIP checks if an IP is in a reserved range
func IsReservedIP(ip string) bool {
	for _, prefix := range ReservedIPRanges {
		if len(ip) >= len(prefix) && ip[:len(prefix)] == prefix {
			return true
		}
	}
	return false
}
