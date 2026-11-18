package dataflow

import "strings"

type sourceModel struct {
	method string
	label  Label
}

type sinkModel struct {
	method    string
	param     int
	labels    Label
	category  string
	severity  string
	sanitizer Sanitizer
}

type sanitizerModel struct {
	method string
	kind   Sanitizer
	// drop marks destructive sanitizers (numeric parsing): the value's type
	// changes so thoroughly that no string-taint can survive — labels are
	// dropped entirely instead of merely flagged as sanitized (audit C4).
	drop bool
}

const pathTraversalLabels = LabelIntent | LabelUserInput | LabelNetwork | LabelFile

// Source catalog: APIs that yield attacker-influenced data.
var sourceModels = []sourceModel{
	// UI input
	{"Landroid/widget/EditText;->getText", LabelUserInput},
	{"Landroid/content/ClipboardManager;->getPrimaryClip", LabelUserInput | LabelPII},

	// IPC: Intent extras and Uri components (deep links)
	{"Landroid/content/Intent;->getStringExtra", LabelIntent | LabelUserInput},
	{"Landroid/content/Intent;->getStringArrayExtra", LabelIntent | LabelUserInput},
	{"Landroid/content/Intent;->getCharSequenceExtra", LabelIntent | LabelUserInput},
	{"Landroid/content/Intent;->getSerializableExtra", LabelIntent | LabelUserInput},
	{"Landroid/content/Intent;->getParcelableExtra", LabelIntent | LabelUserInput},
	{"Landroid/content/Intent;->getBundleExtra", LabelIntent | LabelUserInput},
	{"Landroid/content/Intent;->getStringArrayListExtra", LabelIntent | LabelUserInput},
	{"Landroid/content/Intent;->getData", LabelIntent | LabelUserInput},
	{"Landroid/content/Intent;->getDataString", LabelIntent | LabelUserInput},
	{"Landroid/content/Intent;->getAction", LabelIntent | LabelUserInput},
	{"Landroid/content/Intent;->getExtras", LabelIntent | LabelUserInput},
	{"Landroidx/activity/result/ActivityResult;->getData", LabelIntent | LabelUserInput},
	{"Landroidx/core/app/ShareCompat$IntentReader;->getStream", LabelIntent | LabelFile | LabelUserInput},
	{"Landroid/os/Bundle;->getString", LabelIntent | LabelUserInput},
	{"Landroid/os/Bundle;->getStringArray", LabelIntent | LabelUserInput},
	{"Landroid/os/Bundle;->get", LabelIntent | LabelUserInput},
	{"Landroid/os/Bundle;->getCharSequence", LabelIntent | LabelUserInput},
	{"Landroid/os/Bundle;->getParcelable", LabelIntent | LabelUserInput},
	{"Landroid/os/Parcel;->readString", LabelIntent | LabelUserInput},
	{"Landroid/app/Activity;->getIntent", LabelIntent},

	// Content providers
	{"Landroid/content/ContentResolver;->openInputStream", LabelFile | LabelNetwork},
	{"Landroid/content/ContentResolver;->openFileDescriptor", LabelFile},
	{"Landroid/database/Cursor;->getString", LabelDatabase},

	// Archive entry names are attacker controlled when the archive comes from
	// outside the trust boundary. Keeping a dedicated file label lets the path
	// sinks produce a Zip-Slip evidence chain instead of a generic heuristic.
	{"Ljava/util/zip/ZipEntry;->getName", LabelFile},
	{"Ljava/util/jar/JarEntry;->getName", LabelFile},

	// Network / inter-device input
	{"Ljava/net/HttpURLConnection;->getInputStream", LabelNetwork},
	{"Lokhttp3/ResponseBody;->string", LabelNetwork},
	{"Lokhttp3/ResponseBody;->bytes", LabelNetwork},
	{"Lokhttp3/ResponseBody;->byteStream", LabelNetwork},
	{"Lokhttp3/Response;->body", LabelNetwork},
	{"Lretrofit2/Response;->body", LabelNetwork},
	{"Ljava/net/Socket;->getInputStream", LabelNetwork},
	{"Landroid/bluetooth/BluetoothSocket;->getInputStream", LabelNetwork},
	{"Landroid/telephony/SmsMessage;->getMessageBody", LabelNetwork | LabelUserInput},
	{"Landroid/telephony/SmsMessage;->getDisplayMessageBody", LabelNetwork | LabelUserInput},
	{"Landroid/webkit/WebResourceRequest;->getUrl", LabelNetwork | LabelUserInput},

	// Local storage
	{"Ljava/io/FileInputStream;->read", LabelFile},
	{"Landroid/content/SharedPreferences;->getString", LabelFile},

	// Deserialization of untrusted objects
	{"Ljava/io/ObjectInputStream;->readObject", LabelNetwork | LabelFile | LabelUserInput},

	// Privacy-sensitive
	{"Landroid/location/LocationManager;->getLastKnownLocation", LabelLocation | LabelPII},
	{"Landroid/accounts/AccountManager;->getAccounts", LabelCredential | LabelPII},
}

// Sink catalog: dangerous operations parameterized by attacker data.
// Multiple models may share a signature (e.g. sendBroadcast is both a data
// exposure and an interception sink); sinksFor returns ALL matches.
var sinkModels = []sinkModel{
	// SQL injection
	{"Landroid/database/sqlite/SQLiteDatabase;->rawQuery", 0, LabelUserInput | LabelIntent | LabelNetwork, "sql_injection", "critical", SanitizerSQL},
	{"Landroid/database/sqlite/SQLiteDatabase;->execSQL", 0, LabelUserInput | LabelIntent | LabelNetwork, "sql_injection", "critical", SanitizerSQL},

	// Command injection
	{"Ljava/lang/Runtime;->exec", 0, LabelUserInput | LabelIntent | LabelNetwork, "command_injection", "critical", SanitizerNone},
	{"Ljava/lang/ProcessBuilder;-><init>", 0, LabelUserInput | LabelIntent | LabelNetwork, "command_injection", "critical", SanitizerNone},

	// Dynamic code loading
	{"Ldalvik/system/DexClassLoader;-><init>", 0, LabelIntent | LabelUserInput | LabelNetwork | LabelFile, "dynamic_code_loading", "critical", SanitizerNone},
	{"Ldalvik/system/PathClassLoader;-><init>", 0, LabelIntent | LabelUserInput | LabelNetwork | LabelFile, "dynamic_code_loading", "critical", SanitizerNone},
	{"Ldalvik/system/InMemoryDexClassLoader;-><init>", 0, LabelIntent | LabelUserInput | LabelNetwork | LabelFile, "dynamic_code_loading", "critical", SanitizerNone},
	{"Ldalvik/system/DelegateLastClassLoader;-><init>", 0, LabelIntent | LabelUserInput | LabelNetwork | LabelFile, "dynamic_code_loading", "critical", SanitizerNone},
	{"Ljava/lang/System;->load", 0, LabelIntent | LabelUserInput | LabelNetwork | LabelFile, "dynamic_code_loading", "critical", SanitizerNone},
	{"Ljava/lang/System;->loadLibrary", 0, LabelIntent | LabelUserInput | LabelNetwork, "dynamic_code_loading", "critical", SanitizerNone},
	{"Ljava/lang/Runtime;->load", 0, LabelIntent | LabelUserInput | LabelNetwork | LabelFile, "dynamic_code_loading", "critical", SanitizerNone},
	{"Ljava/lang/Runtime;->loadLibrary", 0, LabelIntent | LabelUserInput | LabelNetwork, "dynamic_code_loading", "critical", SanitizerNone},

	// Reflection
	{"Ljava/lang/Class;->forName", 0, LabelIntent | LabelUserInput | LabelNetwork, "dynamic_class_loading", "high", SanitizerNone},
	// Method.invoke(Object receiver, Object[] args): the method selector is
	// the Method object, not the Object receiver passed as argument zero.
	{"Ljava/lang/reflect/Method;->invoke", -1, LabelIntent | LabelUserInput | LabelNetwork | LabelFile, "reflection_invocation", "high", SanitizerNone},

	// Path traversal
	{"Ljava/io/File;-><init>", 0, pathTraversalLabels, "path_traversal", "high", SanitizerPath},
	// File(File parent, String child): the child is just as security-sensitive
	// as the one-argument path overload.
	{"Ljava/io/File;-><init>", 1, pathTraversalLabels, "path_traversal", "high", SanitizerPath},
	{"Ljava/io/FileInputStream;-><init>", 0, pathTraversalLabels, "path_traversal", "high", SanitizerPath},
	{"Ljava/io/FileOutputStream;-><init>", 0, pathTraversalLabels, "path_traversal", "high", SanitizerPath},
	{"Ljava/io/RandomAccessFile;-><init>", 0, pathTraversalLabels, "path_traversal", "high", SanitizerPath},
	{"Landroid/content/Context;->openFileInput", 0, pathTraversalLabels, "path_traversal", "high", SanitizerPath},
	{"Landroid/content/Context;->openFileOutput", 0, pathTraversalLabels, "path_traversal", "high", SanitizerPath},
	{"Ljava/util/zip/ZipFile;-><init>", 0, pathTraversalLabels, "path_traversal", "high", SanitizerPath},
	{"Landroid/os/ParcelFileDescriptor;->open", 0, pathTraversalLabels, "path_traversal", "high", SanitizerPath},

	// XML external entity (XXE) — parsers fed with untrusted documents
	{"Ljavax/xml/parsers/DocumentBuilder;->parse", 0, LabelNetwork | LabelFile | LabelIntent, "xxe", "high", SanitizerNone},
	{"Ljavax/xml/parsers/SAXParser;->parse", 0, LabelNetwork | LabelFile | LabelIntent, "xxe", "high", SanitizerNone},
	{"Lorg/xml/sax/XMLReader;->parse", 0, LabelNetwork | LabelFile | LabelIntent, "xxe", "high", SanitizerNone},
	{"Ljavax/xml/transform/stream/StreamSource;-><init>", 0, LabelNetwork | LabelFile | LabelIntent, "xxe", "medium", SanitizerNone},

	// Insecure deserialization (untrusted stream wrapped in ObjectInputStream)
	{"Ljava/io/ObjectInputStream;-><init>", 0, LabelNetwork | LabelFile | LabelIntent, "insecure_deserialization", "critical", SanitizerNone},

	// Intent redirection: attacker-controlled Intent forwarded to the OS
	{"Landroid/content/Context;->startActivity", 0, LabelIntent | LabelUserInput | LabelNetwork, "intent_redirection", "high", SanitizerNone},
	{"Landroid/app/Activity;->startActivity", 0, LabelIntent | LabelUserInput | LabelNetwork, "intent_redirection", "high", SanitizerNone},
	{"Landroid/app/Activity;->startActivityForResult", 0, LabelIntent | LabelUserInput | LabelNetwork, "intent_redirection", "high", SanitizerNone},
	{"Landroid/content/Context;->startActivityForResult", 0, LabelIntent | LabelUserInput | LabelNetwork, "intent_redirection", "high", SanitizerNone},
	{"Landroid/content/Context;->startService", 0, LabelIntent | LabelUserInput | LabelNetwork, "intent_redirection", "high", SanitizerNone},
	{"Landroid/app/Activity;->startService", 0, LabelIntent | LabelUserInput | LabelNetwork, "intent_redirection", "high", SanitizerNone},
	{"Landroid/content/Context;->startForegroundService", 0, LabelIntent | LabelUserInput | LabelNetwork, "intent_redirection", "high", SanitizerNone},
	{"Landroid/content/Context;->bindService", 0, LabelIntent | LabelUserInput | LabelNetwork, "intent_redirection", "high", SanitizerNone},

	// WebView content loading
	{"Landroid/webkit/WebView;->loadUrl", 0, LabelUserInput | LabelIntent | LabelNetwork, "webview_injection", "high", SanitizerNone},
	{"Landroid/webkit/WebView;->loadData", 0, LabelUserInput | LabelIntent | LabelNetwork, "webview_injection", "high", SanitizerNone},
	{"Landroid/webkit/WebView;->loadDataWithBaseURL", 1, LabelUserInput | LabelIntent | LabelNetwork, "webview_injection", "high", SanitizerNone},
	{"Landroid/webkit/WebView;->loadDataWithBaseURL", 0, LabelUserInput | LabelIntent | LabelNetwork, "webview_untrusted_origin", "high", SanitizerNone},
	{"Landroid/webkit/WebView;->postUrl", 0, LabelUserInput | LabelIntent | LabelNetwork, "webview_injection", "high", SanitizerNone},
	{"Landroid/webkit/WebView;->evaluateJavascript", 0, LabelUserInput | LabelIntent | LabelNetwork, "javascript_injection", "critical", SanitizerNone},
	{"Landroid/webkit/WebView;->addJavascriptInterface", 0, LabelIntent | LabelNetwork, "webview_bridge_exposure", "medium", SanitizerNone},

	// An untrusted nested Intent used to build a PendingIntent becomes
	// dangerous when the factory is mutable. The mutable-flag detector adds the
	// configuration evidence; this flow gives the attacker-controlled route.
	{"Landroid/app/PendingIntent;->getActivity", 2, LabelIntent | LabelUserInput | LabelNetwork, "pending_intent_injection", "high", SanitizerNone},
	{"Landroid/app/PendingIntent;->getActivities", 2, LabelIntent | LabelUserInput | LabelNetwork, "pending_intent_injection", "high", SanitizerNone},
	{"Landroid/app/PendingIntent;->getBroadcast", 2, LabelIntent | LabelUserInput | LabelNetwork, "pending_intent_injection", "high", SanitizerNone},
	{"Landroid/app/PendingIntent;->getService", 2, LabelIntent | LabelUserInput | LabelNetwork, "pending_intent_injection", "high", SanitizerNone},

	// SSRF: URL built from untrusted input
	{"Ljava/net/URL;-><init>", 0, LabelIntent | LabelUserInput, "ssrf", "high", SanitizerNone},
	{"Lokhttp3/Request$Builder;->url", 0, LabelIntent | LabelUserInput, "ssrf", "high", SanitizerNone},

	// Sensitive data exposure
	{"Ljava/io/OutputStream;->write", 0, LabelPII | LabelCredential | LabelLocation, "sensitive_data_exposure", "high", SanitizerNone},
	{"Landroid/util/Log;->d", 1, LabelPII | LabelCredential | LabelLocation | LabelUserInput, "log_data_exposure", "medium", SanitizerNone},
	{"Landroid/util/Log;->i", 1, LabelPII | LabelCredential | LabelLocation | LabelUserInput, "log_data_exposure", "medium", SanitizerNone},
	{"Landroid/util/Log;->e", 1, LabelPII | LabelCredential | LabelLocation | LabelUserInput, "log_data_exposure", "medium", SanitizerNone},
	{"Landroid/util/Log;->v", 1, LabelPII | LabelCredential | LabelLocation | LabelUserInput, "log_data_exposure", "medium", SanitizerNone},
	{"Landroid/util/Log;->w", 1, LabelPII | LabelCredential | LabelLocation | LabelUserInput, "log_data_exposure", "medium", SanitizerNone},
	{"Landroid/content/Context;->sendBroadcast", 0, LabelPII | LabelCredential | LabelLocation, "ipc_data_exposure", "high", SanitizerNone},
	{"Landroid/content/Context;->sendBroadcast", 0, LabelIntent | LabelUserInput | LabelNetwork, "broadcast_interception", "medium", SanitizerNone},
	{"Landroid/content/Context;->sendOrderedBroadcast", 0, LabelPII | LabelCredential | LabelLocation, "ipc_data_exposure", "high", SanitizerNone},
}

var sanitizerModels = []sanitizerModel{
	{"Landroid/database/DatabaseUtils;->sqlEscapeString", SanitizerSQL, false},
	{"Landroid/text/TextUtils;->htmlEncode", SanitizerHTML, false},
	// Encoding and canonicalization preserve origin. Neither proves containment:
	// URLEncoder("..") == ".."; canonical paths can be outside the permitted root.
	// Numeric parsing converts to a primitive: no string payload survives.
	{"Ljava/lang/Integer;->parseInt", SanitizerNumeric, true},
	{"Ljava/lang/Integer;->valueOf", SanitizerNumeric, true},
	{"Ljava/lang/Long;->parseLong", SanitizerNumeric, true},
	{"Ljava/lang/Long;->valueOf", SanitizerNumeric, true},
	{"Ljava/lang/Float;->parseFloat", SanitizerNumeric, true},
	{"Ljava/lang/Double;->parseDouble", SanitizerNumeric, true},
	{"Ljava/lang/Boolean;->parseBoolean", SanitizerNumeric, true},
	{"Ljava/lang/Byte;->parseByte", SanitizerNumeric, true},
	{"Ljava/lang/Short;->parseShort", SanitizerNumeric, true},
}

func sourceFor(signature string) (sourceModel, bool) {
	for _, model := range sourceModels {
		if methodMatches(model.method, signature) {
			return model, true
		}
	}
	return sourceModel{}, false
}

// Containers do not establish an IPC boundary: an app can fill a Bundle or
// Parcel itself. Trace their receiver before attributing attacker control.
func containerReadSource(signature string) bool {
	return strings.HasPrefix(signature, "Landroid/os/Bundle;->") ||
		strings.HasPrefix(signature, "Landroid/os/Parcel;->read")
}

func sinksFor(signature string) []sinkModel {
	var out []sinkModel
	for _, model := range sinkModels {
		if methodMatches(model.method, signature) {
			out = append(out, model)
		}
	}
	return out
}

func sanitizerFor(signature string) (sanitizerModel, bool) {
	for _, model := range sanitizerModels {
		if methodMatches(model.method, signature) {
			return model, true
		}
	}
	return sanitizerModel{}, false
}

func methodMatches(prefix, signature string) bool {
	return signature == prefix || strings.HasPrefix(signature, prefix+"(")
}

func isIntentPut(signature string) bool {
	return methodMatches("Landroid/content/Intent;->putExtra", signature) ||
		methodMatches("Landroid/os/Bundle;->putString", signature) ||
		methodMatches("Landroid/os/Bundle;->putParcelable", signature)
}

func isValuePropagator(signature string) bool {
	for _, prefix := range []string{
		"Ljava/lang/String;->valueOf", "Ljava/lang/String;->concat",
		"Ljava/lang/StringBuilder;->append", "Ljava/lang/StringBuilder;->toString",
		"Ljava/lang/StringBuffer;->append", "Ljava/lang/StringBuffer;->toString",
		"Ljava/lang/Object;->toString",
		"Landroid/net/Uri;->toString", "Landroid/net/Uri;->parse", "Landroid/net/Uri;->encode",
		// Reading a component does not make an app-owned URI attacker input.
		// Propagate the receiver's origin (Intent, network, etc.) instead.
		"Landroid/net/Uri;->getQueryParameter", "Landroid/net/Uri;->getPath",
		"Landroid/net/Uri;->getLastPathSegment", "Landroid/net/Uri;->getHost", "Landroid/net/Uri;->getFragment",
		"Ljava/net/URLEncoder;->encode",
		"Ljava/io/File;->getCanonicalPath", "Ljava/io/File;->getCanonicalFile",
		"Ljava/nio/file/Path;->normalize", "Ljava/nio/file/Path;->toRealPath",
		"Ljava/nio/ByteBuffer;->wrap",
		"Landroid/util/Base64;->encodeToString", "Landroid/util/Base64;->decode",
		"Ljava/lang/reflect/Method;->invoke",
		"Ljava/lang/Class;->forName", "Ljava/lang/Class;->getMethod", "Ljava/lang/Class;->getDeclaredMethod",
	} {
		if methodMatches(prefix, signature) {
			return true
		}
	}
	return false
}
