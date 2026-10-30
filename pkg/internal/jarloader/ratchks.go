package jarloader

// RAT / stealer / tracker indicator coverage for the JAR analyzer.
//
// Mods have no legitimate reason to touch Discord token stores, browser
// credential databases, crypto wallets, webcams or keylog APIs — unlike
// generic applications, where half of these are dual-use. Every signal below
// was grounded on the Fractureiser stage-3 client (DiscordStealer,
// BrowserDataStealer, MSAStealer, Exodus wallet code, GetAsyncKeyState).
//
// Three signal kinds feed one archive-level combo rule:
//
//	path	well-known victim data locations (Login Data, exodus.wallet …)
//	api	dangerous platform APIs (Robot, TargetDataLine, CryptUnprotectData)
//	net	tracker/geolocation service hosts (api.ipify.org …)
//
// Singles are LOW/MEDIUM/HIGH by strength; three or more DISTINCT theft
// behaviors in one archive escalate to a HIGH malware-combo finding. The
// combo counts only ratchks subcategories (no double counting with the
// generic exec/reflection findings).
//
// Two FP guards, both learned from a clean cracked cheat client (wexside):
// microphone covers capture-side APIs only (playback via Clip is what
// every game client does), and class-name fragments count only beside
// real theft behavior in the same class.
//
// Two more, learned from a fat 1.12.2 client (keaz): victim-path rules
// stay silent inside bundled libraries (httpclient names its own cookies
// "Cookies"), and the ratsock rule stands down inside *webserver* classes
// (Javassist's bundled debug web server accept()s sockets).

import (
	"fmt"
	"sort"
	"strings"

	"mega-analyzer/pkg/internal/types"
)

// ratHit is one indicator inside a single class.
type ratHit struct {
	subcat   string // theft behavior bucket, e.g. "browser", "keylog"
	note     string // human-readable detail
	evidence string // matched string or API reference
	isAPI    bool   // method-reference hit (bytecode_invocation) vs string
	sev      types.Severity
}

// ratPath is a victim-data location substring (matched case-insensitively).
type ratPath struct {
	substr string
	subcat string
	note   string
	sev    types.Severity
}

var ratPaths = []ratPath{
	// Discord token stores.
	{"discord/Local Storage/leveldb", "discord", "Discord token database (leveldb)", types.SeverityMedium},
	{"discordcanary/Local Storage/leveldb", "discord", "Discord Canary token database", types.SeverityMedium},
	{"discordptb/Local Storage/leveldb", "discord", "Discord PTB token database", types.SeverityMedium},
	{"discord/Local State", "discord", "Discord state file (tokens)", types.SeverityMedium},
	// Browser credential stores.
	{"Login Data", "browser", "browser credential store (logins)", types.SeverityMedium},
	// Bare "Cookies" also names HTTP client cookie jars (lenni, okhttp):
	// LOW alone, the combo rule escalates real cookie theft in stealer
	// company.
	{"Cookies", "browser", "browser cookie store (session hijack)", types.SeverityLow},
	{"Web Data", "browser", "browser autofill/credit-card store", types.SeverityMedium},
	{"places.sqlite", "browser", "Firefox history/bookmarks database", types.SeverityMedium},
	{"logins.json", "browser", "Firefox saved logins", types.SeverityMedium},
	{"key4.db", "browser", "Firefox key database", types.SeverityMedium},
	{"formhistory.sqlite", "browser", "Firefox form history", types.SeverityMedium},
	// Crypto wallets.
	{"exodus.wallet", "wallet", "Exodus wallet file", types.SeverityMedium},
	{"exodus", "wallet", "Exodus wallet reference", types.SeverityMedium},
	{"electrum", "wallet", "Electrum wallet reference", types.SeverityMedium},
	{".electrum/wallets", "wallet", "Electrum wallets directory", types.SeverityMedium},
	{"wallet.dat", "wallet", "Bitcoin Core wallet file", types.SeverityMedium},
	{"Ledger Live", "wallet", "Ledger Live data", types.SeverityMedium},
	{"nkbihfbeogaeaoehlefnkodbefgpgknn", "wallet", "MetaMask extension id", types.SeverityMedium},
	// Bare "Atomic" fires on java.util.concurrent.atomic and ATOMIC_MOVE;
	// even "atomic/" matches package paths ("concurrent/atomic/..."). Only
	// the genuine wallet data path survives.
	{"atomic/local storage", "wallet", "Atomic wallet data directory", types.SeverityMedium},
	{"Coinomi", "wallet", "Coinomi wallet reference", types.SeverityMedium},
	{"Guarda", "wallet", "Guarda wallet reference", types.SeverityMedium},
	// Minecraft / gaming accounts.
	{"launcher_accounts.json", "minecraft", "Minecraft account tokens", types.SeverityMedium},
	{"launcher_profiles.json", "minecraft", "Minecraft profiles", types.SeverityMedium},
	{"usercache.json", "minecraft", "Minecraft user cache", types.SeverityMedium},
	{"loginusers.vdf", "steam", "Steam login users", types.SeverityMedium},
	{"ssfn", "steam", "Steam sentry file", types.SeverityMedium},
	// Messengers / remote access. "tdata" alone is forbidden here: it fires
	// on every getData/setData. Telegram session paths always carry the
	// "Telegram Desktop" directory or slash-delimited tdata.
	{"Telegram Desktop", "telegram", "Telegram Desktop data directory (sessions/tokens)", types.SeverityMedium},
	{"/tdata/", "telegram", "Telegram tdata session path", types.SeverityMedium},
	{"sitemanager.xml", "ftp", "FileZilla site manager (saved passwords)", types.SeverityMedium},
	{"recentservers.xml", "ftp", "FileZilla recent servers", types.SeverityMedium},
	{"WinSCP.ini", "ftp", "WinSCP saved sessions", types.SeverityMedium},
	{".ssh/id_rsa", "ssh", "SSH private key", types.SeverityMedium},
	{"id_rsa", "ssh", "SSH private key reference", types.SeverityLow},
}

// ratAPI is a dangerous platform API reference (class prefix or exact name).
type ratAPI struct {
	class  string // class prefix, or "" for name-only match
	name   string // method name, or "" for any method of the class
	subcat string
	note   string
	sev    types.Severity
}

var ratAPIs = []ratAPI{
	// Keylogging: zero legitimate use inside a Minecraft mod.
	{"", "GetAsyncKeyState", "keylog", "polls physical key state (keylogger)", types.SeverityHigh},
	{"", "SetWindowsHookEx", "keylog", "installs a system hook (keylogger)", types.SeverityHigh},
	{"", "GetKeyboardState", "keylog", "reads keyboard state", types.SeverityMedium},
	// Screen capture + input control.
	{"java.awt.Robot", "", "screen", "screen capture and input injection", types.SeverityMedium},
	// Microphone: capture side ONLY. Playback (Clip, SourceDataLine,
	// AudioSystem.getClip/getAudioInputStream) is what every game client
	// does for UI sounds; only TargetDataLine paths can record.
	{"javax.sound.sampled.TargetDataLine", "", "microphone", "microphone capture line", types.SeverityMedium},
	{"", "getTargetDataLine", "microphone", "opens a microphone capture line", types.SeverityMedium},
	{"", "getTargetLineInfo", "microphone", "queries microphone capture lines", types.SeverityMedium},
	// Camera.
	{"com.github.sarxos.", "", "camera", "webcam-capture library", types.SeverityMedium},
	// Windows credential decryption.
	{"", "CryptUnprotectData", "dpapi", "decrypts DPAPI-protected credentials", types.SeverityHigh},
	{"", "CryptProtectData", "dpapi", "DPAPI crypto API", types.SeverityMedium},
	// Clipboard (weak alone, meaningful in stealer company).
	{"java.awt.Toolkit", "getSystemClipboard", "clipboard", "system clipboard access", types.SeverityLow},
	{"java.awt.datatransfer.", "", "clipboard", "clipboard data-transfer API", types.SeverityLow},
	// Listening socket: accept() means a real listener (backdoor pattern);
	// a bare ServerSocket is often just a single-instance mutex.
	{"java.net.ServerSocket", "accept", "ratsock", "accepts inbound connections (backdoor listener pattern)", types.SeverityMedium},
	{"java.net.ServerSocket", "", "ratsock", "server socket object (mutex or listener)", types.SeverityLow},
}

// ratClassName marks damning class-name fragments (renamed builds evade
// this; strings and APIs above still catch them). A name hit counts only
// beside real theft behavior in the SAME class: game cheats name gameplay
// modules "stealer" too (ChestStealer loots chests, not credentials).
var ratClassName = []struct {
	frag   string
	subcat string
	note   string
}{
	{"stealer", "malware", "class name declares stealing"},
	{"keylog", "keylog", "class name declares keylogging"},
	{"clipper", "clipboard", "clipboard-hijacker class (clipper)"},
	{"grabber", "malware", "grabber class (credential/token theft)"},
}

// trackerHosts are IP/geolocation services: knowing the victim IP is the
// first step of targeting. LOW alone — the combo rule gives it weight.
var trackerHosts = map[string]bool{
	"api.ipify.org": true, "api64.ipify.org": true,
	"ip-api.com": true, "ipapi.co": true,
	"ifconfig.me": true, "checkip.amazonaws.com": true,
	"checkip.dyndns.org": true, "wtfismyip.com": true,
	"geolocation-db.com": true, "ipinfo.io": true,
	"freegeoip.app": true,
}

// ratSignals scans one class for stealer/tracker indicators.
func ratSignals(cf *ClassFile) []ratHit {
	var out []ratHit
	if cf == nil {
		return nil
	}
	lowClass := strings.ToLower(cf.ThisClass)
	var nameHits []ratHit
	for _, c := range ratClassName {
		if strings.Contains(lowClass, c.frag) {
			nameHits = append(nameHits, ratHit{subcat: c.subcat, note: c.note, evidence: cf.ThisClass, sev: types.SeverityMedium})
		}
	}
	// Library self-talk is not theft: httpclient's own CookieStore names
	// its cookies "Cookies", and Javassist ships a debug web server that
	// accept()s sockets. Path rules go fully silent inside bundled
	// libraries (isThirdPartyLibrary); API rules additionally stand down
	// for the caller namespaces in ratLibCaller.
	libCaller := isThirdPartyLibrary(cf.ThisClass)
	apiSilent := ratLibCaller(cf.ThisClass)
	// Broad pool first (paths also hide in descriptors), genuine literals
	// as fallback for hand-built fixtures. Skipped for library callers
	// (see libCaller above).
	strs := cf.Strings
	if len(strs) == 0 {
		strs = secretScanStrings(cf)
	}
	if !libCaller {
		for _, s := range strs {
			low := strings.ToLower(s)
			for _, p := range ratPaths {
				if strings.Contains(low, strings.ToLower(p.substr)) {
					out = append(out, ratHit{subcat: p.subcat, note: p.note, evidence: truncEvidence(s), sev: p.sev})
				}
			}
			if host, _, _ := splitBytecodeURL(s); host != "" && trackerHosts[host] {
				out = append(out, ratHit{subcat: "ip-tracker", note: "IP geolocation lookup service (" + host + ")", evidence: truncEvidence(s), sev: types.SeverityLow})
			}
		}
	}
	if !apiSilent {
		for _, r := range cf.MethodRefs {
			for _, a := range ratAPIs {
				if a.class != "" && !strings.HasPrefix(r.Class, a.class) {
					continue
				}
				if a.name != "" && r.Name != a.name {
					continue
				}
				out = append(out, ratHit{subcat: a.subcat, note: a.note, evidence: r.FullName(), isAPI: true, sev: a.sev})
				break // first (most specific) table entry wins per reference
			}
		}
	}
	// Name-only hits stay silent without corroborating theft behavior in
	// the same class (see ratClassName).
	if len(out) > 0 {
		out = append(out, nameHits...)
	}
	return out
}

// ratLibCaller reports whether API references from this class are library
// self-implementation rather than foreign uses: the shared prefix table
// (isThirdPartyLibrary) plus namespaces it does not cover — bundled game
// natives (lwjgl), shaded protocol libs (viaversion), and Javassist, which
// is routinely shaded (hence the contains-match; dot-delimited so
// "javassistlike" does not match). Deliberately NOT net.minecraft.*: malware
// does hide there, and vanilla rows are LOW noise that cannot combo alone.
func ratLibCaller(dotted string) bool {
	if isThirdPartyLibrary(dotted) {
		return true
	}
	low := strings.ToLower(dotted)
	for _, p := range []string{"org.lwjgl.", "com.viaversion."} {
		if strings.HasPrefix(low, p) {
			return true
		}
	}
	return strings.HasPrefix(low, "javassist.") || strings.Contains(low, ".javassist.")
}

func truncEvidence(s string) string {
	s = strings.TrimSpace(s)
	if len(s) > 120 {
		return s[:120] + "…"
	}
	return s
}

// emitRatFindings turns per-class hits into STEALER_INDICATOR matches.
func emitRatFindings(hits []ratHit, className, entry string) []types.Match {
	out := make([]types.Match, 0, len(hits))
	for _, h := range hits {
		ev := "bytecode_string"
		if h.isAPI {
			ev = "bytecode_invocation"
		}
		out = append(out, types.Match{
			Categorized:       types.Categorized{Category: types.CategoryStealerIndicator},
			Text:              h.evidence,
			Pattern:           "rat-indicator:" + h.subcat,
			Context:           "stealer/tracker indicator (" + h.subcat + ") in " + className + ": " + h.note,
			ClassName:         className,
			Severity:          h.sev,
			Confidence:        "0.75",
			EvidenceType:      ev,
			ReasonForSeverity: "data-theft capability (" + h.subcat + "): " + h.note,
			SourceLocation:    types.SourceLocation{File: entry},
		})
	}
	return out
}

// emitRatCombo escalates when DISTINCT theft behaviors co-occur in one
// archive: a keylogger that also reads browser stores and wallets is a
// stealer, not three coincidences. Threshold 3 keeps single-dual-use hits
// (clipboard alone) from screaming.
func emitRatCombo(rep *Report) *types.Match {
	if rep == nil {
		return nil
	}
	// Distinct theft subcategories across all rat-indicator findings.
	catSet := map[string]bool{}
	for _, f := range rep.Findings {
		if f.Category != types.CategoryStealerIndicator {
			continue
		}
		if sub, ok := strings.CutPrefix(f.Pattern, "rat-indicator:"); ok && sub != "" {
			catSet[sub] = true
		}
	}
	if len(catSet) < 3 {
		return nil
	}
	cats := make([]string, 0, len(catSet))
	for c := range catSet {
		cats = append(cats, c)
	}
	sort.Strings(cats)
	return &types.Match{
		Categorized:          types.Categorized{Category: types.CategoryMalwareCombo},
		Text:                 "stealer-combo",
		Pattern:              "stealer-combo",
		Context:              fmt.Sprintf("probable stealer/RAT: %d distinct data-theft behaviors in one archive (%s)", len(cats), strings.Join(cats, ", ")),
		Severity:             types.SeverityHigh,
		Confidence:           "0.80",
		EvidenceType:         "indicator_combo",
		ReasonForSeverity:    "multiple independent theft capabilities co-occur; see STEALER_INDICATOR rows for each",
		SourceLocation:       types.SourceLocation{File: rep.Target},
		RequiredNextEvidence: "Confirm an exfiltration sink (webhook, bot API, socket) receiving the collected data.",
	}
}
