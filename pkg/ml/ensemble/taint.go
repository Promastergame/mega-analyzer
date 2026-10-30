package ensemble

import "strings"

// ═══════════════════════════════════════════════════════════════════════════════
// LIGHTWEIGHT TAINT FLOW HEURISTIC
// ═══════════════════════════════════════════════════════════════════════════════
//
// We do not run a full IR-based taint analysis here — instead, we look for
// the classical pattern: an attacker-controlled SOURCE (Intent/extras, URI
// query, network response, file contents) flows into a SENSITIVE SINK
// (Runtime.exec, dynamic class loading, raw SQL, file write, native bridge).
//
// A method scores high when both ends are present in the same body and the
// distance between them is short (suggesting flow through local registers).

// taintSource is a substring marker for an input source.
type taintHint struct {
	Token  string
	Weight float64
}

var (
	sourceHints = []taintHint{
		{"intent;->getstringextra", 1.0},
		{"intent;->getstringextra(", 1.0},
		{"intent;->getserializableextra", 1.0},
		{"intent;->getextras", 0.9},
		{"intent;->getdata", 0.9},
		{"uri;->getqueryparameter", 0.9},
		{"bundle;->get", 0.8},
		{"sharedpreferences;->getstring", 0.6},
		{"file;->", 0.5},
		{"socket;->getinputstream", 0.7},
		{"httpurlconnection;->getinputstream", 0.7},
		{"webview;->loadurl", 0.6}, // attacker URL also as sink-ish
	}
	sinkHints = []taintHint{
		{"runtime;->exec", 1.0},
		{"processbuilder;->start", 1.0},
		{"system;->load", 0.9},
		{"system;->loadlibrary", 0.9},
		{"dexclassloader;-><init>", 1.0},
		{"pathclassloader;-><init>", 0.8},
		{"sqlitedatabase;->rawquery", 1.0},
		{"sqlitedatabase;->execsql", 1.0},
		{"file;->createnewfile", 0.5},
		{"fileoutputstream;->write", 0.6},
		{"webview;->loadurl", 0.7},
		{"webview;->evaluatejavascript", 0.9},
		{"keystore;->load", 0.4},
	}
)

// taintFlowScore returns a value in [0..1] estimating the chance the method
// implements an exploitable source→sink flow.
//
// The score considers:
//   - presence of source and sink lines
//   - proximity in the body (closer = higher)
//   - weights of the hits (best source weight × best sink weight)
//
// Body and calls are inspected together so we catch patterns expressed via
// invoke-* (calls slice) and via const-string + raw smali alike.
func taintFlowScore(body, calls []string) float64 {
	bestSource, bestSink := 0.0, 0.0
	srcLine, sinkLine := -1, -1

	scan := func(lines []string, hints []taintHint, store *float64, lineIdx *int) {
		for i, line := range lines {
			lower := strings.ToLower(line)
			for _, h := range hints {
				if strings.Contains(lower, h.Token) {
					if h.Weight > *store {
						*store = h.Weight
						*lineIdx = i
					}
				}
			}
		}
	}

	scan(body, sourceHints, &bestSource, &srcLine)
	scan(calls, sourceHints, &bestSource, &srcLine)
	scan(body, sinkHints, &bestSink, &sinkLine)
	scan(calls, sinkHints, &bestSink, &sinkLine)

	if bestSource == 0 || bestSink == 0 {
		return 0
	}

	// Proximity bonus: source-sink within 20 lines is a strong signal.
	prox := 0.5
	if srcLine >= 0 && sinkLine >= 0 {
		dist := sinkLine - srcLine
		if dist < 0 {
			dist = -dist
		}
		switch {
		case dist <= 5:
			prox = 1.0
		case dist <= 20:
			prox = 0.85
		case dist <= 50:
			prox = 0.65
		default:
			prox = 0.4
		}
	}

	score := bestSource * bestSink * prox
	return clamp01(score)
}
