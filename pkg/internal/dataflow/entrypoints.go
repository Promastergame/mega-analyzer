// entrypoints.go — IPC entry-point parameter tainting (audit C2 / P1-7).
//
// Android lifecycle callbacks receive attacker-controlled data by design:
// a broadcast receiver's Intent, a service's start Intent, a content
// provider's Uri/selection, an activity's redirection Intent. Before this
// module, the taint engine only seeded explicit source CALLS, so chains
// that begin inside these callbacks (the dominant IPC attack surface)
// started untainted.
//
// Matching is heuristic — lifecycle method name + parameter signature shape
// — and seeded facts carry a depth penalty so findings derived from them
// report lower confidence than flows from concrete source calls.
package dataflow

type entryTaint struct {
	param  int
	labels Label
}

const entryPointDepthPenalty = 2 // heuristic origin → confidence -= 0.10

// entryPointTaints returns the attacker-controlled parameters of a method,
// keyed by lifecycle name + signature shape. Empty for ordinary methods.
func entryPointTaints(method methodData) []entryTaint {
	if method.IsStatic {
		return nil
	}
	params := paramDescriptors(method.Params)
	has := func(i int, want string) bool { return i < len(params) && params[i] == want }

	const intent = "Landroid/content/Intent;"
	const uri = "Landroid/net/Uri;"
	const str = "Ljava/lang/String;"
	ipc := LabelIntent | LabelUserInput

	switch method.Name {
	// Intent-bearing lifecycle callbacks.
	case "onNewIntent", "onHandleIntent", "onStartCommand", "onBind",
		"onRebind", "onUnbind", "onTaskRemoved":
		if has(0, intent) {
			return []entryTaint{{0, ipc}}
		}
	case "onReceive":
		if len(params) == 2 && has(1, intent) {
			return []entryTaint{{1, ipc}}
		}
	case "onActivityResult":
		if len(params) == 3 && has(2, intent) {
			return []entryTaint{{2, ipc}}
		}
	case "onCreate":
		// Activity.onCreate(Bundle): the restored state can be forged by a
		// caller using startActivityForResult on a task-reparented activity.
		if len(params) == 1 && has(0, "Landroid/os/Bundle;") {
			return []entryTaint{{0, LabelIntent}}
		}

	// ContentProvider: every string-like parameter is caller-controlled.
	case "query":
		if len(params) == 5 && has(0, uri) {
			return []entryTaint{{0, ipc}, {2, ipc}, {3, ipc}, {4, ipc}}
		}
	case "update":
		if len(params) == 4 && has(0, uri) {
			return []entryTaint{{0, ipc}, {2, ipc}, {3, ipc}}
		}
	case "delete":
		if len(params) == 3 && has(0, uri) {
			return []entryTaint{{0, ipc}, {1, ipc}, {2, ipc}}
		}
	case "insert", "bulkInsert":
		if has(0, uri) {
			return []entryTaint{{0, ipc}}
		}
	case "openFile", "openAssetFile", "openTypedAssetFile":
		if has(0, uri) {
			return []entryTaint{{0, ipc}}
		}
	case "call":
		if len(params) == 3 && has(0, str) && has(1, str) {
			return []entryTaint{{0, ipc}, {1, ipc}}
		}

	// WebViewClient URL interception.
	case "shouldOverrideUrlLoading":
		if len(params) == 2 && has(1, str) {
			return []entryTaint{{1, LabelNetwork | LabelUserInput}}
		}
	}
	return nil
}

// paramDescriptors splits a dex parameter descriptor list
// ("Landroid/content/Intent;I[B") into individual descriptors.
func paramDescriptors(descriptor string) []string {
	var out []string
	i := 0
	for i < len(descriptor) {
		start := i
		for i < len(descriptor) && descriptor[i] == '[' {
			i++
		}
		if i >= len(descriptor) {
			break
		}
		switch descriptor[i] {
		case 'L':
			for i < len(descriptor) && descriptor[i] != ';' {
				i++
			}
			if i >= len(descriptor) {
				return out
			}
			i++
		default:
			i++
		}
		out = append(out, descriptor[start:i])
	}
	return out
}
