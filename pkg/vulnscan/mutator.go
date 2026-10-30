package vulnscan

import (
	"encoding/json"
	"sort"
)

// MutateJSON recursively walks a JSON document and, for every string-valued
// leaf at any depth (inside nested objects and arrays), produces a mutated
// copy of the whole document with the payload substituted at that single
// location. Structure (the AST) is preserved so the backend parser accepts the
// request instead of rejecting it outright.
//
// Contract (relied upon by callers and tests):
//   - invalid or empty JSON input returns an error
//   - valid JSON with no string leaves (e.g. "{}") returns an empty slice, nil
//   - valid JSON with N string leaves returns N mutated variants
func MutateJSON(body []byte, payload string) ([][]byte, error) {
	var root interface{}
	if err := json.Unmarshal(body, &root); err != nil {
		return nil, err
	}

	// Collect the path to every string leaf. Paths are ordered
	// deterministically (sorted map keys) so output is stable across runs.
	var stringPaths [][]interface{}
	var walk func(node interface{}, path []interface{})
	walk = func(node interface{}, path []interface{}) {
		switch v := node.(type) {
		case map[string]interface{}:
			keys := make([]string, 0, len(v))
			for k := range v {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			for _, k := range keys {
				child := v[k]
				next := appendStep(path, k)
				if _, ok := child.(string); ok {
					stringPaths = append(stringPaths, next)
				}
				walk(child, next)
			}
		case []interface{}:
			for i, child := range v {
				next := appendStep(path, i)
				if _, ok := child.(string); ok {
					stringPaths = append(stringPaths, next)
				}
				walk(child, next)
			}
		}
	}
	walk(root, nil)

	payloads := make([][]byte, 0, len(stringPaths))
	for _, p := range stringPaths {
		// Deep-copy via round-trip so each mutation is independent.
		copyBytes, err := json.Marshal(root)
		if err != nil {
			continue
		}
		var copyRoot interface{}
		if err := json.Unmarshal(copyBytes, &copyRoot); err != nil {
			continue
		}
		if setJSONPath(copyRoot, p, payload) {
			if mutated, err := json.Marshal(copyRoot); err == nil {
				payloads = append(payloads, mutated)
			}
		}
	}
	return payloads, nil
}

// appendStep returns a new path slice with step appended (never aliases path).
func appendStep(path []interface{}, step interface{}) []interface{} {
	next := make([]interface{}, len(path)+1)
	copy(next, path)
	next[len(path)] = step
	return next
}

// setJSONPath walks root following the recorded steps and sets the final
// location to value. Maps and slices are reference types, so mutating them
// in place mutates the document. Returns true if the assignment succeeded.
func setJSONPath(root interface{}, path []interface{}, value string) bool {
	cur := root
	for i, step := range path {
		last := i == len(path)-1
		switch s := step.(type) {
		case string:
			m, ok := cur.(map[string]interface{})
			if !ok {
				return false
			}
			if last {
				m[s] = value
				return true
			}
			cur = m[s]
		case int:
			arr, ok := cur.([]interface{})
			if !ok || s < 0 || s >= len(arr) {
				return false
			}
			if last {
				arr[s] = value
				return true
			}
			cur = arr[s]
		}
	}
	return false
}
