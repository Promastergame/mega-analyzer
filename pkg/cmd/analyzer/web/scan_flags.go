package web

import (
	"fmt"
	"strconv"
	"strings"
)

// Transform jobs have narrower options than analysis jobs. Keep the input and
// output managed by the server, and never let browser flags enable host tools.
func validateWebModeFlags(mode string, args []string) ([]string, error) {
	if mode != "build" && mode != "decode" {
		return validateWorkspaceScanFlags(args)
	}
	allowed := map[string]bool{"-standalone": true}
	if mode == "decode" {
		for _, key := range []string{"-java-view", "-no-resources", "-no-smali", "-copy-original"} {
			allowed[key] = true
		}
	} else {
		allowed["-no-sign"] = true
		allowed["-no-align"] = true
	}
	if len(args) > 16 {
		return nil, fmt.Errorf("too many %s options", mode)
	}
	out := make([]string, 0, len(args))
	seen := map[string]bool{}
	for i := 0; i < len(args); i++ {
		key := args[i]
		if seen[key] {
			return nil, fmt.Errorf("duplicate %s option %s", mode, key)
		}
		seen[key] = true
		if allowed[key] {
			out = append(out, key)
			continue
		}
		if key == "-timeout" && i+1 < len(args) {
			i++
			value := args[i]
			if n, err := strconv.Atoi(value); err == nil && n >= 0 && n <= 86400 {
				out = append(out, key, value)
				continue
			}
			return nil, fmt.Errorf("invalid timeout value for %s", mode)
		}
		if mode == "build" && key == "-compression-mode" && i+1 < len(args) {
			i++
			value := args[i]
			if value == "fast" || value == "balanced" || value == "best" {
				out = append(out, key, value)
				continue
			}
		}
		return nil, fmt.Errorf("unsupported web %s option %s", mode, key)
	}
	return out, nil
}

// Web inputs are not arbitrary CLI arguments. In particular -output/-o,
// -clean-output, -t and mode-switching flags must not override managed paths.
func validateWorkspaceScanFlags(args []string) ([]string, error) {
	switches := map[string]bool{
		"-apkid": true, "-artifacts": true, "-callgraph": true, "-correlations": true, "-deep-scan": true,
		"-fp-strict": true, "-gamemode": true, "-graph-explorer": true, "-jni-bridge": true, "-manifest-audit": true,
		"-medium-all": true, "-ml-patch": true, "-mobsf-all": true, "-no-image-blur": true, "-nsc-audit": true,
		"-privacy": true, "-sarif": true, "-sast-rules": true, "-top5": true, "-trackers": true,
		"-i-own-this-target": true, "-lab-mode": true,
		"-bundle-export": true, "-bundle-patches": true, "-save-decoded": true,
		"-java-view": true, "-no-resources": true, "-no-smali": true,
		"-copy-original": true, "-standalone": true,
	}
	values := map[string]bool{"-profile": true, "-report": true, "-workers": true, "-timeout": true, "-fp-min-score": true, "-bundle-budget": true}
	if len(args) > 100 {
		return nil, fmt.Errorf("too many scan options")
	}
	out := make([]string, 0, len(args))
	seen := map[string]bool{}
	for i := 0; i < len(args); i++ {
		key := args[i]
		if seen[key] {
			return nil, fmt.Errorf("duplicate scan option %s", key)
		}
		seen[key] = true
		if switches[key] {
			out = append(out, key)
			continue
		}
		if !values[key] || i+1 >= len(args) {
			return nil, fmt.Errorf("unsupported web scan option %s", key)
		}
		i++
		value := args[i]
		if len(value) > 64 || !isSafeArg(value) {
			return nil, fmt.Errorf("invalid value for %s", key)
		}
		if key == "-bundle-budget" {
			if value != "compact" && value != "large" {
				return nil, fmt.Errorf("invalid bundle budget")
			}
		} else if key == "-profile" || key == "-report" {
			// Built-in preset names only: profiles cannot read a host path.
			if strings.ContainsAny(value, "/.") || strings.HasPrefix(value, "-") {
				return nil, fmt.Errorf("invalid preset")
			}
		} else {
			n, err := strconv.ParseFloat(value, 64)
			if err != nil || n != n || n < -1 || n > 1000000 {
				return nil, fmt.Errorf("invalid numeric scan option %s", key)
			}
		}
		out = append(out, key, value)
	}
	return out, nil
}
