package analyzer

import "regexp"

var proWord = regexp.MustCompile(`(?:^|[^a-z0-9])pro(?:$|[^a-z0-9])`)

func isProPredicate(name string) bool {
	switch name {
	case "ispro", "isprouser", "isproversion", "isproactive", "haspro", "hasproaccess", "checkpro", "getpro", "setpro", "unlockpro", "activatepro":
		return true
	}
	return false
}
