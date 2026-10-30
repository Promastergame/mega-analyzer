package finding

import (
	"regexp"
	"sort"
	"strings"
)

type Taxonomy struct {
	CWE   []string
	MASVS []string
}

var taxonomyRegistry = map[string]Taxonomy{
	"sql_injection":                     {[]string{"CWE-89"}, []string{"MASVS-CODE-4"}},
	"command_injection":                 {[]string{"CWE-78"}, []string{"MASVS-CODE-4"}},
	"webview_injection":                 {[]string{"CWE-79"}, []string{"MASVS-PLATFORM-2"}},
	"javascript_injection":              {[]string{"CWE-79"}, []string{"MASVS-PLATFORM-2"}},
	"webview_js_bridge":                 {[]string{"CWE-749"}, []string{"MASVS-PLATFORM-2"}},
	"webview_remote_js":                 {[]string{"CWE-749"}, []string{"MASVS-PLATFORM-2"}},
	"path_traversal":                    {[]string{"CWE-22"}, []string{"MASVS-STORAGE-2"}},
	"dynamic_class_loading":             {[]string{"CWE-470"}, []string{"MASVS-CODE-4"}},
	"reflection_invocation":             {[]string{"CWE-470"}, []string{"MASVS-CODE-4"}},
	"log_data_exposure":                 {[]string{"CWE-532"}, []string{"MASVS-STORAGE-2"}},
	"sensitive_data_exposure":           {[]string{"CWE-200"}, []string{"MASVS-NETWORK-1"}},
	"ipc_data_exposure":                 {[]string{"CWE-927"}, []string{"MASVS-PLATFORM-1"}},
	"cleartext":                         {[]string{"CWE-319"}, []string{"MASVS-NETWORK-1"}},
	"weak_crypto":                       {[]string{"CWE-327"}, []string{"MASVS-CRYPTO-1"}},
	"hardcoded_secret":                  {[]string{"CWE-798"}, []string{"MASVS-AUTH-1"}},
	"provider_exported_no_permission":   {[]string{"CWE-926"}, []string{"MASVS-PLATFORM-1"}},
	"provider_missing_write_permission": {[]string{"CWE-926"}, []string{"MASVS-PLATFORM-1"}},
	"provider_coarse_permission":        {[]string{"CWE-732"}, []string{"MASVS-PLATFORM-1"}},
	"receiver_exported_no_permission":   {[]string{"CWE-925"}, []string{"MASVS-PLATFORM-1"}},
	"service_exported_no_permission":    {[]string{"CWE-925"}, []string{"MASVS-PLATFORM-1"}},
	"debuggable":                        {[]string{"CWE-489"}, []string{"MASVS-RESILIENCE-2"}},
	"allow_backup":                      {[]string{"CWE-530"}, []string{"MASVS-STORAGE-1"}},
}

func TaxonomyForRule(ruleID string) Taxonomy {
	key := strings.ToLower(strings.TrimSpace(ruleID))
	key = strings.TrimPrefix(key, "dataflow.")
	key = strings.TrimPrefix(key, "manifestaudit.")
	key = strings.TrimPrefix(key, "artifact.")
	if value, ok := taxonomyRegistry[key]; ok {
		return cloneTaxonomy(value)
	}
	for candidate, value := range taxonomyRegistry {
		if strings.Contains(key, candidate) {
			return cloneTaxonomy(value)
		}
	}
	return Taxonomy{}
}

var referenceToken = regexp.MustCompile(`(?i)\b(CWE-\d+|MASVS-[A-Z]+(?:-\d+)?)\b`)

func ParseReference(ref string) Taxonomy {
	var out Taxonomy
	for _, match := range referenceToken.FindAllString(ref, -1) {
		token := strings.ToUpper(match)
		if strings.HasPrefix(token, "CWE-") {
			out.CWE = appendUnique(out.CWE, token)
		} else {
			out.MASVS = appendUnique(out.MASVS, token)
		}
	}
	sort.Strings(out.CWE)
	sort.Strings(out.MASVS)
	return out
}

func MergeTaxonomy(values ...Taxonomy) Taxonomy {
	var out Taxonomy
	for _, value := range values {
		for _, item := range value.CWE {
			out.CWE = appendUnique(out.CWE, item)
		}
		for _, item := range value.MASVS {
			out.MASVS = appendUnique(out.MASVS, item)
		}
	}
	sort.Strings(out.CWE)
	sort.Strings(out.MASVS)
	return out
}

func cloneTaxonomy(value Taxonomy) Taxonomy {
	return Taxonomy{CWE: append([]string(nil), value.CWE...), MASVS: append([]string(nil), value.MASVS...)}
}

func appendUnique(values []string, value string) []string {
	for _, current := range values {
		if current == value {
			return values
		}
	}
	return append(values, value)
}
