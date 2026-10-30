package sbom

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"path/filepath"
	"strconv"
)

// ExportCycloneDX формирует CycloneDX 1.5 (JSON) из отчёта SBOM.
//
// serialNumber детерминирован: строится из целевого пути и списка компонентов,
// поэтому повторный экспорт того же состава даёт тот же документ, а различия
// между релизами видны обычным diff.
func ExportCycloneDX(r *Report) ([]byte, error) {
	type component struct {
		Type    string `json:"type"`
		BOMRef  string `json:"bom-ref"`
		Group   string `json:"group,omitempty"`
		Name    string `json:"name"`
		Version string `json:"version,omitempty"`
		PURL    string `json:"purl,omitempty"`
	}
	type tool struct {
		Vendor string `json:"vendor"`
		Name   string `json:"name"`
	}
	type document struct {
		BOMFormat    string `json:"bomFormat"`
		SpecVersion  string `json:"specVersion"`
		SerialNumber string `json:"serialNumber"`
		Version      int    `json:"version"`
		Metadata     struct {
			Timestamp string `json:"timestamp"`
			Tools     []tool `json:"tools"`
			Component struct {
				Type string `json:"type"`
				Name string `json:"name"`
			} `json:"component"`
		} `json:"metadata"`
		Components []component `json:"components"`
	}

	doc := document{BOMFormat: "CycloneDX", SpecVersion: "1.5", Version: 1}
	doc.Metadata.Timestamp = r.GeneratedAt
	doc.Metadata.Tools = []tool{{Vendor: "mega-analyzer", Name: "mega-analyzer"}}
	doc.Metadata.Component.Type = "application"
	doc.Metadata.Component.Name = filepath.Base(r.Target)

	h := sha256.New()
	h.Write([]byte(r.Target))
	doc.Components = make([]component, 0, len(r.Deps))
	seen := make(map[string]int)
	for _, d := range r.Deps {
		ref := d.PURL
		if ref == "" {
			ref = d.Raw
		}
		// bom-ref обязан быть уникальным в документе.
		if n := seen[ref]; n > 0 {
			seen[ref] = n + 1
			ref = ref + "#" + strconv.Itoa(n)
		} else {
			seen[ref] = 1
		}
		h.Write([]byte{0})
		h.Write([]byte(ref))
		doc.Components = append(doc.Components, component{
			Type: "library", BOMRef: ref, Group: d.Group, Name: d.Name, Version: d.Version, PURL: d.PURL,
		})
	}
	sum := hex.EncodeToString(h.Sum(nil))
	doc.SerialNumber = "urn:uuid:" + sum[0:8] + "-" + sum[8:12] + "-" + sum[12:16] + "-" + sum[16:20] + "-" + sum[20:32]

	return json.MarshalIndent(doc, "", "  ")
}
