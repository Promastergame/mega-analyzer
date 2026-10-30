// Command knownset-build собирает и опрашивает набор «известно хорошее /
// известно плохое» (см. pkg/knownset).
//
// Вход — NDJSON, по записи на строку; допустим любой из ключей или оба:
//
//	{"sha256":"<64 hex>","purl":"pkg:maven/g/a@1","label":"good"}
//	{"sha256":"<64 hex>","label":"bad"}
//
// Собрать набор:
//
//	knownset-build -in pool.ndjson -out known.mks -fpr 1e-9
//
// Спросить:
//
//	knownset-build -check known.mks -sha256 <hex>
//	knownset-build -check known.mks -purl pkg:maven/g/a@1
package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"mega-analyzer/pkg/knownset"
)

type record struct {
	SHA256 string `json:"sha256"`
	PURL   string `json:"purl"`
	Label  string `json:"label"`
}

func main() { os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr)) }

func run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("knownset-build", flag.ContinueOnError)
	fs.SetOutput(stderr)
	in := fs.String("in", "", "NDJSON pool ('-' = stdin)")
	out := fs.String("out", "", "bundle file to write")
	fpr := fs.Float64("fpr", 1e-9, "target false-positive rate of the known-good filter")
	check := fs.String("check", "", "existing bundle to query")
	sha := fs.String("sha256", "", "sha256 to look up (with -check)")
	pu := fs.String("purl", "", "purl to look up (with -check)")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	if *check != "" {
		return query(*check, *sha, *pu, stdout, stderr)
	}
	if *in == "" || *out == "" {
		fmt.Fprintln(stderr, "usage: knownset-build -in pool.ndjson -out known.mks  |  knownset-build -check known.mks -sha256 H | -purl P")
		return 2
	}

	var r io.Reader = stdin
	if *in != "-" {
		f, err := os.Open(*in)
		if err != nil {
			fmt.Fprintln(stderr, "error:", err)
			return 3
		}
		defer f.Close()
		r = f
	}

	b, err := knownset.NewBuilder(*fpr)
	if err != nil {
		fmt.Fprintln(stderr, "error:", err)
		return 2
	}

	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	var lines, malformed, unusable int
	for sc.Scan() {
		text := strings.TrimSpace(sc.Text())
		if text == "" {
			continue
		}
		lines++
		var rec record
		if err := json.Unmarshal([]byte(text), &rec); err != nil {
			malformed++
			continue
		}
		add := b.AddGood
		switch strings.ToLower(rec.Label) {
		case "good", "benign", "clean":
		case "bad", "malicious", "hostile":
			add = b.AddBad
		default:
			malformed++
			continue
		}
		keys := 0
		if rec.SHA256 != "" {
			if k, ok := knownset.KeySHA256(rec.SHA256); ok && add(k) {
				keys++
			}
		}
		if rec.PURL != "" {
			// PURL, который не разбирается, ключа не даёт: искать по нему потом
			// значило бы получить только ложное срабатывание.
			if k, ok := knownset.KeyPURL(rec.PURL); ok && add(k) {
				keys++
			}
		}
		if keys == 0 {
			unusable++
		}
	}
	if err := sc.Err(); err != nil {
		fmt.Fprintln(stderr, "error:", err)
		return 3
	}
	if malformed > 0 {
		// Как и у fp-calibrate: набор, собранный из частично нечитаемого пула,
		// выглядел бы полным, но молча не знал бы части образцов.
		fmt.Fprintf(stderr, "error: %d of %d records are malformed (need label good|bad and a valid sha256/purl)\n", malformed, lines)
		return 3
	}

	res, err := b.Build()
	if err != nil {
		fmt.Fprintln(stderr, "error:", err)
		return 3
	}
	if err := res.Bundle.Save(*out); err != nil {
		fmt.Fprintln(stderr, "error:", err)
		return 3
	}
	st := res.Bundle.Stats()
	fmt.Fprintf(stdout, "wrote %s: good=%d bad=%d filter=%d bytes est.fpr=%.2e\n", *out, st.GoodKeys, st.BadKeys, st.FilterBytes, st.EstimatedFPR)
	if unusable > 0 {
		fmt.Fprintf(stderr, "warning: %d record(s) had no usable key and were skipped\n", unusable)
	}
	if res.Conflicts > 0 {
		fmt.Fprintf(stderr, "warning: %d key(s) were labelled both good and bad; kept as bad\n", res.Conflicts)
	}
	return 0
}

func query(path, sha, purl string, stdout, stderr io.Writer) int {
	b, err := knownset.Open(path)
	if err != nil {
		fmt.Fprintln(stderr, "error:", err)
		return 3
	}
	switch {
	case sha != "":
		fmt.Fprintln(stdout, b.LookupSHA256(sha))
	case purl != "":
		fmt.Fprintln(stdout, b.LookupPURL(purl))
	default:
		st := b.Stats()
		fmt.Fprintf(stdout, "good=%d bad=%d filter=%d bytes hashes=%d est.fpr=%.2e\n", st.GoodKeys, st.BadKeys, st.FilterBytes, st.Hashes, st.EstimatedFPR)
	}
	return 0
}
