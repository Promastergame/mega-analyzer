package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"hash/crc32"
	"io"
	"os"
	"sort"
	"strings"
)

const magic = "MACDB001"

type rec struct {
	Key, Dex, Emitter, Class, Smali string
	Size                            int64
}

func load(path string) ([]rec, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	m := make([]byte, len(magic))
	if _, err := io.ReadFull(f, m); err != nil {
		return nil, err
	}
	if string(m) != magic {
		return nil, fmt.Errorf("bad cache magic: not a Mega Analyzer binary cache DB")
	}
	entries := map[string]rec{}
	for {
		var typ [1]byte
		_, err := io.ReadFull(f, typ[:])
		if err == io.EOF || err == io.ErrUnexpectedEOF {
			break
		}
		if err != nil {
			return nil, err
		}
		var hdr [12]byte
		if _, err := io.ReadFull(f, hdr[:]); err != nil {
			break
		}
		kl := binary.LittleEndian.Uint32(hdr[0:4])
		vl := binary.LittleEndian.Uint64(hdr[4:12])
		key := make([]byte, kl)
		if _, err := io.ReadFull(f, key); err != nil {
			break
		}
		val := make([]byte, vl)
		if _, err := io.ReadFull(f, val); err != nil {
			break
		}
		var c [4]byte
		if _, err := io.ReadFull(f, c[:]); err != nil {
			break
		}
		if crc32.ChecksumIEEE(append(key, val...)) != binary.LittleEndian.Uint32(c[:]) {
			continue
		}
		k := string(key)
		if typ[0] == 2 {
			delete(entries, k)
			continue
		}
		parts := strings.Split(k, "\x00")
		if len(parts) != 3 {
			continue
		}
		entries[k] = rec{Key: k, Dex: parts[0], Emitter: parts[1], Class: parts[2], Smali: string(val), Size: int64(len(val))}
	}
	out := make([]rec, 0, len(entries))
	for _, r := range entries {
		out = append(out, r)
	}
	return out, nil
}

func main() {
	limit := flag.Int("limit", 50, "rows to show")
	find := flag.String("find", "", "case-insensitive class substring")
	dump := flag.String("dump", "", "dump exact class name smali")
	flag.Parse()
	if flag.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "usage: cache-viewer [-limit N] [-find name] [-dump class] .mega-analyzer-cache.db")
		os.Exit(2)
	}
	rows, err := load(flag.Arg(0))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if *dump != "" {
		for _, r := range rows {
			if r.Class == *dump {
				fmt.Print(r.Smali)
				return
			}
		}
		fmt.Fprintln(os.Stderr, "class not found")
		os.Exit(1)
	}
	needle := strings.ToLower(*find)
	filtered := rows[:0]
	var bytes int64
	for _, r := range rows {
		if needle == "" || strings.Contains(strings.ToLower(r.Class), needle) {
			filtered = append(filtered, r)
			bytes += r.Size
		}
	}
	sort.Slice(filtered, func(i, j int) bool { return filtered[i].Class < filtered[j].Class })
	if *limit <= 0 || *limit > len(filtered) {
		*limit = len(filtered)
	}
	fmt.Printf("Mega Analyzer binary cache DB\nentries: %d shown / %d matched / %d total\nsmali bytes matched: %d\n\n", *limit, len(filtered), len(rows), bytes)
	for i := 0; i < *limit; i++ {
		r := filtered[i]
		fmt.Printf("%6d  %8d  %.12s  %-14s  %s\n", i+1, r.Size, r.Dex, r.Emitter, r.Class)
	}
}
