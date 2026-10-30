package main

import (
	"fmt"
	"os"

	"mega-analyzer/pkg/internal/apkloader/axml"
)

func main() {
	data, err := os.ReadFile(os.Args[1])
	if err != nil {
		panic(err)
	}
	out, err := axml.Render(data)
	if err != nil {
		panic(err)
	}
	fmt.Println(string(out))
}
