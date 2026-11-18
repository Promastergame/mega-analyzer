package main

import (
	"fmt"
	"decisionai/semai"
	"os"
	"runtime"
)

func main() {
	runtime.GC()
	var a, b runtime.MemStats
	runtime.ReadMemStats(&a)
	e, err := semai.LoadEncoder("models/encoder-tiny.dte")
	if err != nil {
		panic(err)
	}
	x, err := semai.LoadCrossEncoderAny("models/s1-distilled.dte", e)
	if err != nil {
		panic(err)
	}
	y, err := semai.LoadCrossEncoderAny("models/s1-distilled-b.dte", e, x)
	if err != nil {
		panic(err)
	}
	runtime.GC()
	runtime.ReadMemStats(&b)
	fmt.Printf("HeapDeltaBytes=%d HeapAllocBytes=%d\n", b.HeapAlloc-a.HeapAlloc, b.HeapAlloc)
	fmt.Println("Native", e.Native())
	runtime.KeepAlive(e)
	runtime.KeepAlive(x)
	runtime.KeepAlive(y)
	if len(os.Args) > 1 {
		fmt.Println(y.Encode("Проверка модели.").Mean[:3])
	}
}
