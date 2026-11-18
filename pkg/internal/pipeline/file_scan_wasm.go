//go:build js && wasm

package pipeline

import (
	"context"
	"encoding/json"
	"errors"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall/js"
	"time"

	"mega-analyzer/pkg/internal/config"
)

type browserFileReply struct {
	result FileScanResult
	err    error
}

var browserFileSequence atomic.Uint64
var browserFilePending sync.Map
var browserFileCallback js.Func
var browserFileCallbackOnce sync.Once

type browserFileExecutor struct{ configuration string }

func newFileScanExecutor(cfg *config.Config) fileScanExecutor {
	if js.Global().Get("megaFileScan").Type() != js.TypeFunction {
		return nil
	}
	encoded, err := json.Marshal(cfg)
	if err != nil {
		return nil
	}
	browserFileCallbackOnce.Do(func() {
		browserFileCallback = js.FuncOf(func(_ js.Value, args []js.Value) any {
			if len(args) != 3 {
				return false
			}
			pending, ok := browserFilePending.LoadAndDelete(args[0].String())
			if !ok {
				return false
			}
			var reply browserFileReply
			if message := args[2].String(); message != "" {
				reply.err = errors.New(message)
			} else {
				reply.err = json.Unmarshal([]byte(args[1].String()), &reply.result)
			}
			pending.(chan browserFileReply) <- reply
			return true
		})
		js.Global().Set("megaFileScanDone", browserFileCallback)
	})
	return &browserFileExecutor{configuration: string(encoded)}
}

func (e *browserFileExecutor) Start(ctx context.Context, task FileScanTask, content []byte) fileScanFuture {
	if ctx.Err() != nil || !js.Global().Call("megaFileScanAvailable").Bool() {
		return nil
	}
	metadata, err := json.Marshal(task)
	if err != nil {
		return nil
	}
	id := strconv.FormatUint(browserFileSequence.Add(1), 10)
	replies := make(chan browserFileReply, 1)
	bytes := js.Global().Get("Uint8Array").New(len(content))
	js.CopyBytesToJS(bytes, content)
	browserFilePending.Store(id, replies)
	if !js.Global().Call("megaFileScan", id, e.configuration, string(metadata), bytes).Bool() {
		browserFilePending.Delete(id)
		return nil
	}
	return func(ctx context.Context) (FileScanResult, error) {
		defer browserFilePending.Delete(id)
		select {
		case reply := <-replies:
			return reply.result, reply.err
		case <-ctx.Done():
			return FileScanResult{}, ctx.Err()
		}
	}
}

// Let pending MessagePort replies enter Go between bounded file tasks. A plain
// Gosched only switches Go goroutines and would starve the browser event loop.
func (*browserFileExecutor) Yield() { time.Sleep(time.Millisecond) }
