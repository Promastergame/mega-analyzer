package testutil

import (
	"fmt"
	"mega-analyzer/pkg/internal/wsx"
	"os"
	"strings"
	"testing"
)

func TestCaptureStdoutRestoresOnReturnAndPanic(t *testing.T) {
	old := os.Stdout
	want := strings.Repeat("hello\n", 20000)
	got := CaptureStdout(t, func() { fmt.Print(want) })
	if got != want || os.Stdout != old {
		t.Fatal("stdout lost or not restored")
	}
	func() {
		defer func() {
			if recover() != "expected" {
				t.Error("panic was swallowed")
			}
		}()
		CaptureStdout(t, func() { panic("expected") })
	}()
	if os.Stdout != old {
		t.Fatal("stdout not restored after panic")
	}
}

func TestWebSocketPair(t *testing.T) {
	c, s := WebSocketPair(t)
	done := make(chan error, 1)
	go func() {
		p, _, err := wsx.ReadClientData(s)
		if err == nil {
			err = wsx.WriteServerText(s, p)
		}
		done <- err
	}()
	if err := c.WriteText([]byte("loopback")); err != nil {
		t.Fatal(err)
	}
	op, p, err := c.ReadMessage()
	if err != nil || op != wsx.OpText || string(p) != "loopback" {
		t.Fatalf("echo=%v %q %v", op, p, err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}
