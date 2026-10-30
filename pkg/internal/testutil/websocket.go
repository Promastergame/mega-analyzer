package testutil

import (
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"mega-analyzer/pkg/internal/wsx"
)

// WebSocketPair establishes an actual loopback RFC6455 connection for protocol
// tests. Both ends are closed before the server is stopped, including on Fatal.
func WebSocketPair(t testing.TB) (*wsx.ClientConn, net.Conn) {
	t.Helper()
	accepted := make(chan net.Conn, 1)
	failed := make(chan error, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, _, _, err := wsx.UpgradeHTTP(r, w)
		if err != nil {
			failed <- err
			return
		}
		c.SetDeadline(time.Now().Add(10 * time.Second))
		accepted <- c
	}))
	t.Cleanup(srv.Close)
	client, err := wsx.Dial("ws" + strings.TrimPrefix(srv.URL, "http") + "/test")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { client.Close() })
	select {
	case server := <-accepted:
		t.Cleanup(func() { server.Close() })
		return client, server
	case err := <-failed:
		t.Fatal(err)
	case <-time.After(5 * time.Second):
		t.Fatal("websocket server did not accept connection")
	}
	return nil, nil
}
