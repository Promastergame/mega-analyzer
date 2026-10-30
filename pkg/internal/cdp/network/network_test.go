package network

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"mega-analyzer/pkg/internal/cdp/cdpconn"
	"mega-analyzer/pkg/internal/testutil"
	"mega-analyzer/pkg/internal/wsx"
)

func TestEnableAndTypedNetworkEvent(t *testing.T) {
	if err := Enable().Do(context.Background()); err == nil {
		t.Fatal("missing connection accepted")
	}
	ws, server := testutil.WebSocketPair(t)
	conn := cdpconn.NewConn(ws)
	t.Cleanup(func() { conn.Close() })
	events := make(chan interface{}, 1)
	conn.SetDispatch(func(e interface{}) { events <- e })
	done := make(chan error, 1)
	go func() {
		p, _, err := wsx.ReadClientData(server)
		if err != nil {
			done <- err
			return
		}
		var req struct {
			ID     int
			Method string
			Params map[string]interface{}
		}
		if err := json.Unmarshal(p, &req); err != nil {
			done <- err
			return
		}
		if req.Method != "Network.enable" || len(req.Params) != 0 {
			done <- fmt.Errorf("request=%s", p)
			return
		}
		if err := wsx.WriteServerText(server, []byte(fmt.Sprintf(`{"id":%d,"result":{}}`, req.ID))); err != nil {
			done <- err
			return
		}
		done <- wsx.WriteServerText(server, []byte(`{"method":"Network.requestWillBeSent","params":{"requestId":"r1","type":"Fetch","request":{"url":"https://example.test/api","method":"POST","hasPostData":true,"postData":"x=1","postDataEntries":[{"bytes":"eD0x"}]}}}`))
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := Enable().Do(cdpconn.WithConn(ctx, conn)); err != nil {
		t.Fatal(err)
	}
	select {
	case raw := <-events:
		ev, ok := raw.(*EventRequestWillBeSent)
		if !ok || ev.Request == nil {
			t.Fatalf("event=%#v", raw)
		}
		r := ev.Request
		if ev.RequestID != "r1" || ev.Type != ResourceTypeFetch || r.URL != "https://example.test/api" || r.Method != "POST" || !r.HasPostData || r.PostData != "x=1" || len(r.PostDataEntries) != 1 || r.PostDataEntries[0].Bytes != "eD0x" {
			t.Fatalf("event=%+v request=%+v", ev, r)
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}
