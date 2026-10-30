package netproxy

import (
	"context"
	"net"
	"testing"
	"time"
)

// mockReplayServer: на обычный кадр отвечает "OK", но если первый байт кадра
// равен 0x00 (например, опкод обнулён мутацией) — закрывает соединение без
// ответа, имитируя падение/отказ валидации.
func mockReplayServer(t *testing.T) (addr string, stop func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				select {
				case <-done:
					return
				default:
					return
				}
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 4096)
				_ = c.SetReadDeadline(time.Now().Add(time.Second))
				n, err := c.Read(buf)
				if err != nil || n == 0 {
					return
				}
				if buf[0] == 0x00 {
					return // «падение»: закрываем без ответа
				}
				_, _ = c.Write([]byte("OK"))
			}(conn)
		}
	}()
	return ln.Addr().String(), func() { close(done); ln.Close() }
}

func TestReplayer_ClassifiesResetVsSame(t *testing.T) {
	addr, stop := mockReplayServer(t)
	defer stop()

	r := &Replayer{Target: addr, Timeout: 500 * time.Millisecond}
	baseline := []byte{0x27, 0x74, 0x01} // ненулевой опкод → сервер ответит OK
	cases := []ReplayCase{
		{Name: "benign", Frame: []byte{0x27, 0x74, 0x09}},        // тоже ответит OK → same
		{Name: "zeroed-opcode", Frame: []byte{0x00, 0x00, 0x09}}, // сервер закроет → reset
	}

	res, err := r.Run(context.Background(), baseline, cases)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(res) != 2 {
		t.Fatalf("ожидалось 2 результата, получено %d", len(res))
	}

	byName := map[string]ReplayResult{}
	for _, x := range res {
		byName[x.Name] = x
	}
	if byName["benign"].Outcome != OutcomeSame {
		t.Errorf("benign: ожидался same, получено %s", byName["benign"].Outcome)
	}
	if byName["benign"].Interesting {
		t.Errorf("benign не должен быть interesting")
	}
	if byName["zeroed-opcode"].Outcome != OutcomeReset {
		t.Errorf("zeroed-opcode: ожидался reset, получено %s", byName["zeroed-opcode"].Outcome)
	}
	if !byName["zeroed-opcode"].Interesting {
		t.Errorf("zeroed-opcode должен быть помечен interesting")
	}
}

func TestReplayer_BlocksDisallowedTarget(t *testing.T) {
	r := &Replayer{Target: "93.184.216.34:80"} // публичный IP, не loopback/private
	_, err := r.Run(context.Background(), nil, nil)
	if err == nil {
		t.Fatal("ожидалась ошибка политики для публичной цели")
	}
}

func TestReplayer_DivergentResponse(t *testing.T) {
	// Сервер всегда отвечает echo первого байта → ответы различаются по кадрам.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 64)
				_ = c.SetReadDeadline(time.Now().Add(time.Second))
				n, _ := c.Read(buf)
				if n > 0 {
					_, _ = c.Write([]byte{buf[0]}) // echo первого байта
				}
			}(conn)
		}
	}()

	r := &Replayer{Target: ln.Addr().String(), Timeout: 500 * time.Millisecond}
	baseline := []byte{0x41, 0x00}
	cases := []ReplayCase{{Name: "diff", Frame: []byte{0x42, 0x00}}}
	res, err := r.Run(context.Background(), baseline, cases)
	if err != nil {
		t.Fatal(err)
	}
	if res[0].Outcome != OutcomeDivergent || !res[0].Interesting {
		t.Errorf("ожидалось divergent+interesting, получено %s interesting=%v", res[0].Outcome, res[0].Interesting)
	}
}
