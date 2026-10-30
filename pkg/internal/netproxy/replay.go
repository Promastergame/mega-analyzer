package netproxy

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"net"
	"time"
)

// Replayer отправляет последовательность кадров на цель и классифицирует
// реакцию сервера относительно базового (немутированного) ответа. Это активная
// сторона фаззера: пассивный перехват даёт корпус мутаций, а Replayer выясняет,
// какие из них вызывают аномальное поведение (reset, таймаут, расхождение).
//
// Цель ОБЯЗАНА проходить ту же offline/allowlist-политику, что и сам прокси
// (upstreamAllowed): loopback, приватная сеть или явный allowlist. Это не
// «SaaS-защита», а предохранитель от случайной отправки трафика на чужой сервер.
type Replayer struct {
	// Target — адрес «host:port» приватного/локального сервера.
	Target string
	// Timeout — сколько ждать ответ на один кадр (по умолчанию 2s).
	Timeout time.Duration
	// ReadLimit — максимум байт ответа для чтения (по умолчанию 8 KiB).
	ReadLimit int
	// DialTimeout — таймаут установки соединения (по умолчанию 3s).
	DialTimeout time.Duration
}

// ReplayOutcome — классификация реакции сервера на один кадр.
type ReplayOutcome string

const (
	// OutcomeSame — ответ байт-в-байт совпал с базовым.
	OutcomeSame ReplayOutcome = "same"
	// OutcomeDivergent — ответ получен, но отличается от базового.
	OutcomeDivergent ReplayOutcome = "divergent"
	// OutcomeNoResponse — соединение живо, но ответа за Timeout не пришло.
	OutcomeNoResponse ReplayOutcome = "no-response"
	// OutcomeReset — сервер закрыл/сбросил соединение до ответа.
	OutcomeReset ReplayOutcome = "reset"
	// OutcomeError — ошибка на стороне клиента (dial/запись).
	OutcomeError ReplayOutcome = "error"
)

// ReplayCase — один кадр для проигрывания.
type ReplayCase struct {
	Name  string
	Frame []byte
}

// ReplayResult — итог проигрывания одного кадра.
type ReplayResult struct {
	Name    string        `json:"name"`
	Outcome ReplayOutcome `json:"outcome"`
	RespLen int           `json:"resp_len"`
	RespHex string        `json:"resp_hex,omitempty"`
	Note    string        `json:"note,omitempty"`
	// Interesting — true, если реакция отличается от базовой (стоит внимания).
	Interesting bool `json:"interesting"`
}

func (r *Replayer) timeout() time.Duration {
	if r.Timeout <= 0 {
		return 2 * time.Second
	}
	return r.Timeout
}

func (r *Replayer) readLimit() int {
	if r.ReadLimit <= 0 {
		return 8 << 10
	}
	return r.ReadLimit
}

func (r *Replayer) dialTimeout() time.Duration {
	if r.DialTimeout <= 0 {
		return 3 * time.Second
	}
	return r.DialTimeout
}

// Run проигрывает baseline и затем каждый case на свежем соединении, возвращая
// классификацию. baseline — исходный немутированный кадр; его ответ служит
// эталоном. Возвращает ошибку только при невалидной/запрещённой цели.
func (r *Replayer) Run(ctx context.Context, baseline []byte, cases []ReplayCase) ([]ReplayResult, error) {
	if !upstreamAllowed(r.Target) {
		return nil, fmt.Errorf("netproxy/replay: target %q blocked by offline/allowlist policy (loopback, private or allowlisted only)", r.Target)
	}

	baseResp, baseOutcome := r.sendOne(ctx, baseline)
	results := make([]ReplayResult, 0, len(cases))

	for _, c := range cases {
		if err := ctx.Err(); err != nil {
			break
		}
		resp, outcome := r.sendOne(ctx, c.Frame)
		res := ReplayResult{Name: c.Name, Outcome: outcome, RespLen: len(resp)}

		switch outcome {
		case OutcomeReset, OutcomeNoResponse, OutcomeError:
			// Аномалия интересна, только если база вела себя иначе.
			res.Interesting = outcome != baseOutcome
			res.Note = fmt.Sprintf("baseline=%s", baseOutcome)
		default: // получили ответ — сравниваем с эталоном
			if baseOutcome != OutcomeSame && baseOutcome != OutcomeDivergent {
				// База вообще не отвечала, а тут ответ — это расхождение.
				res.Outcome = OutcomeDivergent
				res.Interesting = true
				res.Note = fmt.Sprintf("baseline=%s, mutation got %d-byte response", baseOutcome, len(resp))
			} else if bytes.Equal(resp, baseResp) {
				res.Outcome = OutcomeSame
			} else {
				res.Outcome = OutcomeDivergent
				res.Interesting = true
			}
		}
		if res.Interesting && len(resp) > 0 {
			res.RespHex = hex.EncodeToString(resp[:minInt(len(resp), 64)])
		}
		results = append(results, res)
	}
	return results, nil
}

// sendOne открывает соединение, шлёт один кадр, читает ответ и классифицирует.
func (r *Replayer) sendOne(ctx context.Context, frame []byte) ([]byte, ReplayOutcome) {
	d := net.Dialer{Timeout: r.dialTimeout()}
	conn, err := d.DialContext(ctx, "tcp", r.Target)
	if err != nil {
		return nil, OutcomeError
	}
	defer conn.Close()

	_ = conn.SetWriteDeadline(time.Now().Add(r.dialTimeout()))
	if _, err := conn.Write(frame); err != nil {
		return nil, OutcomeError
	}

	_ = conn.SetReadDeadline(time.Now().Add(r.timeout()))
	buf := make([]byte, r.readLimit())
	n, rerr := conn.Read(buf)
	if n > 0 {
		// успели прочитать хотя бы часть ответа
		if rerr == nil {
			// возможно есть ещё — добираем без блокировки надолго
			_ = conn.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
			for n < len(buf) {
				m, e := conn.Read(buf[n:])
				n += m
				if e != nil || m == 0 {
					break
				}
			}
		}
		return append([]byte(nil), buf[:n]...), OutcomeSame
	}
	// 0 байт прочитано — различаем reset и таймаут
	if ne, ok := rerr.(net.Error); ok && ne.Timeout() {
		return nil, OutcomeNoResponse
	}
	return nil, OutcomeReset // EOF/RST до ответа
}

// minInt — локальный помощник (в пакете нет дублирующего).
func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
