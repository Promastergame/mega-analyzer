package debugger

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// Client talks to the OmniSec debugger REST API.
type Client struct {
	BaseURL string
	HTTP    *http.Client
}

// NewClient creates a client pointing at baseURL.
func NewClient(baseURL string) *Client {
	return &Client{
		BaseURL: baseURL,
		HTTP:    &http.Client{Timeout: 60 * time.Second},
	}
}

func (c *Client) url(path string) string {
	return c.BaseURL + path
}

func (c *Client) post(path string, body any) ([]byte, error) {
	b, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	resp, err := c.HTTP.Post(c.url(path), "application/json", bytes.NewReader(b))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	return io.ReadAll(resp.Body)
}

func (c *Client) get(path string) ([]byte, error) {
	resp, err := c.HTTP.Get(c.url(path))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	return io.ReadAll(resp.Body)
}

// Start opens a debugger session for a file.
func (c *Client) Start(req StartRequest) (*StartResponse, error) {
	raw, err := c.post("/api/v1/debug/start", req)
	if err != nil {
		return nil, err
	}
	var envelope struct {
		Ok     bool          `json:"ok"`
		Result StartResponse `json:"result"`
		Error  string        `json:"error"`
	}
	if err := json.Unmarshal(raw, &envelope); err != nil {
		return nil, err
	}
	if !envelope.Ok {
		return nil, fmt.Errorf("start failed: %s", envelope.Error)
	}
	res := envelope.Result
	res.Ok = true
	return &res, nil
}

// Stop destroys a session.
func (c *Client) Stop(sessionID uint64) error {
	_, err := c.post("/api/v1/debug/stop", map[string]uint64{"session_id": sessionID})
	return err
}

// Step executes one instruction.
func (c *Client) Step(sessionID uint64) (*StepResponse, error) {
	raw, err := c.post("/api/v1/debug/step", map[string]uint64{"session_id": sessionID})
	if err != nil {
		return nil, err
	}
	var envelope struct {
		Ok     bool         `json:"ok"`
		Result StepResponse `json:"result"`
		Error  string       `json:"error"`
	}
	if err := json.Unmarshal(raw, &envelope); err != nil {
		return nil, err
	}
	if !envelope.Ok {
		return nil, fmt.Errorf("step failed: %s", envelope.Error)
	}
	return &envelope.Result, nil
}

// Continue runs until stop.
func (c *Client) Continue(sessionID uint64) (*StepResponse, error) {
	raw, err := c.post("/api/v1/debug/continue", map[string]uint64{"session_id": sessionID})
	if err != nil {
		return nil, err
	}
	var envelope struct {
		Ok     bool         `json:"ok"`
		Result StepResponse `json:"result"`
		Error  string       `json:"error"`
	}
	if err := json.Unmarshal(raw, &envelope); err != nil {
		return nil, err
	}
	if !envelope.Ok {
		return nil, fmt.Errorf("continue failed: %s", envelope.Error)
	}
	return &envelope.Result, nil
}

// Registers reads CPU state.
func (c *Client) Registers(sessionID uint64) (*RegistersResponse, error) {
	raw, err := c.get(fmt.Sprintf("/api/v1/debug/registers?session_id=%d", sessionID))
	if err != nil {
		return nil, err
	}
	var envelope struct {
		Ok     bool              `json:"ok"`
		Result RegistersResponse `json:"result"`
		Error  string            `json:"error"`
	}
	if err := json.Unmarshal(raw, &envelope); err != nil {
		return nil, err
	}
	if !envelope.Ok {
		return nil, fmt.Errorf("registers failed: %s", envelope.Error)
	}
	return &envelope.Result, nil
}

// Disassemble returns count lines at address.
func (c *Client) Disassemble(sessionID, address uint64, count int) (*DisassembleResponse, error) {
	path := fmt.Sprintf("/api/v1/debug/disassemble?session_id=%d&address=%d&count=%d", sessionID, address, count)
	raw, err := c.get(path)
	if err != nil {
		return nil, err
	}
	var envelope struct {
		Ok     bool                `json:"ok"`
		Result DisassembleResponse `json:"result"`
		Error  string              `json:"error"`
	}
	if err := json.Unmarshal(raw, &envelope); err != nil {
		return nil, err
	}
	if !envelope.Ok {
		return nil, fmt.Errorf("disassemble failed: %s", envelope.Error)
	}
	return &envelope.Result, nil
}

// ReadMemory reads bytes at address.
func (c *Client) ReadMemory(sessionID, address, size uint64) (*MemoryResponse, error) {
	path := fmt.Sprintf("/api/v1/debug/memory?session_id=%d&address=%d&size=%d", sessionID, address, size)
	raw, err := c.get(path)
	if err != nil {
		return nil, err
	}
	var envelope struct {
		Ok     bool           `json:"ok"`
		Result MemoryResponse `json:"result"`
		Error  string         `json:"error"`
	}
	if err := json.Unmarshal(raw, &envelope); err != nil {
		return nil, err
	}
	if !envelope.Ok {
		return nil, fmt.Errorf("read_memory failed: %s", envelope.Error)
	}
	return &envelope.Result, nil
}

// SetBreakpoint adds a breakpoint.
func (c *Client) SetBreakpoint(sessionID uint64, target string) (*BreakpointResponse, error) {
	raw, err := c.post("/api/v1/debug/breakpoint", map[string]any{"session_id": sessionID, "target": target})
	if err != nil {
		return nil, err
	}
	var envelope struct {
		Ok     bool               `json:"ok"`
		Result BreakpointResponse `json:"result"`
		Error  string             `json:"error"`
	}
	if err := json.Unmarshal(raw, &envelope); err != nil {
		return nil, err
	}
	if !envelope.Ok {
		return nil, fmt.Errorf("breakpoint failed: %s", envelope.Error)
	}
	return &envelope.Result, nil
}

// RemoveBreakpoint deletes a breakpoint by id.
func (c *Client) RemoveBreakpoint(sessionID uint64, id uint32) error {
	_, err := c.post("/api/v1/debug/remove_bp", map[string]any{"session_id": sessionID, "id": id})
	return err
}

// ListBreakpoints returns all active breakpoints.
func (c *Client) ListBreakpoints(sessionID uint64) ([]BreakpointResponse, error) {
	path := fmt.Sprintf("/api/v1/debug/breakpoints?session_id=%d", sessionID)
	raw, err := c.get(path)
	if err != nil {
		return nil, err
	}
	var envelope struct {
		Ok     bool `json:"ok"`
		Result struct {
			Breakpoints []BreakpointResponse `json:"breakpoints"`
		} `json:"result"`
		Error string `json:"error"`
	}
	if err := json.Unmarshal(raw, &envelope); err != nil {
		return nil, err
	}
	if !envelope.Ok {
		return nil, fmt.Errorf("list breakpoints failed: %s", envelope.Error)
	}
	return envelope.Result.Breakpoints, nil
}

// SetFlavor changes disassembly syntax.
func (c *Client) SetFlavor(sessionID uint64, flavor string) error {
	_, err := c.post("/api/v1/debug/flavor", map[string]any{"session_id": sessionID, "flavor": flavor})
	return err
}

// PatchMemory writes raw hex bytes to an address.
func (c *Client) PatchMemory(sessionID, address uint64, hex string) error {
	_, err := c.post("/api/v1/debug/patch", map[string]any{"session_id": sessionID, "address": address, "hex": hex})
	return err
}

// SetRegister changes a single register value.
func (c *Client) SetRegister(sessionID uint64, reg string, value uint64) error {
	_, err := c.post("/api/v1/debug/register", map[string]any{"session_id": sessionID, "register": reg, "value": value})
	return err
}

// ScanMemory searches for a byte pattern (hex with ?? wildcards).
func (c *Client) ScanMemory(sessionID uint64, pattern string) ([]uint64, error) {
	path := fmt.Sprintf("/api/v1/debug/scan?session_id=%d&pattern=%s", sessionID, pattern)
	raw, err := c.get(path)
	if err != nil {
		return nil, err
	}
	var envelope struct {
		Ok     bool `json:"ok"`
		Result struct {
			Hits []struct {
				Address uint64 `json:"address"`
			} `json:"hits"`
			Count int `json:"count"`
		} `json:"result"`
		Error string `json:"error"`
	}
	if err := json.Unmarshal(raw, &envelope); err != nil {
		return nil, err
	}
	if !envelope.Ok {
		return nil, fmt.Errorf("scan failed: %s", envelope.Error)
	}
	addrs := make([]uint64, 0, envelope.Result.Count)
	for _, h := range envelope.Result.Hits {
		addrs = append(addrs, h.Address)
	}
	return addrs, nil
}

// TraceEnable toggles time-travel tracing.
func (c *Client) TraceEnable(sessionID uint64, enabled bool) error {
	_, err := c.post("/api/v1/debug/trace", map[string]any{"session_id": sessionID, "enabled": enabled})
	return err
}

// ReverseStep rewinds one instruction.
func (c *Client) ReverseStep(sessionID uint64) (*StepResponse, error) {
	raw, err := c.post("/api/v1/debug/reverse_step", map[string]uint64{"session_id": sessionID})
	if err != nil {
		return nil, err
	}
	var envelope struct {
		Ok     bool         `json:"ok"`
		Result StepResponse `json:"result"`
		Error  string       `json:"error"`
	}
	if err := json.Unmarshal(raw, &envelope); err != nil {
		return nil, err
	}
	if !envelope.Ok {
		return nil, fmt.Errorf("reverse_step failed: %s", envelope.Error)
	}
	return &envelope.Result, nil
}

// ReverseContinue rewinds until previous breakpoint.
func (c *Client) ReverseContinue(sessionID uint64) (*StepResponse, error) {
	raw, err := c.post("/api/v1/debug/reverse_continue", map[string]uint64{"session_id": sessionID})
	if err != nil {
		return nil, err
	}
	var envelope struct {
		Ok     bool         `json:"ok"`
		Result StepResponse `json:"result"`
		Error  string       `json:"error"`
	}
	if err := json.Unmarshal(raw, &envelope); err != nil {
		return nil, err
	}
	if !envelope.Ok {
		return nil, fmt.Errorf("reverse_continue failed: %s", envelope.Error)
	}
	return &envelope.Result, nil
}
