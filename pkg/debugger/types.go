package debugger

// StartRequest is sent to POST /api/v1/debug/start.
type StartRequest struct {
	FilePath string  `json:"file_path"`
	Entry    *uint64 `json:"entry,omitempty"`
	Flavor   string  `json:"flavor,omitempty"`
}

// StartResponse is returned by the start endpoint.
type StartResponse struct {
	Ok         bool   `json:"ok"`
	SessionID  uint64 `json:"session_id"`
	EntryPoint uint64 `json:"entry_point"`
	Arch       string `json:"arch"`
}

// StepResponse is returned by step/continue.
type StepResponse struct {
	RIP         uint64  `json:"rip"`
	Instruction *string `json:"instruction"`
	StopReason  string  `json:"stop_reason"`
	StopAddress *uint64 `json:"stop_address"`
}

// RegistersResponse is returned by GET /registers.
type RegistersResponse struct {
	RAX   uint64 `json:"rax"`
	RBX   uint64 `json:"rbx"`
	RCX   uint64 `json:"rcx"`
	RDX   uint64 `json:"rdx"`
	RSI   uint64 `json:"rsi"`
	RDI   uint64 `json:"rdi"`
	RBP   uint64 `json:"rbp"`
	RSP   uint64 `json:"rsp"`
	R8    uint64 `json:"r8"`
	R9    uint64 `json:"r9"`
	R10   uint64 `json:"r10"`
	R11   uint64 `json:"r11"`
	R12   uint64 `json:"r12"`
	R13   uint64 `json:"r13"`
	R14   uint64 `json:"r14"`
	R15   uint64 `json:"r15"`
	RIP   uint64 `json:"rip"`
	Flags struct {
		ZF bool `json:"zf"`
		SF bool `json:"sf"`
		CF bool `json:"cf"`
		OF bool `json:"of"`
	} `json:"flags"`
}

// DisassemblyLine is one line of disassembly.
type DisassemblyLine struct {
	Address string `json:"address"`
	Raw     string `json:"raw"`
	Text    string `json:"text"`
	IsPC    bool   `json:"is_pc"`
}

// DisassembleResponse holds multiple lines.
type DisassembleResponse struct {
	Lines []DisassemblyLine `json:"lines"`
}

// MemoryResponse is returned by GET /memory.
type MemoryResponse struct {
	Ok      bool   `json:"ok"`
	Address uint64 `json:"address"`
	Hex     string `json:"hex"`
	Size    int    `json:"size"`
}

// BreakpointResponse is returned by breakpoint ops.
type BreakpointResponse struct {
	Ok      bool   `json:"ok"`
	ID      uint32 `json:"id"`
	Address uint64 `json:"address"`
	Error   string `json:"error,omitempty"`
}

// GenericOK is used for simple ok/error payloads.
type GenericOK struct {
	Ok    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
}
