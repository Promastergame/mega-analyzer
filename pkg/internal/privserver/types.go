// Package privserver builds an authorized-lab private server skeleton
// from an APK / captured session. It only generates a mock backend for
// the user's own / authorized targets: no live game traffic, no
// circumvention of third-party servers.
//
// Pipeline:
//
//	APK / target  ->  discovery  ->  plan  ->  Elixir / OTP skeleton
//	                                      ->  Markdown readiness report
package privserver

import "time"

// Plan is the structured result of analysing an APK / target and is the
// only input to the Elixir generator. Keep it serialisable so it can also
// be round-tripped via JSON.
type Plan struct {
	GeneratedAt time.Time `json:"generated_at"`
	Target      string    `json:"target"`
	GameName    string    `json:"game_name"`
	AppPackage  string    `json:"app_package,omitempty"`
	Module      string    `json:"module"`

	Transport TransportProfile `json:"transport"`
	Framing   FramingProfile   `json:"framing"`
	Family    string           `json:"family"`

	Endpoints []DiscoveredEndpoint `json:"endpoints,omitempty"`
	Domains   []string             `json:"domains,omitempty"`
	IPs       []string             `json:"ips,omitempty"`
	Pinning   PinningProfile       `json:"pinning"`

	Messages []MessageStub `json:"messages,omitempty"`
	Replays  []ReplayEntry `json:"replays,omitempty"`

	Readiness Readiness `json:"readiness"`

	Listen ListenProfile `json:"listen"`

	Notes []string `json:"notes,omitempty"`
}

// TransportProfile describes the recommended transport for the mock
// server. It's the best guess from APK strings/resources, never traffic
// to live servers.
type TransportProfile struct {
	Protocol      string  `json:"protocol"`
	Confidence    float64 `json:"confidence"`
	Reason        string  `json:"reason,omitempty"`
	UsesTLS       bool    `json:"uses_tls"`
	UsesWebSocket bool    `json:"uses_websocket"`
}

// FramingProfile is the recommended packet framing layout.
type FramingProfile struct {
	Style        string `json:"style"`
	HeaderSize   int    `json:"header_size"`
	IDOffset     int    `json:"id_offset"`
	IDSize       int    `json:"id_size"`
	LengthOffset int    `json:"length_offset"`
	LengthSize   int    `json:"length_size"`
	Endian       string `json:"endian"`
	Reason       string `json:"reason,omitempty"`
}

// DiscoveredEndpoint is a candidate backend address found inside the
// target. It mirrors patcher.ServerAddress but is decoupled from cgo.
type DiscoveredEndpoint struct {
	Address    string  `json:"address"`
	Port       uint16  `json:"port,omitempty"`
	FilePath   string  `json:"file_path"`
	FileType   string  `json:"file_type"`
	Confidence float64 `json:"confidence"`
	Kind       string  `json:"kind"`
}

// PinningProfile flags SSL pinning hints found inside the target. We
// only describe what is observed — we do not generate bypass code from
// here, that is the patcher's responsibility under --mode research.
type PinningProfile struct {
	Detected bool     `json:"detected"`
	Hints    []string `json:"hints,omitempty"`
	Reason   string   `json:"reason,omitempty"`
}

// MessageStub is a per-message handler the Elixir skeleton will scaffold.
// Direction is one of: client_to_server, server_to_client, bidirectional.
type MessageStub struct {
	ID        uint16 `json:"id"`
	Name      string `json:"name"`
	Direction string `json:"direction"`
	Replay    bool   `json:"replay"`
	Stateful  bool   `json:"stateful"`
	NextState string `json:"next_state,omitempty"`
}

// ReplayEntry is a canned response that can be replayed back to the
// client by the replay store. Payload is hex-encoded so the file is
// readable and round-trippable.
type ReplayEntry struct {
	MessageID  uint16 `json:"message_id"`
	Direction  string `json:"direction"`
	PayloadHex string `json:"payload_hex"`
	Note       string `json:"note,omitempty"`
}

// ListenProfile is the host:port pair the generated server will listen on.
type ListenProfile struct {
	Host      string `json:"host"`
	Port      int    `json:"port"`
	AdminPort int    `json:"admin_port"`
}

// Readiness gives a human-readable score for how complete the generated
// server is. The lower it is, the more handlers the user will have to
// fill in manually.
type Readiness struct {
	Score         int      `json:"score"`
	Risk          string   `json:"risk"`
	KnownMessages int      `json:"known_messages"`
	ReplayBacked  int      `json:"replay_backed"`
	StatefulCount int      `json:"stateful_count"`
	CriticalGaps  []string `json:"critical_gaps,omitempty"`
	Notes         []string `json:"notes,omitempty"`
}
