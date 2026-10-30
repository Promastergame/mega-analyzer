package netproxy

import (
	"sync"
	"time"
)

// ProtocolInferrer выполняет инферирование протокола.
type ProtocolInferrer struct {
	captures map[string]*ProtocolCapture
	mu       sync.RWMutex
}

// ProtocolCapture представляет захват для инферирования.
type ProtocolCapture struct {
	Host         string
	Port         int
	Packets      [][]byte
	Timestamps   []time.Time
	Directions   []string // "client_to_server", "server_to_client"
	InferredType string
	Confidence   float64
}

// ReplayEngine воспроизводит захваченный трафик.
type ReplayEngine struct {
	captures map[string]*ReplayCapture
	mu       sync.RWMutex
}

// ReplayCapture представляет захват для воспроизведения.
type ReplayCapture struct {
	ID         string
	Requests   [][]byte
	Responses  [][]byte
	Timestamps []time.Duration
	Mutations  []ReplayMutation
}

// ReplayMutation представляет мутацию для фаззинга.
type ReplayMutation struct {
	FieldIndex int
	Offset     int
	Length     int
	NewValue   []byte
}

// FuzzingEngine выполняет фаззинг.
type FuzzingEngine struct {
	mutationRate float64
	results      map[string]*FuzzingResult
	mu           sync.RWMutex
}

// FuzzingResult представляет результат фаззинга.
type FuzzingResult struct {
	MutatedPayload []byte
	ServerResponse []byte
	Anomaly        bool
	Description    string
}
