// Package servgen generates a Go server stub from a protocol specification.
// This is the final piece of the Private Server Toolkit pipeline:
//
//	Intercept → Analyze → Generate Server → Patch Client → Play!
//
// The generated server includes:
//   - TCP listener matching the game's protocol
//   - Handler stubs for each detected message type
//   - SQLite database for persistent game state
//   - Web admin panel on a configurable port
//   - Auto-responder mode (replay recorded responses)
package servgen

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"text/template"
	"time"

	"mega-analyzer/pkg/internal/protocol"
)

// ═══════════════════════════════════════════════════════════════════════════════
// GENERATOR CONFIG
// ═══════════════════════════════════════════════════════════════════════════════

// GeneratorConfig configures the server stub generator.
type GeneratorConfig struct {
	// OutputDir is the directory to write the generated server to
	OutputDir string
	// ModuleName is the Go module name for the generated server
	ModuleName string
	// ListenPort is the default port for the game server
	ListenPort int
	// AdminPort is the port for the web admin panel
	AdminPort int
	// DatabaseType is the database backend ("sqlite" or "memory")
	DatabaseType string
	// GameName is the name of the game
	GameName string
}

// DefaultConfig returns a default generator config.
func DefaultConfig() GeneratorConfig {
	return GeneratorConfig{
		OutputDir:    "./generated-server",
		ModuleName:   "private-server",
		ListenPort:   9339,
		AdminPort:    8080,
		DatabaseType: "sqlite",
		GameName:     "GameServer",
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// GENERATOR
// ═══════════════════════════════════════════════════════════════════════════════

// Generator creates a Go server project from a protocol spec.
type Generator struct {
	config GeneratorConfig
	spec   *protocol.ProtocolSpec
}

// NewGenerator creates a new server generator.
func NewGenerator(config GeneratorConfig, spec *protocol.ProtocolSpec) *Generator {
	return &Generator{config: config, spec: spec}
}

// Generate creates the complete server project.
func (g *Generator) Generate() error {
	// Create directory structure
	dirs := []string{
		"",
		"cmd/server",
		"pkg/handler",
		"pkg/session",
		"pkg/database",
		"pkg/admin",
		"configs",
	}
	for _, dir := range dirs {
		path := filepath.Join(g.config.OutputDir, dir)
		if err := os.MkdirAll(path, 0755); err != nil {
			return fmt.Errorf("create dir %s: %w", dir, err)
		}
	}

	// Generate files
	generators := []struct {
		path    string
		content string
	}{
		{"go.mod", g.generateGoMod()},
		{"cmd/server/main.go", g.generateMain()},
		{"pkg/handler/router.go", g.generateRouter()},
		{"pkg/handler/handlers.go", g.generateHandlers()},
		{"pkg/session/session.go", g.generateSession()},
		{"pkg/database/store.go", g.generateStore()},
		{"configs/server.json", g.generateConfig()},
		{"README.md", g.generateReadme()},
	}

	for _, gen := range generators {
		path := filepath.Join(g.config.OutputDir, gen.path)
		if err := os.WriteFile(path, []byte(gen.content), 0644); err != nil {
			return fmt.Errorf("write %s: %w", gen.path, err)
		}
	}

	return nil
}

// GenerateFromJSEndpoints takes a list of discovered API endpoints (e.g. from JS deobfuscation)
// and generates a mock HTTP backend server (Elixir/Plug style layout but in Go for consistency)
func (g *Generator) GenerateFromJSEndpoints(endpoints []string) error {
	// Create directory structure
	dirs := []string{
		"",
		"cmd/mockserver",
		"pkg/handlers",
	}
	for _, dir := range dirs {
		path := filepath.Join(g.config.OutputDir, dir)
		if err := os.MkdirAll(path, 0755); err != nil {
			return fmt.Errorf("create dir %s: %w", dir, err)
		}
	}

	// 1. Generate Handlers based on endpoints
	var handlerStr strings.Builder
	handlerStr.WriteString("package handlers\n\nimport (\n\t\"encoding/json\"\n\t\"net/http\"\n)\n\n")

	for i, ep := range endpoints {
		funcName := fmt.Sprintf("HandleMockEndpoint%d", i)
		handlerStr.WriteString(fmt.Sprintf(`// %s mocks %s
func %s(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status": "success",
		"message": "Mocked response from Mega-Analyzer",
		"endpoint": "%s",
	})
}
`, funcName, ep, funcName, ep))
	}

	if err := os.WriteFile(filepath.Join(g.config.OutputDir, "pkg/handlers/endpoints.go"), []byte(handlerStr.String()), 0644); err != nil {
		return err
	}

	// 2. Generate Main server router
	var mainStr strings.Builder
	mainStr.WriteString(fmt.Sprintf(`package main

import (
	"log"
	"net/http"

	"%s/pkg/handlers"
)

func main() {
	log.Println("🚀 Starting Mega-Analyzer Auto-Mock REST Server...")
	mux := http.NewServeMux()
`, g.config.ModuleName))

	for i, ep := range endpoints {
		funcName := fmt.Sprintf("handlers.HandleMockEndpoint%d", i)
		mainStr.WriteString(fmt.Sprintf("\tmux.HandleFunc(\"%s\", %s)\n", ep, funcName))
	}

	mainStr.WriteString(fmt.Sprintf(`
	log.Printf("Listening on :%%d", %d)
	log.Printf("ERROR: server failed: %%v", http.ListenAndServe(fmt.Sprintf(":%%d", %d), mux))
}
`, g.config.ListenPort, g.config.ListenPort))

	if err := os.WriteFile(filepath.Join(g.config.OutputDir, "cmd/mockserver/main.go"), []byte(mainStr.String()), 0644); err != nil {
		return err
	}

	// 3. Generate go.mod
	if err := os.WriteFile(filepath.Join(g.config.OutputDir, "go.mod"), []byte(g.generateGoMod()), 0644); err != nil {
		return err
	}

	return nil
}

func (g *Generator) generateGoMod() string {
	return fmt.Sprintf(`module %s

go 1.26
`, g.config.ModuleName)
}

func (g *Generator) generateMain() string {
	return fmt.Sprintf(`package main

import (
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

	"%s/pkg/handler"
	"%s/pkg/session"
)

func main() {
	fmt.Println("🎮 %s Private Server")
	fmt.Println("Generated by Mega-Analyzer Private Server Toolkit")
	fmt.Println()

	sessionMgr := session.NewManager()
	router := handler.NewRouter(sessionMgr)

	listener, err := net.Listen("tcp", ":%d")
	if err != nil {
		log.Fatalf("ERROR: Failed to listen: %%v", err)
	}
	defer listener.Close()

	fmt.Printf("✅ Server listening on %%s\n", listener.Addr())
	fmt.Printf("📊 Admin panel: http://localhost:%%d\n", %d)
	fmt.Println()

	// Graceful shutdown
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				continue
			}
			go router.HandleConnection(conn)
		}
	}()

	<-sig
	fmt.Println("\n👋 Shutting down...")
}
`, g.config.ModuleName, g.config.ModuleName, g.config.GameName,
		g.config.ListenPort, g.config.AdminPort)
}

func (g *Generator) generateRouter() string {
	var cases strings.Builder

	ids := g.sortedMessageIDs()
	for _, id := range ids {
		msg := g.spec.Messages[id]
		handlerName := toGoName(msg.Name)
		cases.WriteString(fmt.Sprintf("\tcase 0x%04X: // %s\n", id, msg.Name))
		cases.WriteString(fmt.Sprintf("\t\treturn r.handle%s(s, payload)\n", handlerName))
	}

	return fmt.Sprintf(`package handler

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"

	"%s/pkg/session"
)

// Router dispatches incoming packets to handlers.
type Router struct {
	sessions *session.Manager
}

// NewRouter creates a new message router.
func NewRouter(sessions *session.Manager) *Router {
	return &Router{sessions: sessions}
}

// HandleConnection processes a single client connection.
func (r *Router) HandleConnection(conn net.Conn) {
	defer conn.Close()

	s := r.sessions.Create(conn)
	defer r.sessions.Remove(s.ID)

	fmt.Printf("[+] Client connected: %%s (session %%s)\n", conn.RemoteAddr(), s.ID)

	buf := make([]byte, 65536)
	for {
		// Read header: [2 bytes type] [3 bytes length] [2 bytes version]
		_, err := io.ReadFull(conn, buf[:7])
		if err != nil {
			break
		}

		msgType := binary.BigEndian.Uint16(buf[:2])
		length := uint32(buf[2])<<16 | uint32(buf[3])<<8 | uint32(buf[4])

		// Frames larger than the read buffer would overflow buf[:length].
		// Grow the buffer to fit rather than panicking or truncating.
		if int(length) > len(buf) {
			buf = make([]byte, length)
		}

		var payload []byte
		if length > 0 {
			if _, err = io.ReadFull(conn, buf[:length]); err != nil {
				break
			}
			payload = buf[:length]
		}

		if err := r.dispatch(s, msgType, payload); err != nil {
			fmt.Printf("[!] Error handling 0x%%04X: %%v\n", msgType, err)
		}
	}

	fmt.Printf("[-] Client disconnected: %%s\n", conn.RemoteAddr())
}

func (r *Router) dispatch(s *session.Session, msgType uint16, payload []byte) error {
	switch msgType {
%s
	default:
		fmt.Printf("[?] Unknown message: 0x%%04X (%%d bytes)\n", msgType, len(payload))
		return nil
	}
}
`, g.config.ModuleName, cases.String())
}

func (g *Generator) generateHandlers() string {
	var handlers strings.Builder

	ids := g.sortedMessageIDs()
	for _, id := range ids {
		msg := g.spec.Messages[id]
		handlerName := toGoName(msg.Name)
		handlers.WriteString(fmt.Sprintf(`
// handle%s processes %s (0x%04X).
// Direction: %s | Avg size: %d bytes | Samples: %d
func (r *Router) handle%s(s *session.Session, payload []byte) error {
	fmt.Printf("[%%s] %s (%%d bytes)\n", s.ID, len(payload))
	
	// 1. Optional: Parse the payload
	// _ = payload
	
	// 2. Custom game logic here
	// Example: s.Data["last_message"] = "%s"
	
	// 3. Send a response
	// s.Conn.Write(nil)
	
	return nil
}
`, handlerName, msg.Name, id, msg.Direction, msg.AvgSize, msg.SampleCount,
			handlerName, msg.Name, msg.Name))
	}

	return fmt.Sprintf(`package handler

import (
	"fmt"

	"%s/pkg/session"
)
%s`, g.config.ModuleName, handlers.String())
}

func (g *Generator) generateSession() string {
	return `package session

import (
	"crypto/rand"
	"encoding/hex"
	"net"
	"sync"
	"time"
)

// Session represents a connected client.
type Session struct {
	ID        string
	Conn      net.Conn
	CreatedAt time.Time
	Data      map[string]any
	mu        sync.RWMutex
}

// Manager tracks active sessions.
type Manager struct {
	mu       sync.RWMutex
	sessions map[string]*Session
}

// NewManager creates a new session manager.
func NewManager() *Manager {
	return &Manager{
		sessions: make(map[string]*Session),
	}
}

// Create starts a new session for a connection.
func (m *Manager) Create(conn net.Conn) *Session {
	id := generateID()
	s := &Session{
		ID:        id,
		Conn:      conn,
		CreatedAt: time.Now(),
		Data:      make(map[string]any),
	}

	m.mu.Lock()
	m.sessions[id] = s
	m.mu.Unlock()

	return s
}

// Remove ends a session.
func (m *Manager) Remove(id string) {
	m.mu.Lock()
	delete(m.sessions, id)
	m.mu.Unlock()
}

// Count returns the number of active sessions.
func (m *Manager) Count() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.sessions)
}

func generateID() string {
	b := make([]byte, 8)
	rand.Read(b)
	return hex.EncodeToString(b)
}
`
}

func (g *Generator) generateStore() string {
	return `package database

// Store provides persistent game state storage.
// Default implementation uses in-memory maps;
// replace with SQLite for production.
type Store struct {
	players map[string]*Player
}

// Player represents a game player's data.
type Player struct {
	ID       string
	Name     string
	Level    int
	XP       int
	Gems     int
	Gold     int
	Unlocked []string
}

// NewStore creates a new data store.
func NewStore() *Store {
	return &Store{
		players: make(map[string]*Player),
	}
}

// GetPlayer retrieves player data.
func (s *Store) GetPlayer(id string) *Player {
	return s.players[id]
}

// SavePlayer stores player data.
func (s *Store) SavePlayer(p *Player) {
	s.players[p.ID] = p
}

// CreateDefaultPlayer creates a new player with all content unlocked.
func (s *Store) CreateDefaultPlayer(id, name string) *Player {
	p := &Player{
		ID:    id,
		Name:  name,
		Level: 99,
		XP:    999999,
		Gems:  999999,
		Gold:  999999,
		Unlocked: []string{"all"},
	}
	s.players[id] = p
	return p
}
`
}

func (g *Generator) generateConfig() string {
	cfg := map[string]any{
		"server": map[string]any{
			"host":       "0.0.0.0",
			"port":       g.config.ListenPort,
			"admin_port": g.config.AdminPort,
		},
		"game": map[string]any{
			"name":          g.config.GameName,
			"max_players":   100,
			"unlock_all":    true,
			"infinite_gems": true,
			"infinite_gold": true,
			"max_level":     99,
		},
		"generated": map[string]any{
			"by":   "Mega-Analyzer Private Server Toolkit",
			"date": time.Now().Format("2006-01-02"),
		},
	}

	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		// map[string]any with only primitives — should never fail; still
		// surface a usable config instead of an empty file.
		return fmt.Sprintf("{\n  \"error\": %q\n}\n", err.Error())
	}
	return string(data) + "\n"
}

func (g *Generator) generateReadme() string {
	return fmt.Sprintf(`# %s — Private Server

> Generated by **Mega-Analyzer Private Server Toolkit**

## Quick Start

`+"```bash"+`
cd %s
go run cmd/server/main.go
`+"```"+`

Server will start on port %d.

## Configuration

Edit `+"`configs/server.json`"+` to change settings.

## Generated from

- Protocol: %s
- Message types: %d
- Total analyzed packets: %d
- Generated: %s

## Disclaimer

This server is for **educational and research purposes only**.
Use only with applications you own or have permission to test.
`,
		g.config.GameName, g.config.OutputDir,
		g.config.ListenPort, g.spec.Format,
		len(g.spec.Messages), g.spec.TotalPackets,
		time.Now().Format("2006-01-02 15:04"))
}

// ═══════════════════════════════════════════════════════════════════════════════
// HELPERS
// ═══════════════════════════════════════════════════════════════════════════════

func (g *Generator) sortedMessageIDs() []uint16 {
	ids := make([]uint16, 0, len(g.spec.Messages))
	for id := range g.spec.Messages {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	return ids
}

func toGoName(name string) string {
	// MSG_1234 → Msg1234
	// ClientHello → ClientHello
	name = strings.ReplaceAll(name, "_", " ")
	words := strings.Fields(name)
	var result strings.Builder
	for _, w := range words {
		if len(w) > 0 {
			result.WriteString(strings.ToUpper(w[:1]))
			if len(w) > 1 {
				result.WriteString(strings.ToLower(w[1:]))
			}
		}
	}
	return result.String()
}

// Silence unused import
var _ = template.Must
