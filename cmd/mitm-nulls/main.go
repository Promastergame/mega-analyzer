package main

import (
	"encoding/hex"
	"encoding/json"
	"io"
	"log"
	"net"
	"os"
	"sync"
	"time"
)

const (
	listenAddr   = ":9339"
	upstreamAddr = "connect.nulls.gg:9339"
	recordPath   = "mitm_capture.jsonl"
)

type Packet struct {
	ID        uint64    `json:"id"`
	Timestamp time.Time `json:"timestamp"`
	Direction string    `json:"direction"`
	Size      int       `json:"size"`
	HexData   string    `json:"hex_data"`
	ASCII     string    `json:"ascii,omitempty"`
}

var (
	packetCount uint64
	mu          sync.Mutex
	file        *os.File
)

func main() {
	log.SetFlags(log.Ltime | log.Lmicroseconds)
	log.Printf("[MITM] Starting proxy: listen=%s upstream=%s", listenAddr, upstreamAddr)

	var err error
	file, err = os.Create(recordPath)
	if err != nil {
		log.Fatalf("[MITM] Failed to create record file: %v", err)
	}
	defer file.Close()

	listener, err := net.Listen("tcp", listenAddr)
	if err != nil {
		log.Fatalf("[MITM] Failed to listen: %v", err)
	}
	defer listener.Close()

	log.Printf("[MITM] Listening on %s, forwarding to %s", listenAddr, upstreamAddr)
	log.Printf("[MITM] Packets will be saved to %s", recordPath)
	log.Println("[MITM] Press Ctrl+C to stop")

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("[MITM] Accept error: %v", err)
			continue
		}
		go handleConnection(conn)
	}
}

func handleConnection(clientConn net.Conn) {
	mu.Lock()
	packetCount++
	id := packetCount
	mu.Unlock()

	log.Printf("[MITM] New connection from %s (id=%d)", clientConn.RemoteAddr(), id)

	serverConn, err := net.DialTimeout("tcp", upstreamAddr, 10*time.Second)
	if err != nil {
		log.Printf("[MITM] Failed to connect to upstream: %v", err)
		clientConn.Close()
		return
	}

	log.Printf("[MITM] Connected to upstream %s (id=%d)", upstreamAddr, id)

	done := make(chan struct{}, 2)

	go func() {
		relay(clientConn, serverConn, "C→S", id)
		done <- struct{}{}
	}()

	go func() {
		relay(serverConn, clientConn, "S→C", id)
		done <- struct{}{}
	}()

	<-done
	_ = clientConn.SetDeadline(time.Now())
	_ = serverConn.SetDeadline(time.Now())
	<-done

	clientConn.Close()
	serverConn.Close()
	log.Printf("[MITM] Connection closed (id=%d)", id)
}

func relay(src, dst net.Conn, direction string, connID uint64) {
	buf := make([]byte, 65536)
	for {
		_ = src.SetReadDeadline(time.Now().Add(30 * time.Second))
		n, err := src.Read(buf)
		if n > 0 {
			data := make([]byte, n)
			copy(data, buf[:n])
			logPacket(data, direction, connID)

			if _, werr := dst.Write(data); werr != nil {
				return
			}
		}
		if err != nil {
			if err != io.EOF {
				log.Printf("[MITM] Read error (%s, id=%d): %v", direction, connID, err)
			}
			return
		}
	}
}

func logPacket(data []byte, direction string, connID uint64) {
	mu.Lock()
	packetCount++
	id := packetCount
	mu.Unlock()

	// Build ASCII representation
	ascii := make([]byte, len(data))
	for i, b := range data {
		if b >= 32 && b <= 126 {
			ascii[i] = b
		} else {
			ascii[i] = '.'
		}
	}

	pkt := Packet{
		ID:        id,
		Timestamp: time.Now(),
		Direction: direction,
		Size:      len(data),
		HexData:   hex.Dump(data[:min(len(data), 256)]),
		ASCII:     string(ascii),
	}

	// Log to console
	log.Printf("[MITM] [%s] conn=%d pkt=%d size=%d", direction, connID, id, len(data))
	if len(data) <= 64 {
		log.Printf("[MITM] hex: %s", hex.EncodeToString(data))
	}

	// Write to file
	line, _ := json.Marshal(pkt)
	file.Write(line)
	file.Write([]byte("\n"))
	file.Sync()
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
