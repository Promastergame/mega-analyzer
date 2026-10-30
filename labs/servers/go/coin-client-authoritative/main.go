// Command coin-client-authoritative is an INTENTIONALLY VULNERABLE lab game
// server (CWE-602: Client-Side Enforcement of Server-Side Security). It exposes
// a persistent browser shop and a small length-prefixed binary protocol. The
// purchase transaction is server-authoritative; one obsolete wallet recovery
// boundary still trusts an unsigned client snapshot. See README.md.
//
// It binds to 127.0.0.1 only and must never be exposed or deployed. Its reason
// for existing is to give this repo's MITM/netproxy tooling a realistic target:
// a player with too few coins can be made to "afford" an item by anything on
// the wire that rewrites the legacy reported balance to, say, 777.
package main

import (
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"time"
)

const defaultListenAddr = "127.0.0.1:18010"
const defaultHTTPListenAddr = "127.0.0.1:18110"

func listenAddr() string {
	if v := os.Getenv("LISTEN_ADDR"); v != "" {
		return v
	}
	return defaultListenAddr
}

func httpListenAddr() string {
	if v := os.Getenv("HTTP_LISTEN_ADDR"); v != "" {
		return v
	}
	return defaultHTTPListenAddr
}

func main() {
	addr := listenAddr()
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatalf("coin-lab: listen %s: %v", addr, err)
	}
	// Print the actual bound address (so LISTEN_ADDR=127.0.0.1:0 lets a
	// supervising test discover the ephemeral port from stdout).
	log.Printf("coin-lab: listening on %s (starting coins: %d, item price: %d)",
		ln.Addr().String(), startingCoins, itemPrice)

	// The external MITM integration tests set only LISTEN_ADDR. In that mode we
	// keep the historical raw TCP fixture isolated and do not also contend for
	// a fixed HTTP port or database file.
	if os.Getenv("HTTP_DISABLED") == "1" ||
		(os.Getenv("LISTEN_ADDR") != "" && os.Getenv("HTTP_LISTEN_ADDR") == "") {
		serveTCP(ln)
		return
	}

	db, err := newBoltStore(databasePath())
	if err != nil {
		log.Fatalf("coin-lab: open database: %v", err)
	}
	defer db.Close()

	go serveTCP(ln)
	httpAddr := httpListenAddr()
	log.Printf("coin-lab: shop UI available at http://%s (database: %s)", httpAddr, databasePath())
	if err := http.ListenAndServe(httpAddr, newWebServer(db).routes()); err != nil {
		log.Fatalf("coin-lab: http server: %v", err)
	}
}

func serveTCP(ln net.Listener) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("coin-lab: accept: %v", err)
			return
		}
		go handleConn(conn)
	}
}

// handleConn serves one client connection: a message loop over the framed
// protocol until the client disconnects or errors.
func handleConn(conn net.Conn) {
	defer conn.Close()
	sess := newSession()

	for {
		_ = conn.SetReadDeadline(time.Now().Add(60 * time.Second))
		f, err := readFrame(conn)
		if err != nil {
			if !errors.Is(err, io.EOF) {
				log.Printf("coin-lab: read from %s: %v", conn.RemoteAddr(), err)
			}
			return
		}
		if err := handleFrame(conn, sess, f); err != nil {
			log.Printf("coin-lab: handle %s: %v", conn.RemoteAddr(), err)
			return
		}
	}
}

// handleFrame dispatches one decoded message and writes the server's reply.
func handleFrame(conn net.Conn, sess *session, f frame) error {
	switch f.msgType {
	case msgHello:
		return writeFrame(conn, msgWelcome, encodeState(State{balance: sess.serverBalance}))

	case msgGetState:
		return writeFrame(conn, msgState, encodeState(State{balance: sess.serverBalance}))

	case msgBuyItem:
		req, err := decodeBuyItem(f.payload)
		if err != nil {
			return writeFrame(conn, msgError, []byte(err.Error()))
		}
		reconciled := reconcileLegacyBalance(sess, req.clientBalance)
		outcome := applyPurchase(sess, req)
		if outcome.approved {
			log.Printf("coin-lab: PURCHASE APPROVED for %s: client claimed %d coins, "+
				"legacy_reconciled=%t, server balance is now %d (item price %d)",
				conn.RemoteAddr(), req.clientBalance, reconciled, sess.serverBalance, itemPrice)
			return writeFrame(conn, msgBuyOK, encodeState(outcome.state))
		}
		return writeFrame(conn, msgBuyDenied, []byte(outcome.reason))

	default:
		return writeFrame(conn, msgError, []byte("unknown message type"))
	}
}
