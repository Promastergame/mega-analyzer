// Command trackercollector runs the beacon sink as a standalone process.
// Local lab use only — see labs/servers/README.md.
package main

import (
	"log"
	"os"

	trackercollector "labs-trackercollector"
)

func main() {
	addr := os.Getenv("LISTEN_ADDR")
	if addr == "" {
		addr = "127.0.0.1:18099"
	}

	s := trackercollector.New()
	if err := s.StartBackground(addr); err != nil {
		log.Fatalf("trackercollector: %v", err)
	}
	log.Printf("trackercollector listening on %s (GET /_hits to inspect)", s.Addr())

	select {}
}
