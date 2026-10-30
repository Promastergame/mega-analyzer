package netproxy

import (
	"bufio"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
)

var (
	stdinReader  *bufio.Reader
	currentStdin *os.File
	stdinMu      sync.Mutex
)

func readLine() (string, error) {
	stdinMu.Lock()
	defer stdinMu.Unlock()
	if stdinReader == nil || currentStdin != os.Stdin {
		currentStdin = os.Stdin
		stdinReader = bufio.NewReader(os.Stdin)
	}
	line, err := stdinReader.ReadString('\n')
	if err != nil {
		return "", err
	}
	return strings.TrimRight(line, "\r\n"), nil
}

// PacketEditor provides interactive terminal-based editing for intercepted packets.
// It supports JSON, MessagePack, and Hex.
type PacketEditor struct {
	consoleMu  sync.Mutex
	ignoredMu  sync.RWMutex
	ignoredIDs map[uint16]bool
}

// NewPacketEditor creates a new interactive packet editor.
func NewPacketEditor() *PacketEditor {
	return &PacketEditor{
		ignoredIDs: make(map[uint16]bool),
	}
}

// PromptAndRewrite displays packet in console and allows y/n/i choices.
// It returns modified payload bytes (not including headers if not necessary,
// but the TCP proxy replaces the whole packet payload, so we return the full modified data).
func (pe *PacketEditor) PromptAndRewrite(pkt Packet, payloadOff int) []byte {
	pe.consoleMu.Lock()
	defer pe.consoleMu.Unlock()

	var payload []byte
	if payloadOff < len(pkt.Data) {
		payload = pkt.Data[payloadOff:]
	}

	// Detect format
	isJSON := false
	isMsgPack := false
	var parsedJSON map[string]any

	if len(payload) > 0 && (payload[0] == '{' || payload[0] == '[') {
		if err := json.Unmarshal(payload, &parsedJSON); err == nil {
			isJSON = true
		}
	} else if len(payload) > 0 && (payload[0] == 0x80 || (payload[0] >= 0x81 && payload[0] <= 0x8f) || payload[0] == 0xde || payload[0] == 0xdf) {
		// Basic MessagePack map heuristic
		if val, err := UnmarshalMsgPack(payload); err == nil {
			if m, ok := val.(map[string]any); ok {
				parsedJSON = m
				isMsgPack = true
			}
		}
	}

	fmt.Printf("\n\n============ \U0001f4e5 INTERCEPTED PACKET ============\n")
	fmt.Printf("Message Type: 0x%04X | Dir: %s | Size: %d bytes\n", pkt.MessageType, pkt.Direction, pkt.Size)

	if isJSON {
		pretty, _ := json.MarshalIndent(parsedJSON, "", "  ")
		fmt.Printf("Payload (JSON):\n%s\n", string(pretty))
	} else if isMsgPack {
		// Render msgpack as JSON for viewing
		pretty, _ := json.MarshalIndent(parsedJSON, "", "  ")
		fmt.Printf("Payload (MessagePack decoded):\n%s\n", string(pretty))
	} else {
		fmt.Printf("Payload (Hex):\n%s\n", pkt.HexDump(64))
	}
	fmt.Printf("================================================\n")

	for {
		fmt.Print("Choose action -> [y] edit, [n] pass original, [i] ignore this msg type: ")
		choice, err := readLine()
		if err != nil {
			choice = "n"
		}
		choice = strings.ToLower(strings.TrimSpace(choice))

		switch choice {
		case "n", "":
			fmt.Println("\U0001f449 Passed without changes.")
			return nil
		case "i":
			pe.ignoredMu.Lock()
			pe.ignoredIDs[pkt.MessageType] = true
			pe.ignoredMu.Unlock()
			fmt.Printf("\U0001f6ab Message type 0x%04X is now IGNORED and will pass automatically.\n", pkt.MessageType)
			return nil
		case "y":
			var newPayload []byte
			var err error

			if isJSON || isMsgPack {
				// Interactive key editor
				editedJSON := make(map[string]any)
				for k, v := range parsedJSON {
					editedJSON[k] = v
				}

				keys := make([]string, 0, len(parsedJSON))
				for k := range parsedJSON {
					keys = append(keys, k)
				}
				sort.Strings(keys)

				fmt.Println("\nEnter fields to modify. Press enter to keep current value.")
				for _, k := range keys {
					v := parsedJSON[k]
					fmt.Printf("Field [%s] (current: %v): ", k, v)
					input, err := readLine()
					if err != nil {
						input = ""
					}
					input = strings.TrimSpace(input)

					switch v.(type) {
					case bool:
						if input == "" {
							// keep current value
						} else if input == "true" || input == "1" {
							editedJSON[k] = true
						} else if input == "false" || input == "0" {
							editedJSON[k] = false
						}
					case float64:
						if input != "" {
							var f float64
							if _, err := fmt.Sscanf(input, "%f", &f); err == nil {
								editedJSON[k] = f
							}
						}
					case int, int64:
						if input != "" {
							var i int64
							if _, err := fmt.Sscanf(input, "%d", &i); err == nil {
								editedJSON[k] = i
							}
						}
					default:
						if input != "" {
							editedJSON[k] = input
						}
					}
				}

				switch isJSON {
				case true:
					newPayload, err = json.Marshal(editedJSON)
				case false:
					newPayload, err = MarshalMsgPack(editedJSON)
				}

				if err != nil {
					fmt.Printf("\u274c Failed to encode: %v. Passing original.\n", err)
					return nil
				}
			} else {
				// Basic Hex editor fallback
				fmt.Println("\nHex Edit Mode:")
				fmt.Println("Format: <offset_in_hex> <new_bytes_in_hex>")
				fmt.Println("Example: 0A 112233")
				fmt.Print("Enter edit (or press enter to cancel): ")
				input, err := readLine()
				if err != nil {
					input = ""
				}
				input = strings.TrimSpace(input)
				if input == "" {
					fmt.Println("\U0001f449 Passed without changes.")
					return nil
				}

				parts := strings.Fields(input)
				if len(parts) != 2 {
					fmt.Println("\u274c Invalid format. Passing original.")
					return nil
				}

				offset, err := strconv.ParseInt(parts[0], 16, 64)
				if err != nil || offset < 0 || int(offset) >= len(payload) {
					fmt.Println("\u274c Invalid offset. Passing original.")
					return nil
				}

				hexStr := parts[1]
				if len(hexStr)%2 != 0 {
					hexStr = "0" + hexStr
				}
				patchBytes, err := hex.DecodeString(hexStr)
				if err != nil {
					fmt.Println("\u274c Invalid hex bytes. Passing original.")
					return nil
				}

				// Apply patch to payload copy, growing the buffer if the
				// patch extends past the current payload length so bytes
				// aren't silently truncated by copy().
				needed := int(offset) + len(patchBytes)
				newLen := len(payload)
				if needed > newLen {
					newLen = needed
				}
				newPayload = make([]byte, newLen)
				copy(newPayload, payload)
				copy(newPayload[int(offset):], patchBytes)
				fmt.Printf("Applied patch at offset 0x%x (%d bytes)\n", offset, len(patchBytes))
			}

			// Rebuild packet data: header + new payload
			header := pkt.Data[:payloadOff]
			patched := make([]byte, len(header)+len(newPayload))
			copy(patched, header)
			copy(patched[len(header):], newPayload)

			// Update Supercell-style length in header if header is 7 bytes
			if payloadOff == 7 {
				length := len(newPayload)
				patched[2] = byte(length >> 16)
				patched[3] = byte(length >> 8)
				patched[4] = byte(length)
			}

			fmt.Println("\u2705 Packet modified successfully!")
			return patched
		default:
			fmt.Println("\u274c Invalid choice. Please enter 'y', 'n', or 'i'.")
		}
	}
}

// IsIgnored checks if the given message type is currently ignored by the user.
func (pe *PacketEditor) IsIgnored(msgType uint16) bool {
	pe.ignoredMu.RLock()
	defer pe.ignoredMu.RUnlock()
	return pe.ignoredIDs[msgType]
}
