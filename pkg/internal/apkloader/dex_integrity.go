package apkloader

import (
	"bytes"
	"crypto/sha1"
	"encoding/binary"
	"fmt"
	"hash/adler32"
)

// finalizeDEX updates integrity fields after all bytecode/header edits. The
// checksum covers the signature, so the order is significant.
func finalizeDEX(data []byte) error {
	if len(data) < dexHeaderSize {
		return fmt.Errorf("DEX image is too small to finalize")
	}
	signature := sha1.Sum(data[32:])
	copy(data[12:32], signature[:])
	binary.LittleEndian.PutUint32(data[8:12], adler32.Checksum(data[12:]))
	return nil
}

func verifyDEXIntegrity(data []byte) error {
	if len(data) < dexHeaderSize {
		return fmt.Errorf("DEX image is too small")
	}
	signature := sha1.Sum(data[32:])
	if !bytes.Equal(data[12:32], signature[:]) {
		return fmt.Errorf("DEX SHA-1 mismatch")
	}
	if binary.LittleEndian.Uint32(data[8:12]) != adler32.Checksum(data[12:]) {
		return fmt.Errorf("DEX Adler-32 mismatch")
	}
	return nil
}
