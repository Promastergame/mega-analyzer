package secrets

import (
	"encoding/base32"
	"fmt"
	"strings"
)

// AWSAccountIDFromAccessKey derives the 12-digit AWS account id that is
// mathematically embedded in every access key id (AKIA.../ASIA...): the 16
// characters after the prefix are base32, and a fixed bit range of the
// decoded value is the account number. Fully offline - a decode and a bit
// shift, no AWS call. Knowing the account instantly tells a report reader
// whose key leaked.
func AWSAccountIDFromAccessKey(keyID string) (string, bool) {
	if len(keyID) != 20 {
		return "", false
	}
	dec, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(keyID[4:]))
	if err != nil || len(dec) < 6 {
		return "", false
	}
	var z uint64
	for i := 0; i < 6; i++ {
		z = z<<8 | uint64(dec[i])
	}
	const mask = uint64(0x7fffffffff80)
	return fmt.Sprintf("%012d", (z&mask)>>7), true
}
