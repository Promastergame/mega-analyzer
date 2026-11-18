package correlation

import (
	"strings"
	"testing"

	"mega-analyzer/pkg/internal/types"
)

func TestCiphertextSubstringIsNotAWeakCryptoSignal(t *testing.T) {
	m := types.Match{Pattern: strings.Repeat("X", 700) + "rc4" + strings.Repeat("Y", 700)}
	if got := mapStaticType(m); got != "" {
		t.Fatalf("ciphertext substring produced %s", got)
	}
	m.Category = types.CategoryInsecureTLS
	if got := mapStaticType(m); got != TypeWeakCrypto {
		t.Fatalf("semantic TLS finding was lost: %s", got)
	}
	if len(staticTitle(TypeWeakCrypto, m)) > 240 {
		t.Fatal("encoded payload copied into the finding title")
	}
}
