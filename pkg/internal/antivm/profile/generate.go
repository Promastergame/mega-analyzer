package profile

import (
	crand "crypto/rand"
	"fmt"
	"math/big"
	mrand "math/rand/v2"
	"strings"
)

// rng is the minimal random interface the generators need. Both the crypto
// source and the seeded source implement it, so generation code is identical
// regardless of mode.
type rng interface {
	intn(n int) int
}

// cryptoRNG draws from crypto/rand — used for the "random" (non-reproducible)
// generation mode.
type cryptoRNG struct{}

func (cryptoRNG) intn(n int) int {
	if n <= 0 {
		return 0
	}
	v, err := crand.Int(crand.Reader, big.NewInt(int64(n)))
	if err != nil {
		// crypto/rand should not fail; if it does, fall back to a fixed value
		// rather than panicking. Callers only need a value in [0,n).
		return 0
	}
	return int(v.Int64())
}

// seededRNG draws from a deterministic PRNG — used for the "seeded" mode so a
// given seed always produces the same profile (regression fixtures, repro).
type seededRNG struct{ r *mrand.Rand }

func newSeededRNG(seed uint64) *seededRNG {
	return &seededRNG{r: mrand.New(mrand.NewPCG(seed, seed^0x9e3779b97f4a7c15))}
}

func (s *seededRNG) intn(n int) int {
	if n <= 0 {
		return 0
	}
	return s.r.IntN(n)
}

// ── field generators (rng-driven) ────────────────────────────

func genDigits(r rng, n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte('0' + r.intn(10))
	}
	return string(b)
}

func genHex(r rng, n int) string {
	const hexChars = "0123456789ABCDEF"
	b := make([]byte, n)
	for i := range b {
		b[i] = hexChars[r.intn(len(hexChars))]
	}
	return string(b)
}

// genIMEI builds a valid 15-digit IMEI (real TAC prefix + serial + Luhn check).
func genIMEI(r rng) string {
	tacs := []string{
		"35332510", "35391610", // Samsung
		"35465206", "35425208", // Google Pixel
		"86749604", // OnePlus
		"86388103", // Xiaomi
		"35976009", // Motorola
		"35260910", // LG
	}
	partial := tacs[r.intn(len(tacs))] + genDigits(r, 6)
	return partial + fmt.Sprintf("%d", luhnCheckDigit(partial))
}

// genSerial builds an 8..12 char uppercase-hex serial.
func genSerial(r rng) string {
	return genHex(r, 8+r.intn(5))
}

// genMAC builds a unicast MAC with a real manufacturer OUI.
func genMAC(r rng) string {
	ouis := []string{
		"3C:5A:B4", "F4:F5:D8", "A4:77:33", // Google
		"F8:E4:E3", "C0:BD:D1", "94:35:0A", // Samsung
		"38:01:46", "C0:EE:FB", "94:65:2D", // OnePlus
		"DC:D9:AE", "64:CC:2E", "28:6C:07", // Xiaomi
	}
	oui := ouis[r.intn(len(ouis))]
	return fmt.Sprintf("%s:%02X:%02X:%02X", oui, r.intn(256), r.intn(256), r.intn(256))
}

// genSSID builds a realistic home WiFi SSID.
func genSSID(r rng) string {
	prefixes := []string{
		"NETGEAR", "TP-Link", "ASUS", "Linksys", "HUAWEI", "Dlink",
		"HOME", "MyWiFi", "FamilyNet", "Keenetic",
	}
	suffixes := []string{"_5G", "-5G", "_2.4G", "", ""}
	return prefixes[r.intn(len(prefixes))] + "_" + genHex(r, 4) + suffixes[r.intn(len(suffixes))]
}

// ── Luhn (shared with validator) ─────────────────────────────

// luhnCheckDigit computes the Luhn check digit for a partial numeric string.
func luhnCheckDigit(partial string) int {
	sum := 0
	n := len(partial)
	parity := (n + 1) % 2
	for i := 0; i < n; i++ {
		d := int(partial[i] - '0')
		if i%2 == parity {
			if d *= 2; d > 9 {
				d -= 9
			}
		}
		sum += d
	}
	return (10 - (sum % 10)) % 10
}

// ValidIMEI reports whether imei is 15 digits with a correct Luhn check digit.
func ValidIMEI(imei string) bool {
	if len(imei) != 15 {
		return false
	}
	for _, r := range imei {
		if r < '0' || r > '9' {
			return false
		}
	}
	return luhnCheckDigit(imei[:14]) == int(imei[14]-'0')
}

// ── device catalogue ─────────────────────────────────────────

// catalogEntry is one known real device the generators can instantiate.
// Pixel devices are included: in this architecture Pixel is both the base AVD
// platform and a valid target profile.
type catalogEntry struct {
	Model, Brand, Manufacturer, Device, Product, ABI string
	// fingerprintFmt is a Printf template taking (androidVersion, buildID).
	fingerprintFmt string
}

var catalog = []catalogEntry{
	{"Pixel 7", "google", "Google", "panther", "panther", "arm64-v8a",
		"google/panther/panther:%s/%s:user/release-keys"},
	{"Pixel 8", "google", "Google", "shiba", "shiba", "arm64-v8a",
		"google/shiba/shiba:%s/%s:user/release-keys"},
	{"Pixel 9", "google", "Google", "tokay", "tokay", "arm64-v8a",
		"google/tokay/tokay:%s/%s:user/release-keys"},
	{"SM-S928B", "samsung", "samsung", "e3q", "e3qxxx", "arm64-v8a",
		"samsung/e3qxxx/e3q:%s/%s:user/release-keys"},
	{"SM-A546B", "samsung", "samsung", "a54x", "a54xnsxx", "arm64-v8a",
		"samsung/a54xnsxx/a54x:%s/%s:user/release-keys"},
	{"CPH2585", "OnePlus", "OnePlus", "OP5913L1", "CPH2585", "arm64-v8a",
		"OnePlus/CPH2585/OP5913L1:%s/%s:user/release-keys"},
	{"23127PN0CG", "Xiaomi", "Xiaomi", "shennong", "shennong", "arm64-v8a",
		"Xiaomi/shennong/shennong:%s/%s:user/release-keys"},
}

// findCatalog returns the catalogue entry matching model/device/product
// (case-insensitive), and whether a match was found.
func findCatalog(key string) (catalogEntry, bool) {
	k := strings.ToLower(key)
	for _, e := range catalog {
		if strings.ToLower(e.Model) == k ||
			strings.ToLower(e.Device) == k ||
			strings.ToLower(e.Product) == k {
			return e, true
		}
	}
	return catalogEntry{}, false
}
