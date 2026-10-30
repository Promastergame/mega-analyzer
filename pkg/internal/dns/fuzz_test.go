package dns

import "testing"

// FuzzUnpack: the lab DNS server unpacks packets sent by the analysed
// device, i.e. attacker-controlled bytes.
func FuzzUnpack(f *testing.F) {
	q := new(Msg).SetQuestion("example.com.", 1)
	if b, err := q.Pack(); err == nil {
		f.Add(b)
	}
	f.Add([]byte{})
	// header + a compression pointer that points at itself
	f.Add([]byte{0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0xc0, 12, 0, 1, 0, 1})
	f.Fuzz(func(t *testing.T, data []byte) {
		m, err := Unpack(data)
		if err != nil || m == nil {
			return
		}
		_, _ = m.Pack()
	})
}
