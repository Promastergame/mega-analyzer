package s1

import "testing"

func TestLexNegation(t *testing.T) {
	d := lexDocOf("Сетевых запросов не было. No network access.")
	if n, _ := d.hits("network"); n != 0 {
		t.Fatalf("negated network counted: %d", n)
	}
	d = lexDocOf("I see two charges of $120 on my card")
	if n, _ := d.hits("=card"); n != 1 {
		t.Fatalf("card not found")
	}
}

func TestOptionVotesPreferDomain(t *testing.T) {
	q := compiled{Type: TypeChoice, Options: []Option{{"secrets", "Утечка секретов или ключей"}, {"crypto", "Слабая криптография"}, {"other", ""}}}
	v := optionVotes(q, lexDocOf(`Hardcoded API key: const-string v1, "sk_live_..." used in Authorization header`))
	if !(v[0].z > v[1].z) || len(v[0].found) == 0 {
		t.Fatalf("secrets should win: %+v", v)
	}
	if v[2].z != 0 {
		t.Fatalf("escape option must stay neutral")
	}
}
