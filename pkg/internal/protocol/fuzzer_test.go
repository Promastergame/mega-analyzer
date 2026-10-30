package protocol

import (
	"testing"
)

// собираем Supercell-кадр: [2B type][3B len][2B ver] + payload
func scFrame(typ uint16, payload []byte) []byte {
	hdr := []byte{
		byte(typ >> 8), byte(typ),
		byte(len(payload) >> 16), byte(len(payload) >> 8), byte(len(payload)),
		0x00, 0x00,
	}
	return append(hdr, payload...)
}

func countStrategy(muts []Mutation, strat string) int {
	n := 0
	for _, m := range muts {
		if m.Strategy == strat {
			n++
		}
	}
	return n
}

func TestMutateFrame_FieldBoundary(t *testing.T) {
	// payload: 2-байтовое поле + 1 байт; фиктивный layout без заголовка.
	seed := []byte{0x10, 0x20, 0x30}
	fields := []FieldSpec{
		{Name: "field_0", Type: "uint16", Offset: 0, Size: 2},
		{Name: "field_2", Type: "uint8", Offset: 2, Size: 1},
	}
	layout := FrameLayout{HeaderLen: 0, LenOffset: -1}
	muts := MutateFrame(seed, layout, fields)

	// На каждое поле — 3 граничных значения (zero/0xFF/signMin).
	if got := countStrategy(muts, StrategyFieldBoundary); got != 6 {
		t.Fatalf("ожидалось 6 граничных мутаций, получено %d", got)
	}
	// Проверяем, что мутация не трогает чужие байты.
	for _, m := range muts {
		if m.Strategy != StrategyFieldBoundary {
			continue
		}
		if len(m.Data) != len(seed) {
			t.Errorf("граничная мутация изменила длину кадра: %d != %d", len(m.Data), len(seed))
		}
		if m.DataHex == "" {
			t.Errorf("DataHex не заполнен для %s", m.Name)
		}
	}
}

func TestMutateFrame_LengthDesync(t *testing.T) {
	seed := scFrame(10100, []byte{0xAA, 0xBB, 0xCC})
	layout := SupercellLayout()
	muts := MutateFrame(seed, layout, nil)

	if got := countStrategy(muts, StrategyLengthDesync); got < 3 {
		t.Fatalf("ожидалось несколько length-desync мутаций, получено %d", got)
	}
	// Поле длины должно реально меняться, заголовок остального — нет.
	for _, m := range muts {
		if m.Strategy != StrategyLengthDesync {
			continue
		}
		if len(m.Data) != len(seed) {
			t.Errorf("desync изменил длину кадра")
		}
		if m.Data[0] != seed[0] || m.Data[1] != seed[1] {
			t.Errorf("desync затронул поле типа сообщения")
		}
	}
}

func TestMutateFrame_BitFlipCapped(t *testing.T) {
	// Большой payload → битфлипы должны быть ограничены maxBitFlipSamples.
	payload := make([]byte, 1024)
	seed := append([]byte{0x01, 0x02}, payload...)
	layout := FrameLayout{HeaderLen: 2, LenOffset: -1}
	muts := MutateFrame(seed, layout, nil)

	flips := countStrategy(muts, StrategyBitFlip)
	if flips == 0 || flips > maxBitFlipSamples {
		t.Fatalf("битфлипы вне диапазона (0, %d]: %d", maxBitFlipSamples, flips)
	}
	// Каждый битфлип отличается от seed ровно частично и сохраняет длину.
	for _, m := range muts {
		if m.Strategy != StrategyBitFlip {
			continue
		}
		if len(m.Data) != len(seed) {
			t.Errorf("битфлип изменил длину")
		}
	}
}

func TestMutateFrame_TruncateAndExtend(t *testing.T) {
	seed := scFrame(10100, []byte{1, 2, 3, 4, 5, 6})
	layout := SupercellLayout()
	muts := MutateFrame(seed, layout, nil)

	if countStrategy(muts, StrategyTruncate) == 0 {
		t.Error("нет truncate-мутаций")
	}
	if countStrategy(muts, StrategyExtend) != 3 {
		t.Errorf("ожидалось 3 extend-мутации, получено %d", countStrategy(muts, StrategyExtend))
	}
	// truncate всегда короче seed, extend всегда длиннее.
	for _, m := range muts {
		switch m.Strategy {
		case StrategyTruncate:
			if len(m.Data) >= len(seed) {
				t.Errorf("truncate %s не короче seed", m.Name)
			}
		case StrategyExtend:
			if len(m.Data) <= len(seed) {
				t.Errorf("extend %s не длиннее seed", m.Name)
			}
		}
	}
}

func TestMutateFrame_Deterministic(t *testing.T) {
	seed := scFrame(20104, []byte{9, 8, 7, 6})
	layout := SupercellLayout()
	a := MutateFrame(seed, layout, []FieldSpec{{Name: "f", Type: "uint16", Offset: 0, Size: 2}})
	b := MutateFrame(seed, layout, []FieldSpec{{Name: "f", Type: "uint16", Offset: 0, Size: 2}})
	if len(a) != len(b) {
		t.Fatalf("недетерминированное число мутаций: %d != %d", len(a), len(b))
	}
	for i := range a {
		if a[i].Name != b[i].Name || a[i].DataHex != b[i].DataHex {
			t.Fatalf("мутация %d отличается между прогонами: %s vs %s", i, a[i].Name, b[i].Name)
		}
	}
}

func TestMutateSpec_FromInferredFields(t *testing.T) {
	ps := NewProtocolSpec("Fuzz")
	// Два сэмпла одного сообщения с постоянным заголовком и переменным телом.
	ps.AddSample(10100, "C2S", []byte{0xAA, 0xBB, 0x01, 0x02})
	ps.AddSample(10100, "C2S", []byte{0xAA, 0xBB, 0x03, 0x04})
	ps.InferFields()

	corpus := ps.MutateSpec(SupercellLayout())
	muts, ok := corpus[10100]
	if !ok || len(muts) == 0 {
		t.Fatalf("нет мутаций для сообщения 10100")
	}
	// Должны присутствовать все основные стратегии.
	for _, strat := range []string{StrategyFieldBoundary, StrategyLengthDesync, StrategyBitFlip, StrategyExtend} {
		if countStrategy(muts, strat) == 0 {
			t.Errorf("стратегия %s не сгенерировала ни одной мутации", strat)
		}
	}
	// Реконструированный заголовок должен нести opcode 10100.
	for _, m := range muts {
		if len(m.Data) >= 2 && m.Strategy == StrategyFieldBoundary {
			if uint16(m.Data[0])<<8|uint16(m.Data[1]) != 10100 {
				t.Errorf("opcode в заголовке потерян: %x %x", m.Data[0], m.Data[1])
			}
			break
		}
	}
}

func TestMutateFrame_NoFieldsStillStructural(t *testing.T) {
	// Без инференса полей всё равно должны быть структурные мутации.
	seed := scFrame(10100, []byte{1, 2, 3})
	muts := MutateFrame(seed, SupercellLayout(), nil)
	if len(muts) == 0 {
		t.Fatal("ожидались хотя бы структурные мутации")
	}
	if countStrategy(muts, StrategyFieldBoundary) != 0 {
		t.Error("без полей не должно быть field-boundary мутаций")
	}
}
