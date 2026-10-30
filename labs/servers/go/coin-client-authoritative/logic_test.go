package main

import (
	"bytes"
	"testing"
)

func TestFrameRoundTrip(t *testing.T) {
	payload := []byte{0xde, 0xad, 0xbe, 0xef}
	wire := encodeFrame(msgBuyItem, payload)

	f, err := readFrame(bytes.NewReader(wire))
	if err != nil {
		t.Fatalf("readFrame: %v", err)
	}
	if f.msgType != msgBuyItem {
		t.Errorf("msgType = 0x%04x, want 0x%04x", f.msgType, msgBuyItem)
	}
	if !bytes.Equal(f.payload, payload) {
		t.Errorf("payload = %x, want %x", f.payload, payload)
	}
}

func TestBuyItemRoundTrip(t *testing.T) {
	in := BuyItem{clientBalance: 777, itemID: 42}
	out, err := decodeBuyItem(encodeBuyItem(in))
	if err != nil {
		t.Fatalf("decodeBuyItem: %v", err)
	}
	if out != in {
		t.Errorf("round-trip = %+v, want %+v", out, in)
	}
}

// TestApplyPurchase_HonestBalanceIsRefused is the control: a player who
// truthfully reports 5 coins cannot buy the 100-coin item.
func TestApplyPurchase_HonestBalanceIsRefused(t *testing.T) {
	s := newSession()
	out := applyPurchase(s, BuyItem{clientBalance: startingCoins, itemID: 1})
	if out.approved {
		t.Fatalf("honest 5-coin balance should not afford a %d-coin item", itemPrice)
	}
	if s.serverBalance != startingCoins {
		t.Errorf("balance changed on a denied purchase: %d", s.serverBalance)
	}
}

func TestApplyPurchase_IgnoresForgedClientBalance(t *testing.T) {
	s := newSession()
	out := applyPurchase(s, BuyItem{clientBalance: 777, itemID: 1})
	if out.approved {
		t.Fatal("purchase core must ignore a forged client balance")
	}
	if s.serverBalance != startingCoins {
		t.Errorf("serverBalance = %d, want %d", s.serverBalance, startingCoins)
	}
}

func TestApplyPurchase_ServerBalanceExactlyPriceApproved(t *testing.T) {
	s := &session{serverBalance: itemPrice}
	out := applyPurchase(s, BuyItem{clientBalance: itemPrice, itemID: 1})
	if !out.approved {
		t.Fatal("server balance equal to price should be approved")
	}
}

func TestLegacyReconciliationEnablesMITMBypass(t *testing.T) {
	s := newSession()
	if !reconcileLegacyBalance(s, 777) {
		t.Fatal("forged legacy snapshot should poison server state in this lab")
	}
	out := applyPurchase(s, BuyItem{clientBalance: startingCoins, itemID: 1})
	if !out.approved {
		t.Fatal("poisoned server state should pass the otherwise-correct purchase check")
	}
	if s.serverBalance != 677 {
		t.Errorf("serverBalance = %d, want 677", s.serverBalance)
	}
}

func TestStateRoundTrip(t *testing.T) {
	st := State{balance: 12345}
	got, err := decodeState(encodeState(st))
	if err != nil {
		t.Fatalf("decodeState: %v", err)
	}
	if got != st {
		t.Errorf("round-trip = %+v, want %+v", got, st)
	}
}
