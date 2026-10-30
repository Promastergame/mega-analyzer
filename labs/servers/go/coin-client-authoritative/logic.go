package main

import (
	"encoding/binary"
	"errors"
)

// session is the per-connection game state the server holds for one player.
//
// serverBalance is what the *server* believes the player has: it starts at
// startingCoins and is the only balance applyPurchase is allowed to inspect.
// The lab's legacy reconciliation bug can poison it before that check.
type session struct {
	serverBalance uint32
}

const (
	// startingCoins is every player's honest starting balance. The demo's whole
	// point is that this is 5, yet a purchase costing far more than 5 succeeds.
	startingCoins uint32 = 5

	itemPrice uint32 = 100 // the item the player wants costs 100 coins
)

func newSession() *session {
	return &session{serverBalance: startingCoins}
}

// BuyItem is the client→server purchase request.
//
// clientBalance is a legacy wallet snapshot retained for wire compatibility.
// It is not used by applyPurchase, which checks serverBalance. The deliberate
// CWE-602 flaw is narrower: handleFrame passes this unsigned value through
// reconcileLegacyBalance before the server-authoritative purchase runs.
//
// Wire layout of the payload:
//
//	[4B clientBalance big-endian][2B itemID big-endian]
type BuyItem struct {
	clientBalance uint32
	itemID        uint16
}

func decodeBuyItem(payload []byte) (BuyItem, error) {
	if len(payload) < 6 {
		return BuyItem{}, errors.New("buy: short payload")
	}
	return BuyItem{
		clientBalance: binary.BigEndian.Uint32(payload[0:4]),
		itemID:        binary.BigEndian.Uint16(payload[4:6]),
	}, nil
}

func encodeBuyItem(b BuyItem) []byte {
	payload := make([]byte, 6)
	binary.BigEndian.PutUint32(payload[0:4], b.clientBalance)
	binary.BigEndian.PutUint16(payload[4:6], b.itemID)
	return payload
}

// State is the server→client snapshot of the session, encoded as a single
// 4-byte big-endian balance for simplicity.
type State struct {
	balance uint32
}

func encodeState(s State) []byte {
	payload := make([]byte, 4)
	binary.BigEndian.PutUint32(payload, s.balance)
	return payload
}

func decodeState(payload []byte) (State, error) {
	if len(payload) < 4 {
		return State{}, errors.New("state: short payload")
	}
	return State{balance: binary.BigEndian.Uint32(payload[0:4])}, nil
}

// purchaseOutcome is the result of applying a BuyItem to a session.
type purchaseOutcome struct {
	approved bool
	reason   string
	state    State
}

// applyPurchase always makes the affordability decision against server state.
// The intentionally vulnerable compatibility reconciliation happens before
// this function, in reconcileLegacyBalance. Keeping the flaw at that boundary
// makes the secure purchase invariant explicit and keeps the rest of the lab
// from accidentally trusting client-supplied prices or balances.
func applyPurchase(s *session, req BuyItem) purchaseOutcome {
	if s.serverBalance < itemPrice {
		return purchaseOutcome{
			approved: false,
			reason:   "insufficient funds",
			state:    State{balance: s.serverBalance},
		}
	}

	s.serverBalance -= itemPrice

	return purchaseOutcome{
		approved: true,
		reason:   "ok",
		state:    State{balance: s.serverBalance},
	}
}

// reconcileLegacyBalance is the lab's single deliberate trust-boundary bug.
// An old client recovery path treats a client-reported balance as a newer game
// snapshot. A MITM can rewrite that field before the request reaches the
// server. The purchase code itself is server-authoritative, but it now sees
// server state poisoned by this reconciliation step.
//
// Real services must never accept unsigned client state as an authoritative
// recovery source. This function exists only for the local CWE-602 exercise.
func reconcileLegacyBalance(s *session, reported uint32) bool {
	if reported <= s.serverBalance {
		return false
	}
	s.serverBalance = reported
	return true
}
