package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"
)

type webHarness struct {
	t      *testing.T
	store  *boltStore
	server *httptest.Server
	client *http.Client
}

func newWebHarness(t *testing.T) *webHarness {
	t.Helper()
	store, err := newBoltStore(filepath.Join(t.TempDir(), "coin-test.db"))
	if err != nil {
		t.Fatalf("newBoltStore: %v", err)
	}
	server := httptest.NewServer(newWebServer(store).routes())
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("cookiejar.New: %v", err)
	}
	h := &webHarness{t: t, store: store, server: server, client: &http.Client{Jar: jar}}
	t.Cleanup(func() {
		server.Close()
		_ = store.Close()
	})
	return h
}

func (h *webHarness) request(method, path, body string) (*http.Response, []byte) {
	h.t.Helper()
	var reader io.Reader
	if body != "" {
		reader = bytes.NewBufferString(body)
	}
	req, err := http.NewRequest(method, h.server.URL+path, reader)
	if err != nil {
		h.t.Fatalf("http.NewRequest: %v", err)
	}
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := h.client.Do(req)
	if err != nil {
		h.t.Fatalf("client.Do: %v", err)
	}
	data, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		h.t.Fatalf("read response: %v", err)
	}
	return resp, data
}

func (h *webHarness) register(username string) accountSnapshot {
	h.t.Helper()
	body, _ := json.Marshal(credentialsRequest{Username: username, Password: "correct-lab-password"})
	resp, data := h.request(http.MethodPost, "/api/register", string(body))
	if resp.StatusCode != http.StatusCreated {
		h.t.Fatalf("register status = %d, body=%s", resp.StatusCode, data)
	}
	var snapshot accountSnapshot
	if err := json.Unmarshal(data, &snapshot); err != nil {
		h.t.Fatalf("decode register response: %v", err)
	}
	return snapshot
}

func TestWebShopRealPurchaseUsesServerPriceAndBalance(t *testing.T) {
	h := newWebHarness(t)
	created := h.register("packet_runner")
	if created.Balance != webStartingCoins {
		t.Fatalf("starting balance = %d, want %d", created.Balance, webStartingCoins)
	}

	resp, data := h.request(http.MethodPost, "/api/buy", `{"item_id":1}`)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("buy status = %d, body=%s", resp.StatusCode, data)
	}
	var bought accountSnapshot
	if err := json.Unmarshal(data, &bought); err != nil {
		t.Fatalf("decode buy response: %v", err)
	}
	if bought.Balance != webStartingCoins-catalog[0].Price {
		t.Errorf("balance = %d, want %d", bought.Balance, webStartingCoins-catalog[0].Price)
	}
	if len(bought.Inventory) != 1 || bought.Inventory[0].Product.ID != 1 || bought.Inventory[0].Count != 1 {
		t.Fatalf("inventory = %+v, want one item #1", bought.Inventory)
	}
}

func TestWebPurchaseRejectsClientBalanceButLegacySyncRemainsMITMVulnerable(t *testing.T) {
	h := newWebHarness(t)
	h.register("wire_runner")

	// The real purchase contract has no balance or price field. Unknown fields
	// are rejected instead of silently becoming part of an authorization check.
	resp, _ := h.request(http.MethodPost, "/api/buy", `{"item_id":2,"client_balance":777}`)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("purchase with client_balance status = %d, want 400", resp.StatusCode)
	}

	resp, _ = h.request(http.MethodPost, "/api/buy", `{"item_id":2}`)
	if resp.StatusCode != http.StatusPaymentRequired {
		t.Fatalf("honest expensive purchase status = %d, want 402", resp.StatusCode)
	}

	// This endpoint is the one intentional flaw: a MITM can rewrite 35 to 777
	// in transit, poisoning otherwise-authoritative state before the purchase.
	resp, data := h.request(http.MethodPost, "/api/wallet/reconcile", `{"reported_balance":777}`)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("legacy reconcile status = %d, body=%s", resp.StatusCode, data)
	}
	resp, data = h.request(http.MethodPost, "/api/buy", `{"item_id":2}`)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("purchase after reconciliation status = %d, body=%s", resp.StatusCode, data)
	}
	var bought accountSnapshot
	if err := json.Unmarshal(data, &bought); err != nil {
		t.Fatalf("decode purchase: %v", err)
	}
	if bought.Balance != 677 {
		t.Errorf("balance = %d, want 677", bought.Balance)
	}
}

func TestLogoutAndPasswordConfirmedAccountDeletion(t *testing.T) {
	h := newWebHarness(t)
	h.register("short_session")

	resp, _ := h.request(http.MethodPost, "/api/logout", `{}`)
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("logout status = %d, want 204", resp.StatusCode)
	}
	resp, _ = h.request(http.MethodGet, "/api/me", "")
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("me after logout status = %d, want 401", resp.StatusCode)
	}

	login, _ := json.Marshal(credentialsRequest{Username: "short_session", Password: "correct-lab-password"})
	resp, data := h.request(http.MethodPost, "/api/login", string(login))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("login status = %d, body=%s", resp.StatusCode, data)
	}
	resp, _ = h.request(http.MethodDelete, "/api/account", `{"password":"wrong-password"}`)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("delete with wrong password status = %d, want 401", resp.StatusCode)
	}
	resp, data = h.request(http.MethodDelete, "/api/account", `{"password":"correct-lab-password"}`)
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("delete status = %d, body=%s", resp.StatusCode, data)
	}
	resp, _ = h.request(http.MethodPost, "/api/login", string(login))
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("login after deletion status = %d, want 401", resp.StatusCode)
	}
}

func TestBoltStorePersistsAccountInventoryAndEarnCooldown(t *testing.T) {
	path := filepath.Join(t.TempDir(), "persistent.db")
	store, err := newBoltStore(path)
	if err != nil {
		t.Fatalf("newBoltStore: %v", err)
	}
	u, err := store.CreateUser(t.Context(), "persistent", "salt", "hash")
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	if _, err := store.Purchase(t.Context(), u.ID, 1); err != nil {
		t.Fatalf("Purchase: %v", err)
	}
	now := time.Unix(1_800_000_000, 0)
	if _, err := store.Earn(t.Context(), u.ID, now); err != nil {
		t.Fatalf("Earn: %v", err)
	}
	if _, err := store.Earn(t.Context(), u.ID, now.Add(time.Second)); !errors.Is(err, errEarnCooldown) {
		t.Fatalf("second Earn error = %v, want cooldown", err)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	reopened, err := newBoltStore(path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer reopened.Close()
	snapshot, err := reopened.Snapshot(t.Context(), u.ID)
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	if snapshot.Balance != webStartingCoins-catalog[0].Price+earnReward {
		t.Errorf("persisted balance = %d", snapshot.Balance)
	}
	if len(snapshot.Inventory) != 1 || snapshot.Inventory[0].Count != 1 {
		t.Errorf("persisted inventory = %+v", snapshot.Inventory)
	}
}
