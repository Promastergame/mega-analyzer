package main

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
	"time"

	bolt "go.etcd.io/bbolt"
)

const (
	webStartingCoins uint64 = 35
	earnReward       uint64 = 15
	earnCooldown            = 5 * time.Second
	maxLabBalance    uint64 = 1_000_000
)

var (
	errUsernameTaken     = errors.New("username already exists")
	errInvalidLogin      = errors.New("invalid username or password")
	errUnauthenticated   = errors.New("unauthenticated")
	errInsufficientFunds = errors.New("insufficient funds")
	errEarnCooldown      = errors.New("earn cooldown active")
	errUnknownProduct    = errors.New("unknown product")
)

var (
	bucketUsers     = []byte("users")
	bucketUsernames = []byte("usernames")
	bucketSessions  = []byte("sessions")
	bucketInventory = []byte("inventory")
)

type product struct {
	ID          uint16 `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Price       uint64 `json:"price"`
	Rarity      string `json:"rarity"`
	Art         string `json:"art"`
}

var catalog = []product{
	{ID: 1, Name: "Патч-кабель", Description: "Стабильный линк для первого стенда.", Price: 25, Rarity: "обычный", Art: "cable"},
	{ID: 2, Name: "Signal Chip", Description: "Чип, который открывает основную coin-injection задачу.", Price: 100, Rarity: "редкий", Art: "chip"},
	{ID: 3, Name: "Proxy Deck", Description: "Карманная дека для разбора пакетов на лету.", Price: 240, Rarity: "эпический", Art: "deck"},
	{ID: 4, Name: "Root Crown", Description: "Коллекционный трофей для тех, кто сломал доверие.", Price: 500, Rarity: "легендарный", Art: "crown"},
}

type userRecord struct {
	ID           uint64 `json:"id"`
	Username     string `json:"username"`
	UsernameKey  string `json:"username_key"`
	PasswordSalt string `json:"password_salt"`
	PasswordHash string `json:"password_hash"`
	Balance      uint64 `json:"balance"`
	NextEarnAt   int64  `json:"next_earn_at"`
	CreatedAt    int64  `json:"created_at"`
}

type sessionRecord struct {
	UserID    uint64 `json:"user_id"`
	ExpiresAt int64  `json:"expires_at"`
}

type inventoryItem struct {
	Product product `json:"product"`
	Count   uint64  `json:"count"`
}

type accountSnapshot struct {
	ID           uint64          `json:"id"`
	Username     string          `json:"username"`
	Balance      uint64          `json:"balance"`
	NextEarnAt   int64           `json:"next_earn_at"`
	EarnReward   uint64          `json:"earn_reward"`
	EarnCooldown int64           `json:"earn_cooldown_seconds"`
	Inventory    []inventoryItem `json:"inventory"`
}

type accountStore interface {
	Close() error
	CreateUser(context.Context, string, string, string) (userRecord, error)
	UserByUsername(context.Context, string) (userRecord, bool, error)
	UserByID(context.Context, uint64) (userRecord, bool, error)
	CreateSession(context.Context, uint64, string, time.Time) error
	UserIDBySession(context.Context, string, time.Time) (uint64, bool, error)
	DeleteSession(context.Context, string) error
	Snapshot(context.Context, uint64) (accountSnapshot, error)
	Earn(context.Context, uint64, time.Time) (accountSnapshot, error)
	Purchase(context.Context, uint64, uint16) (accountSnapshot, error)
	ReconcileLegacyBalance(context.Context, uint64, uint64) (accountSnapshot, error)
	DeleteUser(context.Context, uint64) error
}

type boltStore struct{ db *bolt.DB }

func databasePath() string {
	if v := os.Getenv("DB_PATH"); v != "" {
		return v
	}
	return "coin-lab.db"
}

func newBoltStore(path string) (*boltStore, error) {
	db, err := bolt.Open(path, 0o600, &bolt.Options{Timeout: time.Second})
	if err != nil {
		return nil, err
	}
	s := &boltStore{db: db}
	if err := db.Update(func(tx *bolt.Tx) error {
		for _, name := range [][]byte{bucketUsers, bucketUsernames, bucketSessions, bucketInventory} {
			if _, err := tx.CreateBucketIfNotExists(name); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

func (s *boltStore) Close() error { return s.db.Close() }

func (s *boltStore) CreateUser(ctx context.Context, username, salt, hash string) (userRecord, error) {
	if err := ctx.Err(); err != nil {
		return userRecord{}, err
	}
	var created userRecord
	err := s.db.Update(func(tx *bolt.Tx) error {
		users := tx.Bucket(bucketUsers)
		names := tx.Bucket(bucketUsernames)
		key := normalizeUsername(username)
		if names.Get([]byte(key)) != nil {
			return errUsernameTaken
		}
		id, err := users.NextSequence()
		if err != nil {
			return err
		}
		created = userRecord{
			ID: id, Username: username, UsernameKey: key,
			PasswordSalt: salt, PasswordHash: hash,
			Balance: webStartingCoins, CreatedAt: time.Now().UTC().Unix(),
		}
		encoded, err := json.Marshal(created)
		if err != nil {
			return err
		}
		if err := users.Put(u64key(id), encoded); err != nil {
			return err
		}
		return names.Put([]byte(key), u64key(id))
	})
	return created, err
}

func (s *boltStore) UserByUsername(ctx context.Context, username string) (userRecord, bool, error) {
	var u userRecord
	err := s.db.View(func(tx *bolt.Tx) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		id := tx.Bucket(bucketUsernames).Get([]byte(normalizeUsername(username)))
		if id == nil {
			return nil
		}
		return decodeJSON(tx.Bucket(bucketUsers).Get(id), &u)
	})
	return u, u.ID != 0, err
}

func (s *boltStore) UserByID(ctx context.Context, id uint64) (userRecord, bool, error) {
	var u userRecord
	err := s.db.View(func(tx *bolt.Tx) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		return decodeJSON(tx.Bucket(bucketUsers).Get(u64key(id)), &u)
	})
	return u, u.ID != 0, err
}

func (s *boltStore) CreateSession(ctx context.Context, userID uint64, token string, expires time.Time) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		record, _ := json.Marshal(sessionRecord{UserID: userID, ExpiresAt: expires.Unix()})
		return tx.Bucket(bucketSessions).Put(tokenKey(token), record)
	})
}

func (s *boltStore) UserIDBySession(ctx context.Context, token string, now time.Time) (uint64, bool, error) {
	var sess sessionRecord
	err := s.db.View(func(tx *bolt.Tx) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		return decodeJSON(tx.Bucket(bucketSessions).Get(tokenKey(token)), &sess)
	})
	if err != nil || sess.UserID == 0 || sess.ExpiresAt <= now.Unix() {
		return 0, false, err
	}
	return sess.UserID, true, nil
}

func (s *boltStore) DeleteSession(ctx context.Context, token string) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		return tx.Bucket(bucketSessions).Delete(tokenKey(token))
	})
}

func (s *boltStore) Snapshot(ctx context.Context, userID uint64) (accountSnapshot, error) {
	var out accountSnapshot
	err := s.db.View(func(tx *bolt.Tx) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		u, err := loadUser(tx, userID)
		if err != nil {
			return err
		}
		out, err = snapshotInTx(tx, u)
		return err
	})
	return out, err
}

func (s *boltStore) Earn(ctx context.Context, userID uint64, now time.Time) (accountSnapshot, error) {
	var out accountSnapshot
	err := s.db.Update(func(tx *bolt.Tx) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		u, err := loadUser(tx, userID)
		if err != nil {
			return err
		}
		if now.Unix() < u.NextEarnAt {
			return errEarnCooldown
		}
		if u.Balance > maxLabBalance-earnReward {
			return errors.New("balance limit reached")
		}
		u.Balance += earnReward
		u.NextEarnAt = now.Add(earnCooldown).Unix()
		if err := saveUser(tx, u); err != nil {
			return err
		}
		out, err = snapshotInTx(tx, u)
		return err
	})
	return out, err
}

func (s *boltStore) Purchase(ctx context.Context, userID uint64, productID uint16) (accountSnapshot, error) {
	p, ok := productByID(productID)
	if !ok {
		return accountSnapshot{}, errUnknownProduct
	}
	var out accountSnapshot
	err := s.db.Update(func(tx *bolt.Tx) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		u, err := loadUser(tx, userID)
		if err != nil {
			return err
		}
		// Security invariant: both the balance and price originate on the server,
		// and the debit plus inventory write happen in one database transaction.
		if u.Balance < p.Price {
			return errInsufficientFunds
		}
		u.Balance -= p.Price
		if err := saveUser(tx, u); err != nil {
			return err
		}
		invRoot := tx.Bucket(bucketInventory)
		inv, err := invRoot.CreateBucketIfNotExists(u64key(userID))
		if err != nil {
			return err
		}
		key := u16key(productID)
		count := decodeU64(inv.Get(key)) + 1
		if err := inv.Put(key, u64key(count)); err != nil {
			return err
		}
		out, err = snapshotInTx(tx, u)
		return err
	})
	return out, err
}

func (s *boltStore) ReconcileLegacyBalance(ctx context.Context, userID, reported uint64) (accountSnapshot, error) {
	if reported > maxLabBalance {
		return accountSnapshot{}, errors.New("reported balance out of range")
	}
	var out accountSnapshot
	err := s.db.Update(func(tx *bolt.Tx) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		u, err := loadUser(tx, userID)
		if err != nil {
			return err
		}
		// INTENTIONAL LAB VULNERABILITY (CWE-602): an obsolete recovery API
		// promotes an unsigned client snapshot into authoritative server state.
		// A MITM can rewrite reported before this transaction executes.
		if reported > u.Balance {
			u.Balance = reported
			if err := saveUser(tx, u); err != nil {
				return err
			}
		}
		out, err = snapshotInTx(tx, u)
		return err
	})
	return out, err
}

func (s *boltStore) DeleteUser(ctx context.Context, userID uint64) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		u, err := loadUser(tx, userID)
		if err != nil {
			return err
		}
		if err := tx.Bucket(bucketUsers).Delete(u64key(userID)); err != nil {
			return err
		}
		if err := tx.Bucket(bucketUsernames).Delete([]byte(u.UsernameKey)); err != nil {
			return err
		}
		_ = tx.Bucket(bucketInventory).DeleteBucket(u64key(userID))
		sessions := tx.Bucket(bucketSessions)
		var stale [][]byte
		_ = sessions.ForEach(func(k, v []byte) error {
			var sess sessionRecord
			if json.Unmarshal(v, &sess) == nil && sess.UserID == userID {
				stale = append(stale, append([]byte(nil), k...))
			}
			return nil
		})
		for _, key := range stale {
			if err := sessions.Delete(key); err != nil {
				return err
			}
		}
		return nil
	})
}

func productByID(id uint16) (product, bool) {
	for _, p := range catalog {
		if p.ID == id {
			return p, true
		}
	}
	return product{}, false
}

func loadUser(tx *bolt.Tx, id uint64) (userRecord, error) {
	var u userRecord
	if err := decodeJSON(tx.Bucket(bucketUsers).Get(u64key(id)), &u); err != nil {
		return userRecord{}, err
	}
	if u.ID == 0 {
		return userRecord{}, errUnauthenticated
	}
	return u, nil
}

func saveUser(tx *bolt.Tx, u userRecord) error {
	data, err := json.Marshal(u)
	if err != nil {
		return err
	}
	return tx.Bucket(bucketUsers).Put(u64key(u.ID), data)
}

func snapshotInTx(tx *bolt.Tx, u userRecord) (accountSnapshot, error) {
	out := accountSnapshot{
		ID: u.ID, Username: u.Username, Balance: u.Balance, NextEarnAt: u.NextEarnAt,
		EarnReward: earnReward, EarnCooldown: int64(earnCooldown / time.Second),
		Inventory: []inventoryItem{},
	}
	inv := tx.Bucket(bucketInventory).Bucket(u64key(u.ID))
	if inv == nil {
		return out, nil
	}
	err := inv.ForEach(func(k, v []byte) error {
		if len(k) != 2 {
			return nil
		}
		p, ok := productByID(binary.BigEndian.Uint16(k))
		if ok {
			out.Inventory = append(out.Inventory, inventoryItem{Product: p, Count: decodeU64(v)})
		}
		return nil
	})
	sort.Slice(out.Inventory, func(i, j int) bool { return out.Inventory[i].Product.ID < out.Inventory[j].Product.ID })
	return out, err
}

func u64key(v uint64) []byte {
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, v)
	return buf
}

func u16key(v uint16) []byte {
	buf := make([]byte, 2)
	binary.BigEndian.PutUint16(buf, v)
	return buf
}

func decodeU64(v []byte) uint64 {
	if len(v) != 8 {
		return 0
	}
	return binary.BigEndian.Uint64(v)
}

func decodeJSON(data []byte, target any) error {
	if data == nil {
		return nil
	}
	if err := json.Unmarshal(data, target); err != nil {
		return fmt.Errorf("decode database record: %w", err)
	}
	return nil
}

var _ accountStore = (*boltStore)(nil)
