package main

import (
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"strings"
	"unicode"
	"unicode/utf8"
)

const (
	passwordIterations = 210_000
	passwordKeyLength  = 32
)

func normalizeUsername(username string) string {
	return strings.ToLower(strings.TrimSpace(username))
}

func validateUsername(username string) error {
	username = strings.TrimSpace(username)
	count := utf8.RuneCountInString(username)
	if count < 3 || count > 24 {
		return errors.New("username must contain 3 to 24 characters")
	}
	for _, r := range username {
		if !unicode.IsLetter(r) && !unicode.IsNumber(r) && r != '_' && r != '-' {
			return errors.New("username may contain letters, numbers, _ and -")
		}
	}
	return nil
}

func validatePassword(password string) error {
	if len(password) < 8 || len(password) > 128 {
		return errors.New("password must contain 8 to 128 bytes")
	}
	return nil
}

func hashPassword(password string) (saltHex, hashHex string, err error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", "", err
	}
	key, err := pbkdf2.Key(sha256.New, password, salt, passwordIterations, passwordKeyLength)
	if err != nil {
		return "", "", err
	}
	return hex.EncodeToString(salt), hex.EncodeToString(key), nil
}

func verifyPassword(password, saltHex, hashHex string) bool {
	salt, err := hex.DecodeString(saltHex)
	if err != nil {
		return false
	}
	want, err := hex.DecodeString(hashHex)
	if err != nil || len(want) != passwordKeyLength {
		return false
	}
	got, err := pbkdf2.Key(sha256.New, password, salt, passwordIterations, len(want))
	if err != nil {
		return false
	}
	return subtle.ConstantTimeCompare(got, want) == 1
}

func randomToken() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}

func tokenKey(token string) []byte {
	sum := sha256.Sum256([]byte(token))
	return sum[:]
}
