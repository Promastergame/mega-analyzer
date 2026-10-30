package main

import (
	"embed"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	sessionCookieName = "coin_lab_session"
	sessionLifetime   = 24 * time.Hour
	maxRequestBody    = 16 << 10
)

//go:embed web/*
var webAssets embed.FS

type webServer struct {
	store accountStore
	now   func() time.Time
}

func newWebServer(store accountStore) *webServer {
	return &webServer{store: store, now: time.Now}
}

func (s *webServer) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/register", s.handleRegister)
	mux.HandleFunc("POST /api/login", s.handleLogin)
	mux.HandleFunc("POST /api/logout", s.handleLogout)
	mux.HandleFunc("GET /api/me", s.handleMe)
	mux.HandleFunc("GET /api/shop", s.handleShop)
	mux.HandleFunc("POST /api/earn", s.handleEarn)
	mux.HandleFunc("POST /api/buy", s.handleBuy)
	mux.HandleFunc("POST /api/wallet/reconcile", s.handleLegacyReconcile)
	mux.HandleFunc("DELETE /api/account", s.handleDeleteAccount)

	static, err := fs.Sub(webAssets, "web")
	if err != nil {
		panic(err)
	}
	mux.Handle("GET /", http.FileServer(http.FS(static)))
	return s.securityHeaders(mux)
}

type credentialsRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

func (s *webServer) handleRegister(w http.ResponseWriter, r *http.Request) {
	if !allowStateChange(w, r) {
		return
	}
	var req credentialsRequest
	if err := decodeJSONBody(w, r, &req); err != nil {
		writeAPIError(w, http.StatusBadRequest, "invalid_request", "Проверьте поля формы.")
		return
	}
	req.Username = strings.TrimSpace(req.Username)
	if err := validateUsername(req.Username); err != nil {
		writeAPIError(w, http.StatusBadRequest, "invalid_username", "Имя: 3–24 символа, только буквы, цифры, _ и -.")
		return
	}
	if err := validatePassword(req.Password); err != nil {
		writeAPIError(w, http.StatusBadRequest, "invalid_password", "Пароль должен быть длиной от 8 до 128 символов.")
		return
	}
	salt, hash, err := hashPassword(req.Password)
	if err != nil {
		writeAPIError(w, http.StatusInternalServerError, "internal_error", "Не удалось создать аккаунт.")
		return
	}
	u, err := s.store.CreateUser(r.Context(), req.Username, salt, hash)
	if errors.Is(err, errUsernameTaken) {
		writeAPIError(w, http.StatusConflict, "username_taken", "Это имя уже занято.")
		return
	}
	if err != nil {
		writeAPIError(w, http.StatusInternalServerError, "internal_error", "Не удалось создать аккаунт.")
		return
	}
	if err := s.startSession(w, r, u.ID); err != nil {
		writeAPIError(w, http.StatusInternalServerError, "internal_error", "Не удалось открыть сессию.")
		return
	}
	snapshot, err := s.store.Snapshot(r.Context(), u.ID)
	if err != nil {
		writeAPIError(w, http.StatusInternalServerError, "internal_error", "Не удалось загрузить профиль.")
		return
	}
	writeJSONResponse(w, http.StatusCreated, snapshot)
}

func (s *webServer) handleLogin(w http.ResponseWriter, r *http.Request) {
	if !allowStateChange(w, r) {
		return
	}
	var req credentialsRequest
	if err := decodeJSONBody(w, r, &req); err != nil {
		writeAPIError(w, http.StatusBadRequest, "invalid_request", "Проверьте поля формы.")
		return
	}
	u, ok, err := s.store.UserByUsername(r.Context(), req.Username)
	if err != nil {
		writeAPIError(w, http.StatusInternalServerError, "internal_error", "Не удалось войти.")
		return
	}
	if !ok || !verifyPassword(req.Password, u.PasswordSalt, u.PasswordHash) {
		writeAPIError(w, http.StatusUnauthorized, "invalid_login", "Неверное имя или пароль.")
		return
	}
	if err := s.startSession(w, r, u.ID); err != nil {
		writeAPIError(w, http.StatusInternalServerError, "internal_error", "Не удалось открыть сессию.")
		return
	}
	snapshot, err := s.store.Snapshot(r.Context(), u.ID)
	if err != nil {
		writeAPIError(w, http.StatusInternalServerError, "internal_error", "Не удалось загрузить профиль.")
		return
	}
	writeJSONResponse(w, http.StatusOK, snapshot)
}

func (s *webServer) handleLogout(w http.ResponseWriter, r *http.Request) {
	if !allowStateChange(w, r) {
		return
	}
	if cookie, err := r.Cookie(sessionCookieName); err == nil {
		_ = s.store.DeleteSession(r.Context(), cookie.Value)
	}
	clearSessionCookie(w)
	w.WriteHeader(http.StatusNoContent)
}

func (s *webServer) handleMe(w http.ResponseWriter, r *http.Request) {
	userID, ok := s.requireUser(w, r)
	if !ok {
		return
	}
	snapshot, err := s.store.Snapshot(r.Context(), userID)
	if err != nil {
		writeAPIError(w, http.StatusInternalServerError, "internal_error", "Не удалось загрузить профиль.")
		return
	}
	writeJSONResponse(w, http.StatusOK, snapshot)
}

func (s *webServer) handleShop(w http.ResponseWriter, _ *http.Request) {
	writeJSONResponse(w, http.StatusOK, map[string]any{"products": catalog})
}

func (s *webServer) handleEarn(w http.ResponseWriter, r *http.Request) {
	if !allowStateChange(w, r) {
		return
	}
	userID, ok := s.requireUser(w, r)
	if !ok {
		return
	}
	snapshot, err := s.store.Earn(r.Context(), userID, s.now().UTC())
	if errors.Is(err, errEarnCooldown) {
		current, snapErr := s.store.Snapshot(r.Context(), userID)
		if snapErr != nil {
			writeAPIError(w, http.StatusInternalServerError, "internal_error", "Не удалось проверить таймер.")
			return
		}
		writeJSONResponse(w, http.StatusTooManyRequests, map[string]any{
			"error": "earn_cooldown", "message": "Узел еще перезаряжается.", "next_earn_at": current.NextEarnAt,
		})
		return
	}
	if err != nil {
		writeAPIError(w, http.StatusInternalServerError, "internal_error", "Не удалось начислить монеты.")
		return
	}
	writeJSONResponse(w, http.StatusOK, snapshot)
}

type buyRequest struct {
	ItemID uint16 `json:"item_id"`
}

func (s *webServer) handleBuy(w http.ResponseWriter, r *http.Request) {
	if !allowStateChange(w, r) {
		return
	}
	userID, ok := s.requireUser(w, r)
	if !ok {
		return
	}
	var req buyRequest
	if err := decodeJSONBody(w, r, &req); err != nil || req.ItemID == 0 {
		writeAPIError(w, http.StatusBadRequest, "invalid_request", "Укажите товар из каталога.")
		return
	}
	snapshot, err := s.store.Purchase(r.Context(), userID, req.ItemID)
	switch {
	case errors.Is(err, errInsufficientFunds):
		writeAPIError(w, http.StatusPaymentRequired, "insufficient_funds", "Недостаточно монет.")
		return
	case errors.Is(err, errUnknownProduct):
		writeAPIError(w, http.StatusNotFound, "unknown_product", "Товар не найден.")
		return
	case err != nil:
		writeAPIError(w, http.StatusInternalServerError, "internal_error", "Покупка не завершена.")
		return
	}
	writeJSONResponse(w, http.StatusOK, snapshot)
}

type reconcileRequest struct {
	ReportedBalance uint64 `json:"reported_balance"`
}

func (s *webServer) handleLegacyReconcile(w http.ResponseWriter, r *http.Request) {
	if !allowStateChange(w, r) {
		return
	}
	userID, ok := s.requireUser(w, r)
	if !ok {
		return
	}
	var req reconcileRequest
	if err := decodeJSONBody(w, r, &req); err != nil {
		writeAPIError(w, http.StatusBadRequest, "invalid_request", "Некорректный снимок кошелька.")
		return
	}
	snapshot, err := s.store.ReconcileLegacyBalance(r.Context(), userID, req.ReportedBalance)
	if err != nil {
		writeAPIError(w, http.StatusBadRequest, "invalid_snapshot", "Снимок кошелька отклонен.")
		return
	}
	log.Printf("coin-lab: legacy wallet reconciliation user=%d reported_balance=%d resulting_balance=%d",
		userID, req.ReportedBalance, snapshot.Balance)
	writeJSONResponse(w, http.StatusOK, snapshot)
}

type deleteAccountRequest struct {
	Password string `json:"password"`
}

func (s *webServer) handleDeleteAccount(w http.ResponseWriter, r *http.Request) {
	if !allowStateChange(w, r) {
		return
	}
	userID, ok := s.requireUser(w, r)
	if !ok {
		return
	}
	var req deleteAccountRequest
	if err := decodeJSONBody(w, r, &req); err != nil {
		writeAPIError(w, http.StatusBadRequest, "invalid_request", "Введите пароль для подтверждения.")
		return
	}
	u, exists, err := s.store.UserByID(r.Context(), userID)
	if err != nil || !exists {
		writeAPIError(w, http.StatusUnauthorized, "unauthenticated", "Сессия недействительна.")
		return
	}
	if !verifyPassword(req.Password, u.PasswordSalt, u.PasswordHash) {
		writeAPIError(w, http.StatusUnauthorized, "invalid_password", "Неверный пароль.")
		return
	}
	if err := s.store.DeleteUser(r.Context(), userID); err != nil {
		writeAPIError(w, http.StatusInternalServerError, "internal_error", "Не удалось удалить аккаунт.")
		return
	}
	clearSessionCookie(w)
	w.WriteHeader(http.StatusNoContent)
}

func (s *webServer) startSession(w http.ResponseWriter, r *http.Request, userID uint64) error {
	token, err := randomToken()
	if err != nil {
		return err
	}
	if err := s.store.CreateSession(r.Context(), userID, token, s.now().Add(sessionLifetime)); err != nil {
		return err
	}
	http.SetCookie(w, &http.Cookie{
		Name: sessionCookieName, Value: token, Path: "/", MaxAge: int(sessionLifetime.Seconds()),
		HttpOnly: true, SameSite: http.SameSiteStrictMode,
	})
	return nil
}

func (s *webServer) requireUser(w http.ResponseWriter, r *http.Request) (uint64, bool) {
	cookie, err := r.Cookie(sessionCookieName)
	if err != nil || cookie.Value == "" {
		writeAPIError(w, http.StatusUnauthorized, "unauthenticated", "Сначала войдите в аккаунт.")
		return 0, false
	}
	userID, ok, err := s.store.UserIDBySession(r.Context(), cookie.Value, s.now())
	if err != nil {
		writeAPIError(w, http.StatusInternalServerError, "internal_error", "Не удалось проверить сессию.")
		return 0, false
	}
	if !ok {
		clearSessionCookie(w)
		writeAPIError(w, http.StatusUnauthorized, "unauthenticated", "Сессия истекла.")
		return 0, false
	}
	return userID, true
}

func allowStateChange(w http.ResponseWriter, r *http.Request) bool {
	if ct := r.Header.Get("Content-Type"); ct != "" && !strings.HasPrefix(ct, "application/json") {
		writeAPIError(w, http.StatusUnsupportedMediaType, "json_required", "Ожидается JSON-запрос.")
		return false
	}
	origin := r.Header.Get("Origin")
	if origin == "" {
		return true
	}
	u, err := url.Parse(origin)
	if err != nil || !strings.EqualFold(u.Host, r.Host) {
		writeAPIError(w, http.StatusForbidden, "origin_rejected", "Источник запроса отклонен.")
		return false
	}
	return true
}

func decodeJSONBody(w http.ResponseWriter, r *http.Request, target any) error {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBody)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return errors.New("request must contain one JSON value")
	}
	return nil
}

func clearSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name: sessionCookieName, Value: "", Path: "/", MaxAge: -1,
		HttpOnly: true, SameSite: http.SameSiteStrictMode,
	})
}

func writeJSONResponse(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func writeAPIError(w http.ResponseWriter, status int, code, message string) {
	writeJSONResponse(w, status, map[string]string{"error": code, "message": message})
}

func (s *webServer) securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", "default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
		if strings.HasPrefix(r.URL.Path, "/api/") {
			w.Header().Set("Cache-Control", "no-store")
		}
		next.ServeHTTP(w, r)
	})
}
