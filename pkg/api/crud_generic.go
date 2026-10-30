package api

import (
	"fmt"
	"net/http"
	"strings"
)

// ═══════════════════════════════════════════════════════════════════════════════
// GENERIC CRUD — eliminates copy-paste between Web / Binzap / ML rule handlers.
// Behavior (status codes + error codes) is preserved; only human-readable
// messages are unified. Go 1.18+ type parameters, zero external deps.
// ═══════════════════════════════════════════════════════════════════════════════

type crudStore[T any] struct {
	kind   string // e.g. "web rule", "binzap rule", "ml pattern"
	list   func() []T
	add    func(T) error
	update func(string, T) error
	remove func(string) error
	getID  func(T) string
	setID  func(*T, string)
}

func handleCollection[T any](w http.ResponseWriter, r *http.Request, s crudStore[T]) {
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, s.list())
	case http.MethodPost:
		var v T
		if err := decodeJSONBody(r, defaultMaxJSONBytes, &v); err != nil {
			writeProblem(w, r, http.StatusBadRequest, "ERR_INVALID_PAYLOAD", "Invalid JSON Payload",
				fmt.Sprintf("Failed to decode %s payload: %v", s.kind, err),
				"Verify fields match the specification schema.", nil)
			return
		}
		if s.getID(v) == "" {
			writeProblem(w, r, http.StatusBadRequest, "ERR_INVALID_PAYLOAD", "Missing Rule ID",
				fmt.Sprintf("The %s must contain a unique 'id'.", s.kind),
				"Add a valid 'id' value.", nil)
			return
		}
		if err := s.add(v); err != nil {
			if strings.Contains(err.Error(), "already exists") {
				writeProblem(w, r, http.StatusConflict, "ERR_RULE_DUPLICATE", "Rule Already Exists",
					err.Error(), "Choose a different ID or PUT to update.", nil)
				return
			}
			writeProblem(w, r, http.StatusInternalServerError, "ERR_INTERNAL", "Storage Error",
				err.Error(), "Ensure storage files are writable.", nil)
			return
		}
		writeJSON(w, http.StatusCreated, v)
	default:
		writeProblem(w, r, http.StatusMethodNotAllowed, "ERR_METHOD_NOT_ALLOWED", "Method Not Allowed",
			"Endpoint only supports GET and POST.", "GET to list or POST to create.", nil)
	}
}

func handleSingle[T any](w http.ResponseWriter, r *http.Request, prefix string, s crudStore[T]) {
	id := strings.TrimPrefix(r.URL.Path, prefix)
	if id == "" {
		writeProblem(w, r, http.StatusBadRequest, "ERR_INVALID_PAYLOAD", "Missing ID",
			"ID is required in URI path.", fmt.Sprintf("Call %s<id>.", prefix), nil)
		return
	}
	switch r.Method {
	case http.MethodPut:
		var v T
		if err := decodeJSONBody(r, defaultMaxJSONBytes, &v); err != nil {
			writeProblem(w, r, http.StatusBadRequest, "ERR_INVALID_PAYLOAD", "Invalid JSON Payload",
				err.Error(), "Verify body matches the schema.", nil)
			return
		}
		s.setID(&v, id)
		if err := s.update(id, v); err != nil {
			if strings.Contains(err.Error(), "not found") {
				writeProblem(w, r, http.StatusNotFound, "ERR_RULE_NOT_FOUND", "Rule Not Found",
					err.Error(), "Create it first with POST.", nil)
				return
			}
			writeProblem(w, r, http.StatusInternalServerError, "ERR_INTERNAL", "Storage Error",
				err.Error(), "Check storage availability.", nil)
			return
		}
		writeJSON(w, http.StatusOK, v)
	case http.MethodDelete:
		if err := s.remove(id); err != nil {
			if strings.Contains(err.Error(), "not found") {
				writeProblem(w, r, http.StatusNotFound, "ERR_RULE_NOT_FOUND", "Rule Not Found",
					err.Error(), "No entry matches this identifier.", nil)
				return
			}
			writeProblem(w, r, http.StatusInternalServerError, "ERR_INTERNAL", "Storage Error",
				err.Error(), "Check storage availability.", nil)
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"message": "Deleted successfully"})
	default:
		writeProblem(w, r, http.StatusMethodNotAllowed, "ERR_METHOD_NOT_ALLOWED", "Method Not Allowed",
			"Only PUT and DELETE are allowed here.", "PUT to update or DELETE to remove.", nil)
	}
}
