package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHealthEndpoint(t *testing.T) {
	s := NewServer()
	s.RegisterStaticRoutes()

	req := httptest.NewRequest(http.MethodGet, "/api/health", nil)
	w := httptest.NewRecorder()

	s.Router().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", w.Code)
	}

	var data map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &data); err != nil {
		t.Fatalf("failed to parse json response: %v", err)
	}

	if data["status"] != "healthy" {
		t.Errorf("expected status=healthy, got %v", data["status"])
	}
}

func TestStaticAssetsServing(t *testing.T) {
	s := NewServer()
	s.RegisterStaticRoutes()

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()

	s.Router().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200 for root, got %d", w.Code)
	}

	body := w.Body.String()
	if len(body) == 0 {
		t.Errorf("expected non-empty index.html body")
	}
}
