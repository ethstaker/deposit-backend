package middleware

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func discardLogger() *slog.Logger {
	return slog.New(slog.DiscardHandler)
}

func call(t *testing.T, mw Middleware, pathKey, pathValue string, setPath bool) *httptest.ResponseRecorder {
	t.Helper()

	nextCalled := false
	next := http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		nextCalled = true
	})

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	if setPath {
		req.SetPathValue(pathKey, pathValue)
	}

	rec := httptest.NewRecorder()
	mw.ServeHTTP(next).ServeHTTP(rec, req)

	if nextCalled {
		t.Fatal("next handler was called")
	}
	return rec
}

func assertStatusAndBody(t *testing.T, rec *httptest.ResponseRecorder, status int, body string) {
	t.Helper()
	if rec.Code != status {
		t.Fatalf("status %d, want %d", rec.Code, status)
	}
	got, err := io.ReadAll(rec.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if !strings.Contains(string(got), body) {
		t.Fatalf("body %q, want it to contain %q", got, body)
	}
}

func TestExecutionAddressMiddleware(t *testing.T) {
	mw := NewExecutionAddressMiddleware(discardLogger())

	t.Run("missing execution address", func(t *testing.T) {
		rec := call(t, mw, string(ExecutionAddressContextKey), "", false)
		assertStatusAndBody(t, rec, http.StatusBadRequest, "Execution address is required")
	})

	t.Run("missing 0x prefix", func(t *testing.T) {
		rec := call(t, mw, string(ExecutionAddressContextKey), "1111111111111111111111111111111111111111", true)
		assertStatusAndBody(t, rec, http.StatusBadRequest, "Execution address must be 0x-prefixed")
	})

	t.Run("invalid length", func(t *testing.T) {
		rec := call(t, mw, string(ExecutionAddressContextKey), "0xaa", true)
		assertStatusAndBody(t, rec, http.StatusBadRequest, "Invalid execution address")
	})
}

func TestPubkeyMiddleware(t *testing.T) {
	mw := NewPubkeyMiddleware(discardLogger())

	t.Run("missing public key", func(t *testing.T) {
		rec := call(t, mw, string(PubkeyContextKey), "", false)
		assertStatusAndBody(t, rec, http.StatusBadRequest, "Pubkey is required")
	})

	t.Run("missing 0x prefix", func(t *testing.T) {
		rec := call(t, mw, string(PubkeyContextKey), "aa", true)
		assertStatusAndBody(t, rec, http.StatusBadRequest, "Public key must be 0x-prefixed")
	})

	t.Run("invalid length", func(t *testing.T) {
		rec := call(t, mw, string(PubkeyContextKey), "0xaa", true)
		assertStatusAndBody(t, rec, http.StatusBadRequest, "Invalid public key length")
	})
}
