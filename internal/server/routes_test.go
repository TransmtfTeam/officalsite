package server

import (
	"net/http"
	"os"
	"testing"
)

// TestRoutesNoPatternConflict registers every route on a fresh ServeMux exactly
// as production does. Go's ServeMux panics at registration time on conflicting
// patterns (e.g. a method-less "/api/v1/" vs "GET /"), so this reproduces that
// startup failure without needing a database or running New's goroutines.
func TestRoutesNoPatternConflict(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("route registration panicked (pattern conflict): %v", r)
		}
	}()
	h := &Handler{appDist: os.DirFS(".")}
	static := http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})
	_ = h.routes(static)
}
