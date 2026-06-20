package server

import (
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// distFS loads the real built SPA output if present; skips the test otherwise.
func distFS(t *testing.T) fs.FS {
	t.Helper()
	dir := filepath.Join("..", "..", "web", "app", "dist")
	if _, err := os.Stat(filepath.Join(dir, "index.html")); err != nil {
		t.Skip("web/app/dist not built; run `pnpm build` in web/app")
	}
	return os.DirFS(dir)
}

func TestServeSPAShell(t *testing.T) {
	h := &Handler{appDist: distFS(t)}
	for _, path := range []string{"/", "/login", "/admin/users", "/oauth2/authorize", "/some/deep/spa/route"} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		rw := httptest.NewRecorder()
		h.serveSPAShell(rw, req)
		if rw.Code != http.StatusOK {
			t.Fatalf("%s: status = %d, want 200", path, rw.Code)
		}
		if ct := rw.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
			t.Fatalf("%s: content-type = %q, want text/html", path, ct)
		}
		if cc := rw.Header().Get("Cache-Control"); cc != "no-store" {
			t.Fatalf("%s: cache-control = %q, want no-store", path, cc)
		}
		body := rw.Body.String()
		if !strings.Contains(body, `id="root"`) {
			t.Fatalf("%s: shell body missing #root mount node", path)
		}
		if !strings.Contains(body, "/app/assets/") {
			t.Fatalf("%s: shell body missing hashed asset reference", path)
		}
	}
}

func TestSPAAssetsHandler(t *testing.T) {
	dist := distFS(t)
	// Find a hashed asset to request.
	var asset string
	_ = fs.WalkDir(dist, "assets", func(p string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() && asset == "" && (strings.HasSuffix(p, ".js") || strings.HasSuffix(p, ".css")) {
			asset = p
		}
		return nil
	})
	if asset == "" {
		t.Skip("no built assets found")
	}
	h := &Handler{appDist: dist}
	req := httptest.NewRequest(http.MethodGet, "/app/"+asset, nil)
	rw := httptest.NewRecorder()
	h.spaAssetsHandler().ServeHTTP(rw, req)
	if rw.Code != http.StatusOK {
		t.Fatalf("asset %s: status = %d, want 200", asset, rw.Code)
	}
	if cc := rw.Header().Get("Cache-Control"); !strings.Contains(cc, "immutable") {
		t.Fatalf("asset %s: cache-control = %q, want immutable", asset, cc)
	}
}
