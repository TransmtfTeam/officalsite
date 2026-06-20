package server

import (
	"io/fs"
	"net/http"
)

// spaAssetsHandler serves the hashed, immutable Vite build assets mounted at
// /app/assets/*. Filenames are content-hashed so they can be cached forever.
func (h *Handler) spaAssetsHandler() http.Handler {
	fileServer := http.FileServer(http.FS(h.appDist))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
		// Strip the /app prefix so "/app/assets/x" resolves to "assets/x" in dist.
		http.StripPrefix("/app", fileServer).ServeHTTP(w, r)
	})
}

// serveSPAShell returns the built index.html for any human-facing route that is
// not matched by a more specific (API / protocol / asset) pattern. React then
// renders the route client-side. index.html is never cached so deploys take
// effect immediately while the hashed assets stay cached.
func (h *Handler) serveSPAShell(w http.ResponseWriter, r *http.Request) {
	data, err := fs.ReadFile(h.appDist, "index.html")
	if err != nil {
		http.Error(w, "前端尚未构建（web/app/dist/index.html 缺失）", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	_, _ = w.Write(data)
}
