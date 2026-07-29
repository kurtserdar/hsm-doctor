package server

import (
	"embed"
	"io/fs"
	"net/http"
	"strings"
)

// uiFS embeds the built web interface. The dist directory is produced by
// "make ui" (Vite build of web/); the committed placeholder keeps plain Go
// builds working without a Node toolchain.
//
//go:embed all:ui/dist
var uiFS embed.FS

// registerUI serves the embedded single-page application. Unknown paths
// fall back to index.html so client-side routing works on refresh.
func registerUI(mux *http.ServeMux) {
	sub, err := fs.Sub(uiFS, "ui/dist")
	if err != nil {
		// Embedded FS layout is fixed at compile time; this cannot fail in
		// a correctly built binary.
		panic(err)
	}
	fileServer := http.FileServer(http.FS(sub))

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/") {
			http.NotFound(w, r)
			return
		}
		path := strings.TrimPrefix(r.URL.Path, "/")
		if path != "" {
			if f, err := sub.Open(path); err == nil {
				_ = f.Close()
				fileServer.ServeHTTP(w, r)
				return
			}
		}
		// SPA fallback: let the client-side router handle the path.
		r.URL.Path = "/"
		fileServer.ServeHTTP(w, r)
	})
}
