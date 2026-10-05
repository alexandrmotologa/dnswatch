package server

import (
	"embed"
	"io/fs"
	"net/http"
	"strings"
)

//go:embed all:dist
var staticAssets embed.FS

// RegisterStaticRoutes mounts the embedded static assets onto the router.
func (s *Server) RegisterStaticRoutes() {
	distFS, err := fs.Sub(staticAssets, "dist")
	if err != nil {
		s.router.Get("/*", func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "Embedded UI assets not available", http.StatusInternalServerError)
		})
		return
	}

	fileServer := http.FileServer(http.FS(distFS))

	s.router.Get("/*", func(w http.ResponseWriter, r *http.Request) {
		path := strings.TrimPrefix(r.URL.Path, "/")
		if path == "" {
			path = "index.html"
		}

		// Try to open file directly
		f, err := distFS.Open(path)
		if err == nil {
			_ = f.Close()
			fileServer.ServeHTTP(w, r)
			return
		}

		// Fallback to index.html for Single Page Application routing
		indexFile, err := distFS.Open("index.html")
		if err == nil {
			_ = indexFile.Close()
			r.URL.Path = "/"
			fileServer.ServeHTTP(w, r)
			return
		}

		http.NotFound(w, r)
	})
}
