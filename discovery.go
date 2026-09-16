package main

import (
	"bytes"
	"embed"
	"net/http"
	"time"
)

//go:embed discovery/*
var discoveryFiles embed.FS

// Discovery is public and independent of sessions or database availability.
func registerDiscoveryRoutes(mux *http.ServeMux) {
	for _, asset := range []struct{ path, file, contentType string }{
		{"/.well-known/api-catalog", "api-catalog.json", `application/linkset+json; profile="https://www.rfc-editor.org/info/rfc9727"`},
		{"/openapi.json", "openapi.json", "application/json"},
		{"/llms.txt", "llms.txt", "text/plain; charset=utf-8"},
	} {
		data, err := discoveryFiles.ReadFile("discovery/" + asset.file)
		if err != nil {
			panic(err)
		}
		contentType, name := asset.contentType, asset.file
		mux.HandleFunc(asset.path, func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodGet && r.Method != http.MethodHead {
				w.Header().Set("Allow", "GET, HEAD")
				http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
				return
			}
			w.Header().Set("Content-Type", contentType)
			w.Header().Set("Cache-Control", "public, max-age=3600")
			w.Header().Set("Link", `</.well-known/api-catalog>; rel="api-catalog", </openapi.json>; rel="service-desc", </llms.txt>; rel="service-doc"`)
			http.ServeContent(w, r, name, time.Time{}, bytes.NewReader(data))
		})
	}
}
