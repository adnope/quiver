package api

import (
	"bytes"
	"errors"
	"io"
	"io/fs"
	"net/http"
	"path"
	"strings"
	"time"
)

func FrontendHandler(assets fs.FS) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if isReservedBackendPath(r.URL.Path) {
			http.NotFound(w, r)
			return
		}

		name := strings.TrimPrefix(path.Clean("/"+r.URL.Path), "/")
		if name == "." || name == "" {
			serveFrontendFile(w, r, assets, "index.html")
			return
		}

		if serveFrontendFile(w, r, assets, name) {
			return
		}
		if path.Ext(name) != "" {
			http.NotFound(w, r)
			return
		}
		serveFrontendFile(w, r, assets, "index.html")
	})
}

func isReservedBackendPath(requestPath string) bool {
	return requestPath == "/health" ||
		requestPath == "/metrics" ||
		strings.HasPrefix(requestPath, "/api/")
}

func serveFrontendFile(
	w http.ResponseWriter,
	r *http.Request,
	assets fs.FS,
	name string,
) bool {
	file, err := assets.Open(name)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return false
		}
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return true
	}
	defer file.Close()

	stat, err := file.Stat()
	if err != nil {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return true
	}
	if stat.IsDir() {
		return false
	}

	data, err := io.ReadAll(file)
	if err != nil {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return true
	}
	modTime := stat.ModTime()
	if modTime.IsZero() {
		modTime = time.Unix(0, 0)
	}
	http.ServeContent(w, r, stat.Name(), modTime, bytes.NewReader(data))
	return true
}
