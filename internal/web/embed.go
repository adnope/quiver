package web

import (
	"embed"
	"io/fs"
)

//go:embed dist
var embeddedDist embed.FS

func DistFS() fs.FS {
	dist, err := fs.Sub(embeddedDist, "dist")
	if err != nil {
		return emptyFS{}
	}
	return dist
}

type emptyFS struct{}

func (emptyFS) Open(name string) (fs.File, error) {
	return nil, fs.ErrNotExist
}
