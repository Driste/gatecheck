package ui

import (
	"embed"
	"io/fs"
	"log"
	"net/http"
	"os"
)

//go:embed all:dist
var embededFiles embed.FS

func GetFileSystem(useOS bool) http.FileSystem {
	if useOS {
		log.Print("using live mode")
		return http.FS(os.DirFS("dist"))
	}

	log.Print("using embed mode")
	fsys, err := fs.Sub(embededFiles, "dist")
	if err != nil {
		panic(err)
	}

	return http.FS(fsys)
}
