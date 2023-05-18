package http

import (
	"net/http"

	"github.com/gatecheckdev/gatecheck/api/core"
	"github.com/gatecheckdev/gatecheck/ui"
	"github.com/labstack/echo"
)

func NewRouter(app core.App) (*echo.Echo, error) {
	e := echo.New()

	serveStaticUI(app, e)

	e.Start(app.Config.Addr)

	return e, nil
}

func serveStaticUI(app core.App, e *echo.Echo) {
	assetHandler := http.FileServer(ui.GetFileSystem(true))
	e.GET("/", echo.WrapHandler(assetHandler))
}
