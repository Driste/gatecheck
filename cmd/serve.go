package cmd

import (
	"log"
	"net/http"

	"github.com/gatecheckdev/gatecheck/api/core"
	gchttp "github.com/gatecheckdev/gatecheck/api/http"
	"github.com/spf13/cobra"
)

func NewServeCmd() *cobra.Command {
	var command = &cobra.Command{
		Use:     "serve",
		Short:   "Starts the web and api server",
		Example: "gatecheck serve ':8080'",
		RunE: func(cmd *cobra.Command, args []string) error {
			app := core.App{}

			router, _ := gchttp.NewRouter(app)

			httpConfig := &http.Server{
				Addr:    args[0],
				Handler: router,
			}

			serveErr := httpConfig.ListenAndServe()
			if serveErr != http.ErrServerClosed {
				log.Fatalln(serveErr)
			}
			return serveErr
		},
	}

	return command
}
