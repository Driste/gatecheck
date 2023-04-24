package cmd

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/gatecheckdev/gatecheck/internal/log"
	"github.com/gatecheckdev/gatecheck/pkg/artifact"
	"github.com/gatecheckdev/gatecheck/pkg/epss"
	"github.com/spf13/cobra"
)

func NewEPSSCmd(service EPSSService) *cobra.Command {

	var EPSSCmd = &cobra.Command{
		Use:   "epss <Grype FILE>",
		Short: "Query first.org for Exploit Prediction Scoring System (EPSS)",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			initCache, _ := cmd.Flags().GetBool("init-cache")
			if initCache {
				log.Info("Caching the epss database")
				return service.CreateCache()
			}

			// offline, _ := cmd.Flags().GetBool("offline")
			// if offline {
			// 	log.Info("Switching the service to offline")
			// 	dirname, err := os.UserHomeDir()
			// 	if err != nil {
			// 		return fmt.Errorf("unable to get home directory: %v", err)
			// 	}
			// 	service = epss.NewEPSSOfflineService(nil, dirname)
			// }

			var grypeScan artifact.GrypeScanReport

			f, err := os.Open(args[0])
			if err != nil {
				return fmt.Errorf("%w: %v", ErrorFileAccess, err)
			}

			if err := json.NewDecoder(f).Decode(&grypeScan); err != nil {
				return fmt.Errorf("%w: %v", ErrorEncoding, err)
			}

			CVEs := make([]epss.CVE, len(grypeScan.Matches))

			for i, match := range grypeScan.Matches {
				CVEs[i] = epss.CVE{
					ID:       match.Vulnerability.ID,
					Severity: match.Vulnerability.Severity,
					Link:     match.Vulnerability.DataSource,
				}
			}

			data, err := service.Get(CVEs)
			if err != nil {
				return fmt.Errorf("%w: %s", ErrorAPI, err)
			}

			cmd.Println(epss.Sprint(data))
			return nil
		},
	}
	EPSSCmd.PersistentFlags().Bool("init-cache", false, "Has the epss service create a cache of the db")
	EPSSCmd.PersistentFlags().Bool("offline", false, "Sets the epss service to only use an offline cache of the db")

	return EPSSCmd
}
