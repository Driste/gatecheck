package cmd

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/gatecheckdev/gatecheck/pkg/artifact"
	"github.com/gatecheckdev/gatecheck/pkg/epss"
	"github.com/spf13/cobra"
)

func NewEPSSCmd(service EPSSService) *cobra.Command {

	var EPSSCmd = &cobra.Command{
		Use:   "epss <Grype|CycloneDX FILE>",
		Short: "Query first.org for Exploit Prediction Scoring System (EPSS)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			// var grypeScan artifact.GrypeScanReport
			// var cyclonedxScan artifact.CyclonedxSbomReport

			f, err := os.Open(args[0])
			if err != nil {
				return fmt.Errorf("%w: %v", ErrorFileAccess, err)
			}

			CVEs, err := GrypeEPSSReport(f)
			if err != nil {
				return err
			}

			data, err := service.Get(CVEs)
			if err != nil {
				return fmt.Errorf("%w: %s", ErrorAPI, err)
			}

			cmd.Println(epss.Sprint(data))

			return nil
		},
	}

	return EPSSCmd
}

func GrypeEPSSReport(f *os.File) ([]epss.CVE, error) {
	var grypeScan artifact.GrypeScanReport

	if err := json.NewDecoder(f).Decode(&grypeScan); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrorEncoding, err)
	}

	CVEs := make([]epss.CVE, len(grypeScan.Matches))

	for i, match := range grypeScan.Matches {
		CVEs[i] = epss.CVE{
			ID:       match.Vulnerability.ID,
			Severity: match.Vulnerability.Severity,
			Link:     match.Vulnerability.DataSource,
		}
	}

	return CVEs, nil
}
