package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/gatecheckdev/gatecheck/internal/log"
	"github.com/gatecheckdev/gatecheck/pkg/artifact"
	"github.com/gatecheckdev/gatecheck/pkg/export/defectdojo"
	"github.com/spf13/cobra"
)

func NewExportCmd(service DDExportService, timeout time.Duration, engagement defectdojo.EngagementQuery) *cobra.Command {
	var exportCmd = &cobra.Command{
		Use:   "export",
		Short: "Export a report to a target location",
	}

	var defectDojoCmd = &cobra.Command{
		Use:     "defect-dojo [FILE]",
		Short:   "export raw scan report to Defect Dojo",
		Aliases: []string{"dd"},
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			fullBom, _ := cmd.Flags().GetBool("full-bom")
			// Open the file
			log.Infof("Opening file: %s", args[0])
			f, err := os.Open(args[0])
			if err != nil {
				return fmt.Errorf("%w: %v", ErrorFileAccess, err)
			}

			ctx, cancel := context.WithTimeout(context.Background(), timeout)
			defer cancel()

			rType, fileBytes, err := artifact.ReadWithContext(ctx, f)
			log.Infof("file size: %d", len(fileBytes))
			log.Infof("Detected File Type: %s", rType)
			if err != nil {
				return fmt.Errorf("%w: %v", ErrorEncoding, err)
			}

			var ddScanType defectdojo.ScanType
			switch rType {
			case artifact.Cyclonedx:
				ddScanType = defectdojo.CycloneDX
			case artifact.Grype:
				ddScanType = defectdojo.Grype
			case artifact.Semgrep:
				ddScanType = defectdojo.Semgrep
			case artifact.Gitleaks:
				ddScanType = defectdojo.Gitleaks
			default:
				return fmt.Errorf("%w: Unsupported file type", ErrorEncoding)
			}

			if rType != artifact.Cyclonedx && fullBom {
				return errors.New("--full-bom is only permitted with a CycloneDx file")
			}

			if fullBom {
				buf := bytes.NewBuffer(fileBytes)
				c := artifact.DecodeJSON[artifact.CyclonedxSbomReport](buf)
				fileBytes, _ = json.Marshal(c.ShimComponentsAsVulnerabilities())
			}

			return service.Export(ctx, bytes.NewBuffer(fileBytes), engagement, ddScanType)
		},
	}

	exportCmd.PersistentFlags().BoolP("full-bom", "m", false, "CycloneDx: Adds all the components with no vulnerabilities as SeverityNone")
	exportCmd.AddCommand(defectDojoCmd)
	return exportCmd
}
