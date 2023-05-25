package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/gatecheckdev/gatecheck/pkg/artifact"
	"github.com/gatecheckdev/gatecheck/pkg/blacklist"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

func NewValidateCmd(decodeTimeout time.Duration) *cobra.Command {
	var cmd = &cobra.Command{
		Use:   "validate [FILE]",
		Short: "Validate reports or a bundle using thresholds set in the Gatecheck configuration file",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			var config artifact.Config
			var kevBlacklist artifact.KEVCatalog
			var grypeScan artifact.GrypeScanReport

			var validationError error = nil

			configFilename, _ := cmd.Flags().GetString("config")
			kevFilename, _ := cmd.Flags().GetString("blacklist")
			audit, _ := cmd.Flags().GetBool("audit")

			// Open the config file
			configFile, err := os.Open(configFilename)
			if err != nil {
				return fmt.Errorf("%w: %v", ErrorFileAccess, err)
			}
			if err := yaml.NewDecoder(configFile).Decode(&config); err != nil {
				return fmt.Errorf("%w: %v", ErrorEncoding, err)
			}

			// Open the target file
			targetBytes, err := os.ReadFile(args[0])
			if err != nil {
				return fmt.Errorf("%w: %v", ErrorFileAccess, err)
			}

			err = ParseAndValidate(bytes.NewBuffer(targetBytes), config, decodeTimeout)
			cmd.PrintErrln(err)
			if err != nil {
				validationError = ErrorValidation
			}

			// Return early if no KEV file passed
			if kevFilename == "" {
				if audit {
					return nil
				}
				return validationError
			}

			kevFile, err := os.Open(kevFilename)
			if err != nil {
				return fmt.Errorf("%w: %v", ErrorFileAccess, err)
			}

			if err := json.NewDecoder(kevFile).Decode(&kevBlacklist); err != nil {
				return fmt.Errorf("%w: %v", ErrorEncoding, err)
			}

			// Decode for Grype and return an error on fail because only grype can be validated with a blacklist
			if err := json.NewDecoder(bytes.NewBuffer(targetBytes)).Decode(&grypeScan); err != nil {
				return fmt.Errorf("%w: only Grype Reports are supported with KEV: %v", ErrorEncoding, err)
			}

			vulnerabilities := blacklist.BlacklistedVulnerabilities(grypeScan, kevBlacklist)

			cmd.Println(blacklist.StringBlacklistedVulnerabilities(kevBlacklist.CatalogVersion, vulnerabilities))

			cmd.Println(fmt.Sprintf("%d Vulnerabilities listed on CISA Known Exploited Vulnerabilities Blacklist",
				len(vulnerabilities)))

			if len(vulnerabilities) > 0 {
				validationError = ErrorValidation
			}

			if audit == true {
				return nil
			}

			return validationError
		},
	}

	cmd.Flags().Bool("audit", false, "Exit w/ Code 0 even if validation fails")
	cmd.Flags().StringP("config", "c", "", "A Gatecheck configuration file with thresholds")
	cmd.Flags().StringP("blacklist", "k", "", "A CISA KEV Blacklist file")

	_ = cmd.MarkFlagRequired("config")
	return cmd
}

func ParseAndValidate(r io.Reader, config artifact.Config, timeout time.Duration) error {
	var err error

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	result, err := artifact.ReadWithContext(ctx, r)
	if err != nil {
		return err
	}
	if result.Type == artifact.Unsupported {
		return errors.New("unsupported scan type")
	}

	return result.Report.Validate(config)
}
