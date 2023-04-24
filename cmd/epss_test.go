package cmd

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path"
	"testing"

	"github.com/anchore/grype/grype/presenter/models"
	"github.com/gatecheckdev/gatecheck/pkg/artifact"
	"github.com/gatecheckdev/gatecheck/pkg/epss"
)

func TestNewEPSSCmd(t *testing.T) {
	t.Run("bad-file", func(t *testing.T) {
		commandString := fmt.Sprintf("epss %s", fileWithBadPermissions(t))
		output, err := Execute(commandString, CLIConfig{EPSSService: mockEPSSService{}})
		if errors.Is(err, ErrorFileAccess) != true {
			t.Fatal(err)
		}
		t.Log(output)
	})

	t.Run("bad-file-decode", func(t *testing.T) {
		commandString := fmt.Sprintf("epss %s", fileWithBadJSON(t))
		output, err := Execute(commandString, CLIConfig{EPSSService: mockEPSSService{}})
		if errors.Is(err, ErrorEncoding) != true {
			t.Fatal(err)
		}
		t.Log(output)
	})

	t.Run("bad-file-decode", func(t *testing.T) {
		var grypeScan artifact.GrypeScanReport
		_ = json.NewDecoder(MustOpen(grypeTestReport, t.Fatal)).Decode(&grypeScan)
		grypeScan.Matches = append(grypeScan.Matches,
			models.Match{Vulnerability: models.Vulnerability{VulnerabilityMetadata: models.VulnerabilityMetadata{ID: "A"}}})
		tempGrypeScanFile := path.Join(t.TempDir(), "new-grype-scan.json")
		f, _ := os.Create(tempGrypeScanFile)
		_ = json.NewEncoder(f).Encode(grypeScan)

		commandString := fmt.Sprintf("epss %s", tempGrypeScanFile)
		config := CLIConfig{EPSSService: mockEPSSService{returnError: errors.New("mock error")}}
		output, err := Execute(commandString, config)

		if errors.Is(err, ErrorAPI) != true {
			t.Fatal(err)
		}

		t.Log(output)
	})

	t.Run("success", func(t *testing.T) {
		var grypeScan artifact.GrypeScanReport
		_ = json.NewDecoder(MustOpen(grypeTestReport, t.Fatal)).Decode(&grypeScan)
		grypeScan.Matches = append(grypeScan.Matches,
			models.Match{Vulnerability: models.Vulnerability{VulnerabilityMetadata: models.VulnerabilityMetadata{ID: "A"}}})
		tempGrypeScanFile := path.Join(t.TempDir(), "new-grype-scan.json")
		f, _ := os.Create(tempGrypeScanFile)
		_ = json.NewEncoder(f).Encode(grypeScan)

		commandString := fmt.Sprintf("epss %s", tempGrypeScanFile)
		config := CLIConfig{EPSSService: mockEPSSService{returnError: nil, returnData: []epss.Data{
			{CVE: "A", EPSS: "B", Percentile: "32", Date: "may 3, 2023", Severity: "Critical", URL: "github.com"},
		}}}

		output, err := Execute(commandString, config)

		if err != nil {
			t.Fatal(err)
		}

		t.Log(output)
	})
}

type mockEPSSService struct {
	returnError error
	returnData  []epss.Data
}

func (m mockEPSSService) Get(_ []epss.CVE) ([]epss.Data, error) {
	return m.returnData, m.returnError
}
