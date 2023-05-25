package artifact

import (
	"errors"
	"fmt"
	"strings"

	"github.com/anchore/grype/grype/presenter/models"
	"github.com/gatecheckdev/gatecheck/internal/log"
	gcStrings "github.com/gatecheckdev/gatecheck/pkg/strings"
)

type GrypeScanReport models.Document

var GrypeValidationFailed = errors.New("grype validation failed")

// Enforce Report Interface
var _ Report = GrypeScanReport{}

func (r GrypeScanReport) String() string {
	table := new(gcStrings.Table).WithHeader("Severity", "Package", "Version", "Link")

	for _, item := range r.Matches {
		table = table.WithRow(item.Vulnerability.Severity,
			item.Artifact.Name, item.Artifact.Version, item.Vulnerability.DataSource)
	}

	// Sort the rows by Severity then Package
	severitiesOrder := gcStrings.StrOrder{"Critical", "High", "Medium", "Low", "Negligible", "Unknown"}
	table = table.SortBy([]gcStrings.SortBy{
		{Name: "Severity", Mode: gcStrings.AscCustom, Order: severitiesOrder},
		{Name: "Package", Mode: gcStrings.Asc},
	}).Sort()

	return table.String()
}

type GrypeConfig struct {
	AllowList  []GrypeListItem `yaml:"allowList,omitempty" json:"allowList,omitempty"`
	DenyList   []GrypeListItem `yaml:"denyList,omitempty" json:"denyList,omitempty"`
	Critical   int             `yaml:"critical"   json:"critical"`
	High       int             `yaml:"high"       json:"high"`
	Medium     int             `yaml:"medium"     json:"medium"`
	Low        int             `yaml:"low"        json:"low"`
	Negligible int             `yaml:"negligible" json:"negligible"`
	Unknown    int             `yaml:"unknown"    json:"unknown"`
}

type GrypeListItem struct {
	Id     string `yaml:"id"     json:"id"`
	Reason string `yaml:"reason" json:"reason"`
}

func (r GrypeScanReport) Validate(config Config) error {
	if config.Grype == nil {
		return errors.New("no Grype configuration specified")
	}

	found := map[string]int{"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Negligible": 0, "Unknown": 0}
	allowed := map[string]int{
		"Critical": config.Grype.Critical, "High": config.Grype.High, "Medium": config.Grype.Medium,
		"Low": config.Grype.Low, "Negligible": config.Grype.Negligible, "Unknown": config.Grype.Unknown,
	}
	foundDenied := make([]models.Match, 0)

LOOPMATCH:
	for matchIndex, match := range r.Matches {

		for _, allowed := range config.Grype.AllowList {
			if strings.Compare(match.Vulnerability.ID, allowed.Id) == 0 {

				log.Infof("%s Allowed. Reason: %s", match.Vulnerability.ID, allowed.Reason)
				continue LOOPMATCH
			}
		}

		for _, denied := range config.Grype.DenyList {
			if match.Vulnerability.ID == denied.Id {
				log.Infof("%s Denied. Reason: %s", match.Vulnerability.ID, denied.Reason)
				foundDenied = append(foundDenied, r.Matches[matchIndex])
			}
		}

		found[match.Vulnerability.Severity] += 1
	}
	log.Infof("Grype Findings: %v", gcStrings.PrettyPrintMap(found))

	var errStrings []string

	for severity := range found {
		// A -1 in config means all allowed
		if allowed[severity] == -1 {
			continue
		}
		if found[severity] > allowed[severity] {
			s := fmt.Sprintf("%s (%d found > %d allowed)", severity, found[severity], allowed[severity])
			errStrings = append(errStrings, s)
		}
	}

	if len(foundDenied) != 0 {
		deniedReport := &GrypeScanReport{Matches: foundDenied}
		errStrings = append(errStrings, fmt.Sprintf("Denied Vulnerabilities\n%s", deniedReport))
	}

	if len(errStrings) == 0 {
		return nil
	}

	return fmt.Errorf("%w: %s", GrypeValidationFailed, strings.Join(errStrings, ", "))
}
