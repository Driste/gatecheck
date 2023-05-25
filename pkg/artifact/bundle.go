package artifact

import (
	"bytes"
	"compress/gzip"
	"encoding/gob"
	"errors"
	"io"
	"strings"

	"github.com/dustin/go-humanize"
	"github.com/gatecheckdev/gatecheck/internal/log"
	gcStrings "github.com/gatecheckdev/gatecheck/pkg/strings"
)

type Bundle struct {
	Artifacts   map[string]Artifact
	PipelineID  string
	PipelineURL string
	ProjectName string
}

func NewBundle() *Bundle {
	return &Bundle{Artifacts: map[string]Artifact{}}
}

func (b *Bundle) Add(artifacts ...Artifact) error {
	for _, v := range artifacts {
		if err := b.add(v); err != nil {
			return err
		}
	}
	return nil
}

func (b *Bundle) add(artifact Artifact) error {
	if strings.Trim(artifact.Label, " ") == "" {
		return errors.New("artifact is missing a label")
	}
	// Directly taking bytes, no possibility of error
	result, _ := Inspect(bytes.NewBuffer(artifact.ContentBytes()))

	// No need to check decode errors since it's decoded in the DetectReportType Function
	artifact.Type = result.Type
	b.Artifacts[artifact.Label] = artifact

	return nil
}

func (b *Bundle) String() string {
	table := new(gcStrings.Table).WithHeader("Type", "Label", "Digest", "Size")

	items := []Artifact{}
	types := []string{}
	for _, v := range b.Artifacts {
		items = append(items, v)
		types = append(types, string(v.Type))
	}

	totalSize := uint64(0)
	for i, v := range items {
		totalSize += uint64(len(v.ContentBytes()))
		table = table.WithRow(types[i], v.Label, v.DigestString(), humanize.Bytes(uint64(len(v.ContentBytes()))))
	}
	horizontalLength := len(strings.Split(table.String(), "\n")[0])
	var sb strings.Builder
	sb.WriteString(table.String() + "\n")

	summary := "Total Size: " + humanize.Bytes(totalSize)
	// Left pad with spaces
	sb.WriteString(strings.Repeat(" ", horizontalLength-len(summary)) + summary)
	return sb.String()
}

func (b *Bundle) Validate(config Config) error {
	var errStrings []string

	for _, a := range b.Artifacts {
		if len(a.Content) == 0 {
			log.Infof("No '%s' content... skipping validation", a.Type)
			return nil
		}

		// TODO: make this know by the type instead of having to inspect
		result, err := Inspect(bytes.NewBuffer(a.ContentBytes()))
		if err != nil {
			return err
		}

		if result.Type == Unsupported {
			continue
		}

		log.Infof("Validating '%s' Schema", a.Type)
		if err := result.Report.Validate(config); err != nil {
			errStrings = append(errStrings, err.Error())
		}
	}

	if len(errStrings) != 0 {
		return errors.New(strings.Join(errStrings, "\n"))
	}

	return nil
}

// func (b *Bundle) ValidateCyclonedx(config *Config) error {
// 	var cyclonedxSbom CyclonedxSbomReport
// 	// No config
// 	if config == nil {
// 		return nil
// 	}
// 	// No scan in bundle to validate
// 	if len(b.CyclonedxSbom.Content) == 0 {
// 		log.Info("No cyclonedx content... skipping validation")
// 		return nil
// 	}

// 	// Problem parsing the artifact
// 	if err := json.Unmarshal(b.CyclonedxSbom.ContentBytes(), &cyclonedxSbom); err != nil {
// 		log.Info("Validating CycloneDX Schema")
// 		return fmt.Errorf("%w: %v", ErrCyclonedxValidationFailed, err)
// 	}

// 	log.Info("Validating CycloneDX Findings")
// 	return cyclonedxSbom.Validate(*config)
// }

// func (b *Bundle) ValidateGrype(config *Config) error {
// 	var grypeScan GrypeScanReport
// 	// No config
// 	if config == nil {
// 		return nil
// 	}
// 	// No scan in bundle to validate
// 	if len(b.GrypeScan.Content) == 0 {
// 		log.Info("No grype content... skipping validation")
// 		return nil
// 	}

// 	// Problem parsing the artifact
// 	if err := json.Unmarshal(b.GrypeScan.ContentBytes(), &grypeScan); err != nil {
// 		return fmt.Errorf("%w: %v", GrypeValidationFailed, err)
// 	}

// 	return grypeScan.Validate(*config)
// }

// func (b *Bundle) ValidateSemgrep(config *Config) error {
// 	var semgrepScan SemgrepScanReport
// 	// No config
// 	if config == nil {
// 		return nil
// 	}
// 	// No scan in bundle to validate
// 	if len(b.SemgrepScan.ContentBytes()) == 0 {
// 		log.Info("No semgrep content... skipping validation")
// 		return nil
// 	}

// 	// Problem parsing the artifact
// 	if err := json.Unmarshal(b.SemgrepScan.ContentBytes(), &semgrepScan); err != nil {
// 		return fmt.Errorf("%w: %v", SemgrepFailedValidation, err)
// 	}

// 	return semgrepScan.Validate(*config)
// }

// func (b *Bundle) ValidateGitleaks(config *Config) error {
// 	var gitleaksScan GitleaksScanReport
// 	// No config
// 	if config == nil {
// 		return nil
// 	}
// 	// No scan in bundle to validate
// 	if len(b.GitleaksScan.ContentBytes()) == 0 {
// 		log.Info("No gitleaks content... skipping validation")
// 		return nil
// 	}

// 	// Problem parsing the artifact
// 	if err := json.Unmarshal(b.GitleaksScan.ContentBytes(), &gitleaksScan); err != nil {
// 		return fmt.Errorf("%w: %v", GitleaksValidationFailed, err)
// 	}

// 	return gitleaksScan.Validate(*config)
// }

type Encoder struct {
	w io.Writer
}

func (e Encoder) Encode(bundle *Bundle) error {
	// TODO: Add encryption
	buf := new(bytes.Buffer)
	if bundle == nil {
		return errors.New("no bundle to encode")
	}
	_ = gob.NewEncoder(buf).Encode(bundle)

	zw := gzip.NewWriter(e.w)

	if _, err := io.Copy(zw, buf); err != nil {
		return err
	}

	_ = zw.Close()
	return nil
}

func NewBundleEncoder(w io.Writer) *Encoder {
	return &Encoder{w: w}
}

type BundleDecoder struct {
	r io.Reader
}

func (d BundleDecoder) Decode(bundle *Bundle) error {
	// TODO: Add decryption

	zr, err := gzip.NewReader(d.r)
	if err != nil {
		return err
	}

	buf := new(bytes.Buffer)
	// Errors captured during gzip.NewReader or during decoding
	_, _ = io.Copy(buf, zr)

	return gob.NewDecoder(buf).Decode(bundle)
}

func NewBundleDecoder(r io.Reader) *BundleDecoder {
	return &BundleDecoder{r: r}
}
