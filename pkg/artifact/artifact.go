package artifact

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"strings"

	"github.com/dustin/go-humanize"
	"github.com/gatecheckdev/gatecheck/pkg/epss"
)

type Report interface {
	String() string
	Validate(Config) error
}

type CVEReport interface {
	Report
	CVEs() []epss.CVE
}

type Artifact struct {
	Label   string
	Type    Type
	Digest  []byte
	Content []byte
}

func (a Artifact) String() string {
	return fmt.Sprintf("%s [%s] %s", a.Label, a.DigestString(), humanize.Bytes(uint64(len(a.Content))))
}

func (a Artifact) DigestString() string {
	return strings.ToUpper(hex.EncodeToString(a.Digest))
}

func (a Artifact) ContentBytes() []byte {
	return append([]byte{}, a.Content...)
}

func NewArtifact(label string, r io.Reader) (Artifact, error) {
	hashWriter := sha256.New()
	buf := new(bytes.Buffer)

	// Hash the file
	multiWriter := io.MultiWriter(hashWriter, buf)

	if _, err := io.Copy(multiWriter, r); err != nil {
		return Artifact{}, err
	}

	return Artifact{
		Label:   label,
		Digest:  hashWriter.Sum(nil),
		Content: buf.Bytes(),
	}, nil
}
