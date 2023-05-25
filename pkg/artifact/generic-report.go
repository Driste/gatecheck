package artifact

type GenericReport []byte

// Enforce Report Interface
var _ Report = GenericReport{}

func (r GenericReport) String() string {
	return "Unsupported/Generic Filetype."
}

func (r GenericReport) Validate(_ Config) error {
	return nil
}
