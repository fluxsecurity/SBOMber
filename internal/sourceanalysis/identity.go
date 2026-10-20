package sourceanalysis

// FunctionID identifies a named application function without relying on its
// name alone, which can be duplicated across files and repositories.
type FunctionID struct {
	RepositoryID string
	File         string
	Name         string
	StartLine    int
}
