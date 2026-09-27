package sourceanalysis

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

const (
	DefaultMaxSourceFiles    = 10_000
	DefaultMaxSourceBytes    = int64(1_000_000)
	DefaultMinifiedLineBytes = 4_000
)

const (
	SkipExcludedDirectory = "excluded_directory"
	SkipGeneratedOutput   = "generated_output"
	SkipMinifiedBundle    = "minified_bundle"
	SkipNonRegularFile    = "non_regular_file"
	SkipSourceTooLarge    = "source_too_large"
	SkipSourceFileLimit   = "source_file_limit"
)

const (
	LimitMaxFiles    = "max_files"
	LimitMaxFileSize = "max_file_size"
)

// RepositoryOptions bounds source discovery and parsing. Zero values use the
// documented defaults. Negative values are rejected.
type RepositoryOptions struct {
	MaxSourceFiles    int
	MaxSourceBytes    int64
	MinifiedLineBytes int
}

// AnalyzedSource keeps a repository-relative path next to the parser result.
type AnalyzedSource struct {
	Path   string
	Result Result
}

// SkippedSource records exclusions explicitly so they cannot be mistaken for
// analysed files. Path can name either a file or a pruned directory.
type SkippedSource struct {
	Path        string
	Reason      string
	IsDirectory bool
}

// FailedSource records a file or traversal failure without stopping the
// repository. IsDirectory lets public coverage avoid counting a pruned tree as
// one failed source file while still marking the scan partial.
type FailedSource struct {
	Path        string
	Reason      string
	IsDirectory bool
}

// RepositoryResult is the internal repository-analysis result. #116 maps
// these lists to the public usage-graph coverage counters.
type RepositoryResult struct {
	Files     []AnalyzedSource
	Skipped   []SkippedSource
	Failed    []FailedSource
	LimitsHit []string
}

func normalizeRepositoryOptions(options RepositoryOptions) (RepositoryOptions, error) {
	if options.MaxSourceFiles < 0 || options.MaxSourceBytes < 0 || options.MinifiedLineBytes < 0 {
		return RepositoryOptions{}, fmt.Errorf("repository analysis limits cannot be negative")
	}

	if options.MaxSourceFiles == 0 {
		options.MaxSourceFiles = DefaultMaxSourceFiles
	}
	if options.MaxSourceBytes == 0 {
		options.MaxSourceBytes = DefaultMaxSourceBytes
	}
	if options.MinifiedLineBytes == 0 {
		options.MinifiedLineBytes = DefaultMinifiedLineBytes
	}

	return options, nil
}

func excludedDirectory(name string) bool {
	switch strings.ToLower(name) {
	case ".git", ".next", "build", "coverage", "dist", "generated", "node_modules", "out", "vendor":
		return true
	default:
		return false
	}
}

func generatedSourceFile(name string) bool {
	lower := strings.ToLower(name)

	for _, suffix := range []string{
		".bundle.cjs",
		".bundle.js",
		".bundle.mjs",
		".bundle.ts",
		".bundle.tsx",
		".generated.cjs",
		".generated.js",
		".generated.mjs",
		".generated.ts",
		".generated.tsx",
		".min.cjs",
		".min.js",
		".min.mjs",
		".min.ts",
		".min.tsx",
	} {
		if strings.HasSuffix(lower, suffix) {
			return true
		}
	}

	return false
}

func hasLineLongerThan(source []byte, limit int) bool {
	for _, line := range bytes.Split(source, []byte{'\n'}) {
		if len(line) > limit {
			return true
		}
	}

	return false
}

func repositoryRelativePath(root, path string) string {
	relative, err := filepath.Rel(root, path)
	if err != nil {
		return filepath.ToSlash(path)
	}

	return filepath.ToSlash(relative)
}

func appendLimit(result *RepositoryResult, limit string) {
	for _, existing := range result.LimitsHit {
		if existing == limit {
			return
		}
	}

	result.LimitsHit = append(result.LimitsHit, limit)
}

// AnalyzeRepository discovers and parses bounded JS, TS and TSX application
// source. It does not follow excluded directories or execute source code.
func AnalyzeRepository(root string, options RepositoryOptions) (RepositoryResult, error) {
	options, err := normalizeRepositoryOptions(options)
	if err != nil {
		return RepositoryResult{}, err
	}

	rootInfo, err := os.Stat(root)
	if err != nil {
		return RepositoryResult{}, fmt.Errorf("stat repository root: %w", err)
	}
	if !rootInfo.IsDir() {
		return RepositoryResult{}, fmt.Errorf("repository root %q is not a directory", root)
	}

	root, err = filepath.Abs(root)
	if err != nil {
		return RepositoryResult{}, fmt.Errorf("resolve repository root: %w", err)
	}

	result := RepositoryResult{
		Files:     []AnalyzedSource{},
		Skipped:   []SkippedSource{},
		Failed:    []FailedSource{},
		LimitsHit: []string{},
	}
	sourceFilesSeen := 0

	err = filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		relative := repositoryRelativePath(root, path)

		if walkErr != nil {
			isDirectory := entry != nil && entry.IsDir()
			result.Failed = append(result.Failed, FailedSource{
				Path:        relative,
				Reason:      walkErr.Error(),
				IsDirectory: isDirectory,
			})
			if entry != nil && entry.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}

		if path == root {
			return nil
		}

		if entry.IsDir() {
			if excludedDirectory(entry.Name()) {
				result.Skipped = append(result.Skipped, SkippedSource{
					Path:        relative,
					Reason:      SkipExcludedDirectory,
					IsDirectory: true,
				})
				return filepath.SkipDir
			}
			return nil
		}

		if _, languageErr := languageForPath(path); languageErr != nil {
			return nil
		}

		if generatedSourceFile(entry.Name()) {
			result.Skipped = append(result.Skipped, SkippedSource{Path: relative, Reason: SkipGeneratedOutput})
			return nil
		}

		sourceFilesSeen++
		if sourceFilesSeen > options.MaxSourceFiles {
			result.Skipped = append(result.Skipped, SkippedSource{Path: relative, Reason: SkipSourceFileLimit})
			appendLimit(&result, LimitMaxFiles)
			return nil
		}

		info, infoErr := entry.Info()
		if infoErr != nil {
			result.Failed = append(result.Failed, FailedSource{Path: relative, Reason: infoErr.Error()})
			return nil
		}
		if !info.Mode().IsRegular() {
			result.Skipped = append(result.Skipped, SkippedSource{Path: relative, Reason: SkipNonRegularFile})
			return nil
		}
		if info.Size() > options.MaxSourceBytes {
			result.Skipped = append(result.Skipped, SkippedSource{Path: relative, Reason: SkipSourceTooLarge})
			appendLimit(&result, LimitMaxFileSize)
			return nil
		}

		source, readErr := os.ReadFile(path)
		if readErr != nil {
			result.Failed = append(result.Failed, FailedSource{Path: relative, Reason: readErr.Error()})
			return nil
		}
		if hasLineLongerThan(source, options.MinifiedLineBytes) {
			result.Skipped = append(result.Skipped, SkippedSource{Path: relative, Reason: SkipMinifiedBundle})
			return nil
		}

		analysis, analysisErr := AnalyzeSource(path)
		if analysisErr != nil {
			result.Failed = append(result.Failed, FailedSource{Path: relative, Reason: analysisErr.Error()})
			return nil
		}

		result.Files = append(result.Files, AnalyzedSource{Path: relative, Result: analysis})
		return nil
	})
	if err != nil {
		return RepositoryResult{}, fmt.Errorf("walk repository: %w", err)
	}

	sort.Slice(result.Files, func(i, j int) bool { return result.Files[i].Path < result.Files[j].Path })
	sort.Slice(result.Skipped, func(i, j int) bool { return result.Skipped[i].Path < result.Skipped[j].Path })
	sort.Slice(result.Failed, func(i, j int) bool { return result.Failed[i].Path < result.Failed[j].Path })

	return result, nil
}
