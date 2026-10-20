package inventory

import (
	"bufio"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

var commitPattern = regexp.MustCompile(`^[0-9a-f]{40}([0-9a-f]{24})?$`)

// headCommit returns the commit a repository's HEAD points at, or "" when it
// cannot be read. It reads .git/HEAD and the refs directly instead of
// running git: the repository being scanned is untrusted, and git runs
// commands its config names (core.fsmonitor, for one).
func headCommit(repoPath string) string {
	gitDir := filepath.Join(repoPath, ".git")
	info, err := os.Stat(gitDir)
	if err != nil {
		return ""
	}
	if !info.IsDir() {
		// A worktree or submodule: .git is a file naming the real directory.
		line := firstLine(gitDir)
		target, ok := strings.CutPrefix(line, "gitdir:")
		if !ok {
			return ""
		}
		target = strings.TrimSpace(target)
		if !filepath.IsAbs(target) {
			target = filepath.Join(repoPath, target)
		}
		gitDir = target
	}

	head := firstLine(filepath.Join(gitDir, "HEAD"))
	if commitPattern.MatchString(head) {
		return head
	}
	ref, ok := strings.CutPrefix(head, "ref:")
	if !ok {
		return ""
	}
	ref = strings.TrimSpace(ref)
	if !strings.HasPrefix(ref, "refs/") || strings.Contains(ref, "..") {
		return ""
	}

	// A linked worktree keeps its refs in the main repository's directory.
	dirs := []string{gitDir}
	if common := firstLine(filepath.Join(gitDir, "commondir")); common != "" {
		if !filepath.IsAbs(common) {
			common = filepath.Join(gitDir, common)
		}
		dirs = append(dirs, common)
	}
	for _, dir := range dirs {
		if commit := firstLine(filepath.Join(dir, filepath.FromSlash(ref))); commitPattern.MatchString(commit) {
			return commit
		}
	}
	for _, dir := range dirs {
		if commit := packedRef(filepath.Join(dir, "packed-refs"), ref); commit != "" {
			return commit
		}
	}
	return ""
}

func firstLine(path string) string {
	file, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer func() { _ = file.Close() }()
	line, _ := bufio.NewReader(io.LimitReader(file, 4096)).ReadString('\n')
	return strings.TrimSpace(line)
}

func packedRef(path, ref string) string {
	file, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer func() { _ = file.Close() }()
	scanner := bufio.NewScanner(io.LimitReader(file, 64<<20))
	for scanner.Scan() {
		commit, name, ok := strings.Cut(scanner.Text(), " ")
		if ok && name == ref && commitPattern.MatchString(commit) {
			return commit
		}
	}
	return ""
}
