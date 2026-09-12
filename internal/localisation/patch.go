package localisation

import (
	"context"
	"fmt"
	"net/url"
	"regexp"
	"strings"
)

var (
	reRepo = regexp.MustCompile(`^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$`)
	reSHA  = regexp.MustCompile(`^[0-9a-f]{7,40}$`)
	reNum  = regexp.MustCompile(`^\d{1,7}$`)
)

// commitInfo is the subset of the GitHub commit resource the localiser uses.
type commitInfo struct {
	SHA     string `json:"sha"`
	HTMLURL string `json:"html_url"`
	Commit  struct {
		Message string `json:"message"`
	} `json:"commit"`
	Parents []struct {
		SHA string `json:"sha"`
	} `json:"parents"`
	Files []commitFile `json:"files"`
}

type commitFile struct {
	Filename         string `json:"filename"`
	PreviousFilename string `json:"previous_filename"`
	Status           string `json:"status"` // added, removed, modified, renamed
	Additions        int    `json:"additions"`
	Deletions        int    `json:"deletions"`
	Patch            string `json:"patch"` // absent for binary or very large files
}

func validateRepo(repo string) error {
	if !reRepo.MatchString(repo) || strings.Contains(repo, "..") {
		return fmt.Errorf("invalid repository %q", repo)
	}
	return nil
}

// Commit fetches one commit with its per-file patches.
func (c *Client) Commit(ctx context.Context, repo, sha string) (*commitInfo, error) {
	if err := validateRepo(repo); err != nil {
		return nil, err
	}
	if !reSHA.MatchString(sha) {
		return nil, fmt.Errorf("invalid commit sha %q", sha)
	}
	var ci commitInfo
	if err := c.getJSON(ctx, c.GitHubAPI+"/repos/"+repo+"/commits/"+sha, "application/vnd.github+json", &ci); err != nil {
		return nil, err
	}
	return &ci, nil
}

// PullRequestCommits lists the commit SHAs of a pull request.
func (c *Client) PullRequestCommits(ctx context.Context, repo, number string) ([]string, error) {
	if err := validateRepo(repo); err != nil {
		return nil, err
	}
	if !reNum.MatchString(number) {
		return nil, fmt.Errorf("invalid pull request number %q", number)
	}
	var list []struct {
		SHA string `json:"sha"`
	}
	if err := c.getJSON(ctx, c.GitHubAPI+"/repos/"+repo+"/pulls/"+number+"/commits?per_page=100", "application/vnd.github+json", &list); err != nil {
		return nil, err
	}
	out := make([]string, 0, len(list))
	for _, e := range list {
		out = append(out, e.SHA)
	}
	return out, nil
}

// FileAt fetches a file's raw content at a ref. Paths are validated so a
// crafted diff cannot steer the request outside the repository tree.
func (c *Client) FileAt(ctx context.Context, repo, path, ref string) ([]byte, error) {
	if err := validateRepo(repo); err != nil {
		return nil, err
	}
	if !reSHA.MatchString(ref) {
		return nil, fmt.Errorf("invalid ref %q", ref)
	}
	if err := validateRepoPath(path); err != nil {
		return nil, err
	}
	escaped := strings.Join(strings.Split(path, "/"), "/") // keep slashes
	for i, seg := range strings.Split(escaped, "/") {
		if i == 0 {
			escaped = url.PathEscape(seg)
		} else {
			escaped += "/" + url.PathEscape(seg)
		}
	}
	body, _, err := c.get(ctx, c.GitHubAPI+"/repos/"+repo+"/contents/"+escaped+"?ref="+ref, "application/vnd.github.raw+json", maxSourceBytes)
	if err != nil {
		return nil, err
	}
	return body, nil
}

func validateRepoPath(p string) error {
	if p == "" || len(p) > 512 || strings.HasPrefix(p, "/") || strings.Contains(p, "\\") {
		return fmt.Errorf("invalid path %q", p)
	}
	for _, seg := range strings.Split(p, "/") {
		if seg == "" || seg == "." || seg == ".." {
			return fmt.Errorf("invalid path %q", p)
		}
	}
	return nil
}

// SearchCommits runs the client's suggested check: does the vulnerability ID
// appear in a commit message of the package repository? Uses the GitHub
// commit search API (30 requests/minute).
func (c *Client) SearchCommits(ctx context.Context, repo, term string) (int, []string, error) {
	if err := validateRepo(repo); err != nil {
		return 0, nil, err
	}
	if !advisoryIDPattern.MatchString(term) {
		return 0, nil, fmt.Errorf("refusing to search for %q", term)
	}
	q := url.QueryEscape("repo:" + repo + " " + term)
	var res struct {
		TotalCount int `json:"total_count"`
		Items      []struct {
			SHA string `json:"sha"`
		} `json:"items"`
	}
	if err := c.getJSON(ctx, c.GitHubAPI+"/search/commits?per_page=10&q="+q, "application/vnd.github+json", &res); err != nil {
		return 0, nil, err
	}
	shas := make([]string, 0, len(res.Items))
	for _, it := range res.Items {
		shas = append(shas, it.SHA)
	}
	return res.TotalCount, shas, nil
}

// fileDiffsFromCommit turns the per-file patches of a commit resource into
// FileDiffs by giving each patch the header the unified parser expects.
func fileDiffsFromCommit(ci *commitInfo) []FileDiff {
	var out []FileDiff
	for _, f := range ci.Files {
		if f.Patch == "" {
			// Binary, or too large for the API to inline. Record without hunks.
			out = append(out, FileDiff{OldPath: f.PreviousFilename, NewPath: f.Filename, Status: f.Status, Binary: true})
			continue
		}
		old := f.Filename
		if f.PreviousFilename != "" {
			old = f.PreviousFilename
		}
		var sb strings.Builder
		fmt.Fprintf(&sb, "diff --git a/%s b/%s\n", old, f.Filename)
		switch f.Status {
		case "added":
			sb.WriteString("new file mode 100644\n--- /dev/null\n")
			fmt.Fprintf(&sb, "+++ b/%s\n", f.Filename)
		case "removed":
			sb.WriteString("deleted file mode 100644\n")
			fmt.Fprintf(&sb, "--- a/%s\n+++ /dev/null\n", old)
		default:
			fmt.Fprintf(&sb, "--- a/%s\n+++ b/%s\n", old, f.Filename)
		}
		sb.WriteString(f.Patch)
		sb.WriteByte('\n')
		parsed, err := ParseUnifiedDiff(strings.NewReader(sb.String()))
		if err != nil || len(parsed) == 0 {
			continue
		}
		fd := parsed[0]
		if f.Status == "renamed" {
			fd.Status = "renamed"
		}
		out = append(out, fd)
	}
	return out
}
