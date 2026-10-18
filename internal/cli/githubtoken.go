package cli

import (
	"context"
	"os"
	"os/exec"
	"strings"
	"time"
)

// ghAuthToken asks the GitHub CLI for the token of the account it is logged
// in as. Swapped out in tests.
var ghAuthToken = func() string {
	if _, err := exec.LookPath("gh"); err != nil {
		return ""
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "gh", "auth", "token").Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

// ensureGitHubToken makes a GitHub token available to every GitHub API
// caller (which all read GITHUB_TOKEN) when the user hasn't set one: first
// the token saved via the interactive menu, then the GitHub CLI's login
// (`gh auth login`). The token is only set for this process, never written
// anywhere. Returns where the token came from, or "" if none was found.
func ensureGitHubToken() string {
	if os.Getenv("GITHUB_TOKEN") != "" {
		return "GITHUB_TOKEN"
	}
	if token := getGitHubToken(); token != "" {
		_ = os.Setenv("GITHUB_TOKEN", token)
		return "sbomber config"
	}
	if token := ghAuthToken(); token != "" {
		_ = os.Setenv("GITHUB_TOKEN", token)
		return "gh auth token"
	}
	return ""
}
