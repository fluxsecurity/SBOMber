package localisation

import (
	"bufio"
	"fmt"
	"io"
	"strconv"
	"strings"
)

// FileDiff is one file's changes from a unified diff.
type FileDiff struct {
	OldPath string
	NewPath string
	// Status is added, removed, renamed or modified.
	Status string
	Binary bool
	Hunks  []Hunk
}

// Path returns the path that identifies the file after the change, or the
// old path for a removal.
func (f FileDiff) Path() string {
	if f.NewPath != "" && f.NewPath != "/dev/null" {
		return f.NewPath
	}
	return f.OldPath
}

// Hunk is one @@ block of a unified diff.
type Hunk struct {
	OldStart int
	OldCount int
	NewStart int
	NewCount int
	// Context is git's function guess after the second @@. It is often
	// empty or wrong for JavaScript (every lodash function is indented inside
	// an IIFE, so git prints nothing), which is why callers resolve the
	// enclosing function from the file itself instead of trusting this.
	Context string
	Lines   []DiffLine
}

// DiffLine is one line inside a hunk.
type DiffLine struct {
	Kind  byte // ' ', '+' or '-'
	Text  string
	OldNo int // 0 for an added line
	NewNo int // 0 for a removed line
}

// maxDiffLines bounds how much diff text is parsed. Fix commits are small;
// anything beyond this is treated as untrusted or not a fix.
const maxDiffLines = 200_000

// ParseUnifiedDiff parses git-style unified diff text, such as the GitHub
// commits API returns for Accept: application/vnd.github.diff. It is
// tolerant of unknown header lines and never panics on malformed input;
// a hunk header it cannot read ends the current file's parsing.
func ParseUnifiedDiff(r io.Reader) ([]FileDiff, error) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)

	var files []FileDiff
	var cur *FileDiff
	var hunk *Hunk
	oldNo, newNo := 0, 0
	lines := 0

	flushHunk := func() {
		if cur != nil && hunk != nil {
			cur.Hunks = append(cur.Hunks, *hunk)
		}
		hunk = nil
	}
	flushFile := func() {
		flushHunk()
		if cur != nil {
			if cur.Status == "" {
				cur.Status = "modified"
			}
			files = append(files, *cur)
		}
		cur = nil
	}

	for sc.Scan() {
		lines++
		if lines > maxDiffLines {
			flushFile()
			return files, fmt.Errorf("diff exceeds %d lines", maxDiffLines)
		}
		line := sc.Text()

		switch {
		case strings.HasPrefix(line, "diff --git "):
			flushFile()
			cur = &FileDiff{}
			a, b := splitDiffGitPaths(line)
			cur.OldPath, cur.NewPath = a, b
			continue
		case cur == nil:
			// Preamble before the first file header; ignore.
			continue
		}

		if hunk == nil {
			switch {
			case strings.HasPrefix(line, "new file mode"):
				cur.Status = "added"
			case strings.HasPrefix(line, "deleted file mode"):
				cur.Status = "removed"
			case strings.HasPrefix(line, "rename from "):
				cur.Status = "renamed"
				cur.OldPath = strings.TrimPrefix(line, "rename from ")
			case strings.HasPrefix(line, "rename to "):
				cur.NewPath = strings.TrimPrefix(line, "rename to ")
			case strings.HasPrefix(line, "Binary files "):
				cur.Binary = true
			case strings.HasPrefix(line, "--- "):
				p := strings.TrimPrefix(line, "--- ")
				if p == "/dev/null" {
					cur.OldPath = ""
					if cur.Status == "" {
						cur.Status = "added"
					}
				} else {
					cur.OldPath = stripDiffPrefix(p)
				}
			case strings.HasPrefix(line, "+++ "):
				p := strings.TrimPrefix(line, "+++ ")
				if p == "/dev/null" {
					cur.NewPath = ""
					if cur.Status == "" {
						cur.Status = "removed"
					}
				} else {
					cur.NewPath = stripDiffPrefix(p)
				}
			case strings.HasPrefix(line, "@@ "):
				h, ok := parseHunkHeader(line)
				if !ok {
					// Malformed header: stop reading this file.
					flushFile()
					continue
				}
				hunk = &h
				oldNo, newNo = h.OldStart, h.NewStart
			}
			continue
		}

		// Inside a hunk.
		switch {
		case strings.HasPrefix(line, "@@ "):
			flushHunk()
			h, ok := parseHunkHeader(line)
			if !ok {
				flushFile()
				continue
			}
			hunk = &h
			oldNo, newNo = h.OldStart, h.NewStart
		case strings.HasPrefix(line, "\\"):
			// "\ No newline at end of file"
		case strings.HasPrefix(line, "+"):
			hunk.Lines = append(hunk.Lines, DiffLine{Kind: '+', Text: line[1:], NewNo: newNo})
			newNo++
		case strings.HasPrefix(line, "-"):
			hunk.Lines = append(hunk.Lines, DiffLine{Kind: '-', Text: line[1:], OldNo: oldNo})
			oldNo++
		case strings.HasPrefix(line, " ") || line == "":
			text := ""
			if line != "" {
				text = line[1:]
			}
			hunk.Lines = append(hunk.Lines, DiffLine{Kind: ' ', Text: text, OldNo: oldNo, NewNo: newNo})
			oldNo++
			newNo++
		case strings.HasPrefix(line, "diff --git "):
			// handled above; unreachable because of the earlier switch
		default:
			// Anything else ends the hunk (for example a stray header).
			flushHunk()
		}
	}
	flushFile()
	if err := sc.Err(); err != nil {
		return files, fmt.Errorf("read diff: %w", err)
	}
	return files, nil
}

// splitDiffGitPaths reads "diff --git a/X b/Y". Paths with spaces are rare in
// npm packages; the split takes the first " b/" occurrence.
func splitDiffGitPaths(line string) (string, string) {
	rest := strings.TrimPrefix(line, "diff --git ")
	idx := strings.Index(rest, " b/")
	if idx < 0 {
		return stripDiffPrefix(rest), ""
	}
	return stripDiffPrefix(rest[:idx]), stripDiffPrefix(rest[idx+1:])
}

func stripDiffPrefix(p string) string {
	p = strings.TrimSpace(p)
	if i := strings.IndexByte(p, '\t'); i >= 0 {
		p = p[:i]
	}
	if strings.HasPrefix(p, "a/") || strings.HasPrefix(p, "b/") {
		return p[2:]
	}
	return p
}

// parseHunkHeader reads "@@ -old[,count] +new[,count] @@ context".
func parseHunkHeader(line string) (Hunk, bool) {
	var h Hunk
	rest := strings.TrimPrefix(line, "@@ ")
	end := strings.Index(rest, " @@")
	if end < 0 {
		return h, false
	}
	ranges := strings.Fields(rest[:end])
	if len(ranges) != 2 || !strings.HasPrefix(ranges[0], "-") || !strings.HasPrefix(ranges[1], "+") {
		return h, false
	}
	var ok bool
	if h.OldStart, h.OldCount, ok = parseRange(ranges[0][1:]); !ok {
		return h, false
	}
	if h.NewStart, h.NewCount, ok = parseRange(ranges[1][1:]); !ok {
		return h, false
	}
	h.Context = strings.TrimSpace(strings.TrimPrefix(rest[end+3:], " "))
	return h, true
}

func parseRange(s string) (start, count int, ok bool) {
	count = 1
	parts := strings.SplitN(s, ",", 2)
	start, err := strconv.Atoi(parts[0])
	if err != nil || start < 0 {
		return 0, 0, false
	}
	if len(parts) == 2 {
		count, err = strconv.Atoi(parts[1])
		if err != nil || count < 0 {
			return 0, 0, false
		}
	}
	return start, count, true
}

// ChangedLines returns the line numbers touched by a file diff: added lines
// numbered in the new file, removed lines numbered in the old file.
func (f FileDiff) ChangedLines() (added []int, removed []int) {
	for _, h := range f.Hunks {
		for _, l := range h.Lines {
			switch l.Kind {
			case '+':
				added = append(added, l.NewNo)
			case '-':
				removed = append(removed, l.OldNo)
			}
		}
	}
	return added, removed
}

// LineEdits is the result of diffing two files line by line.
type LineEdits struct {
	// Removed holds 1-based line numbers in the old file.
	Removed []int
	// Added holds 1-based line numbers in the new file.
	Added []int
	// Approximate is true when a region was too large to align exactly and
	// every line in it was reported as changed. Candidates from an
	// approximate diff are over-inclusive, never missing.
	Approximate bool
}

// maxExactCells bounds the O(n*m) fallback used between patience anchors.
const maxExactCells = 4_000_000

// DiffLines computes a line diff of old against new using patience diff:
// lines unique in both files anchor the alignment, and small gaps between
// anchors are aligned exactly. It needs no external tool and does not touch
// the disk, which keeps the "never executed" guarantee simple to audit.
func DiffLines(oldLines, newLines []string) LineEdits {
	var out LineEdits
	// Trim common prefix and suffix.
	lo := 0
	for lo < len(oldLines) && lo < len(newLines) && oldLines[lo] == newLines[lo] {
		lo++
	}
	aHi, bHi := len(oldLines), len(newLines)
	for aHi > lo && bHi > lo && oldLines[aHi-1] == newLines[bHi-1] {
		aHi--
		bHi--
	}
	patience(oldLines, newLines, lo, aHi, lo, bHi, &out)
	return out
}

func patience(a, b []string, aLo, aHi, bLo, bHi int, out *LineEdits) {
	if aLo >= aHi {
		for j := bLo; j < bHi; j++ {
			out.Added = append(out.Added, j+1)
		}
		return
	}
	if bLo >= bHi {
		for i := aLo; i < aHi; i++ {
			out.Removed = append(out.Removed, i+1)
		}
		return
	}

	anchors := uniqueCommonAnchors(a, b, aLo, aHi, bLo, bHi)
	if len(anchors) == 0 {
		n, m := aHi-aLo, bHi-bLo
		if n*m <= maxExactCells {
			exactLCS(a, b, aLo, aHi, bLo, bHi, out)
			return
		}
		out.Approximate = true
		for i := aLo; i < aHi; i++ {
			out.Removed = append(out.Removed, i+1)
		}
		for j := bLo; j < bHi; j++ {
			out.Added = append(out.Added, j+1)
		}
		return
	}

	prevA, prevB := aLo, bLo
	for _, an := range anchors {
		patience(a, b, prevA, an[0], prevB, an[1], out)
		prevA, prevB = an[0]+1, an[1]+1
	}
	patience(a, b, prevA, aHi, prevB, bHi, out)
}

// uniqueCommonAnchors returns index pairs (i, j) of lines that appear exactly
// once in each range and are equal, as a longest increasing subsequence so the
// anchors are mutually consistent.
func uniqueCommonAnchors(a, b []string, aLo, aHi, bLo, bHi int) [][2]int {
	countA := make(map[string]int)
	posA := make(map[string]int)
	for i := aLo; i < aHi; i++ {
		countA[a[i]]++
		posA[a[i]] = i
	}
	countB := make(map[string]int)
	posB := make(map[string]int)
	for j := bLo; j < bHi; j++ {
		countB[b[j]]++
		posB[b[j]] = j
	}
	var pairs [][2]int
	for i := aLo; i < aHi; i++ {
		line := a[i]
		if countA[line] == 1 && countB[line] == 1 {
			pairs = append(pairs, [2]int{i, posB[line]})
		}
	}
	if len(pairs) == 0 {
		return nil
	}
	// pairs are sorted by i already; take the LIS over j.
	tails := make([]int, 0, len(pairs)) // indices into pairs
	prev := make([]int, len(pairs))
	for k, p := range pairs {
		lo, hi := 0, len(tails)
		for lo < hi {
			mid := (lo + hi) / 2
			if pairs[tails[mid]][1] < p[1] {
				lo = mid + 1
			} else {
				hi = mid
			}
		}
		if lo > 0 {
			prev[k] = tails[lo-1]
		} else {
			prev[k] = -1
		}
		if lo == len(tails) {
			tails = append(tails, k)
		} else {
			tails[lo] = k
		}
	}
	res := make([][2]int, len(tails))
	k := tails[len(tails)-1]
	for idx := len(tails) - 1; idx >= 0; idx-- {
		res[idx] = pairs[k]
		k = prev[k]
	}
	return res
}

// exactLCS aligns a small region with a classic LCS table.
func exactLCS(a, b []string, aLo, aHi, bLo, bHi int, out *LineEdits) {
	n, m := aHi-aLo, bHi-bLo
	dp := make([][]int32, n+1)
	for i := range dp {
		dp[i] = make([]int32, m+1)
	}
	for i := n - 1; i >= 0; i-- {
		for j := m - 1; j >= 0; j-- {
			if a[aLo+i] == b[bLo+j] {
				dp[i][j] = dp[i+1][j+1] + 1
			} else if dp[i+1][j] >= dp[i][j+1] {
				dp[i][j] = dp[i+1][j]
			} else {
				dp[i][j] = dp[i][j+1]
			}
		}
	}
	i, j := 0, 0
	for i < n && j < m {
		switch {
		case a[aLo+i] == b[bLo+j]:
			i++
			j++
		case dp[i+1][j] >= dp[i][j+1]:
			out.Removed = append(out.Removed, aLo+i+1)
			i++
		default:
			out.Added = append(out.Added, bLo+j+1)
			j++
		}
	}
	for ; i < n; i++ {
		out.Removed = append(out.Removed, aLo+i+1)
	}
	for ; j < m; j++ {
		out.Added = append(out.Added, bLo+j+1)
	}
}
