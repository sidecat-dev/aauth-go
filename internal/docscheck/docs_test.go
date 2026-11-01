package docscheck

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

const root = "../.."

// pages returns README.md and every Markdown page under docs/, relative to
// the repository root.
func pages(t *testing.T) []string {
	t.Helper()
	found := []string{"README.md"}
	err := filepath.WalkDir(filepath.Join(root, "docs"), func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !entry.IsDir() && strings.HasSuffix(path, ".md") {
			relative, err := filepath.Rel(root, path)
			if err != nil {
				return err
			}
			found = append(found, filepath.ToSlash(relative))
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(found[1:])
	return found
}

func read(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(root, path))
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

var sampleMarker = regexp.MustCompile(`^<!-- sample: (\S+) -->$`)

// A quoted sample is the fenced block right after `<!-- sample: PATH -->`.
// Its lines must appear, in order and unchanged, in PATH, which the build
// compiles; the whole block may sit deeper in PATH by a run of tabs. Every
// `go` block needs a marker.
func TestSamplesMatchTheirSources(t *testing.T) {
	for _, page := range pages(t) {
		lines := strings.Split(read(t, page), "\n")
		for i := 0; i < len(lines); i++ {
			source := ""
			if match := sampleMarker.FindStringSubmatch(lines[i]); match != nil {
				source = match[1]
				i++
				if i >= len(lines) || !strings.HasPrefix(lines[i], "```") {
					t.Errorf("%s:%d: sample marker for %s has no code block after it", page, i, source)
					continue
				}
			} else if !strings.HasPrefix(lines[i], "```") {
				continue
			} else if strings.HasPrefix(lines[i], "```go") {
				t.Errorf("%s:%d: Go block has no sample marker", page, i+1)
			}
			start := i + 1
			for i++; i < len(lines) && lines[i] != "```"; i++ {
			}
			if source == "" {
				continue
			}
			if !contains(read(t, source), lines[start:i]) {
				t.Errorf("%s:%d: sample no longer matches %s", page, start, source)
			}
		}
	}
}

func contains(text string, block []string) bool {
	for indent := ""; len(indent) <= 4; indent += "\t" {
		var shifted strings.Builder
		for _, line := range block {
			if line != "" {
				shifted.WriteString(indent)
			}
			shifted.WriteString(line)
			shifted.WriteString("\n")
		}
		if strings.Contains(text, shifted.String()) {
			return true
		}
	}
	return false
}

var link = regexp.MustCompile(`\]\(([^)\s]+)\)`)

func TestRelativeLinksResolve(t *testing.T) {
	for _, page := range pages(t) {
		for _, target := range link.FindAllStringSubmatch(prose(read(t, page)), -1) {
			target := target[1]
			if strings.Contains(target, "://") || strings.HasPrefix(target, "mailto:") {
				continue
			}
			file, anchor, _ := strings.Cut(target, "#")
			path := page
			if file != "" {
				path = filepath.ToSlash(filepath.Join(filepath.Dir(page), file))
			}
			if _, err := os.Stat(filepath.Join(root, path)); err != nil {
				t.Errorf("%s: broken link %s", page, target)
				continue
			}
			if anchor != "" && strings.HasSuffix(path, ".md") && !hasAnchor(read(t, path), anchor) {
				t.Errorf("%s: no heading for %s", page, target)
			}
		}
	}
}

// prose drops fenced code blocks, where `](` is code, not a link.
func prose(text string) string {
	var kept strings.Builder
	fenced := false
	for _, line := range strings.Split(text, "\n") {
		if strings.HasPrefix(line, "```") {
			fenced = !fenced
			continue
		}
		if !fenced {
			kept.WriteString(line)
			kept.WriteString("\n")
		}
	}
	return kept.String()
}

var (
	punctuation = regexp.MustCompile(`[^a-z0-9 _-]`)
	hyphens     = regexp.MustCompile(`-+`)
)

// hasAnchor reports whether a heading in text has GitLab's anchor for it:
// lowercase, punctuation dropped, spaces to hyphens, runs of hyphens to one.
func hasAnchor(text, anchor string) bool {
	for _, line := range strings.Split(prose(text), "\n") {
		if !strings.HasPrefix(line, "#") {
			continue
		}
		heading := strings.TrimSpace(strings.TrimLeft(line, "#"))
		slug := punctuation.ReplaceAllString(strings.ToLower(heading), "")
		slug = hyphens.ReplaceAllString(strings.ReplaceAll(slug, " ", "-"), "-")
		if slug == anchor {
			return true
		}
	}
	return false
}

var pin = regexp.MustCompile(`gitlab\.com/sidecat-dev/aauth-go@([0-9a-f]+)`)

// The pages that say which commit to install name the same one.
func TestPinnedRevisionAgrees(t *testing.T) {
	found := map[string][]string{}
	for _, page := range []string{"README.md", "docs/getting-started.md", "USE-IN-YOUR-SERVICE.md"} {
		matches := pin.FindAllStringSubmatch(read(t, page), -1)
		if len(matches) == 0 {
			t.Errorf("%s names no revision to install", page)
		}
		for _, match := range matches {
			found[match[1]] = append(found[match[1]], page)
		}
	}
	if len(found) != 1 {
		t.Fatalf("the install instructions name these revisions: %v", found)
	}
}
