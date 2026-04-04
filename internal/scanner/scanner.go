// Package scanner provides detection of sensitive file candidates within a project.
package scanner

import (
	"io/fs"
	"os/exec"
	"path/filepath"
)

// DefaultPatterns are the constant file name patterns used to detect sensitive files.
var DefaultPatterns = []string{
	"*.jks",
	"*.p12",
	"google-services*.json",
	"GoogleService-Info*.plist",
	"*.pem",
	"*.key",
}

// fallbackExcludeDirs is used when git is unavailable to skip well-known third-party package directories.
var fallbackExcludeDirs = map[string]bool{
	"node_modules": true,
	".bundle":      true,
	"Pods":         true,
	".dart_tool":   true,
}

// ScanResult holds the results of a scan operation.
type ScanResult struct {
	Matches []string // relative paths from root
}

// Scanner is the interface for scanning directories and detecting sensitive file candidates.
type Scanner interface {
	// Scan walks root and returns files matching the default patterns.
	Scan(root string) (ScanResult, error)
}

type scanner struct{}

// New returns a new Scanner instance.
func New() Scanner {
	return &scanner{}
}

// Scan recursively walks root and lists files matching DefaultPatterns.
// Directories ignored by git (or in the fallback exclusion list) are skipped.
// Results are returned as relative paths from root.
func (s *scanner) Scan(root string) (ScanResult, error) {
	var matches []string

	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if path == root {
				return nil
			}
			rel, relErr := filepath.Rel(root, path)
			if relErr != nil {
				return relErr
			}
			if isGitIgnoredDir(root, rel) {
				return filepath.SkipDir
			}
			return nil
		}

		name := d.Name()
		for _, pattern := range DefaultPatterns {
			matched, matchErr := filepath.Match(pattern, name)
			if matchErr != nil {
				return matchErr
			}
			if matched {
				rel, relErr := filepath.Rel(root, path)
				if relErr != nil {
					return relErr
				}
				matches = append(matches, rel)
				break
			}
		}
		return nil
	})
	if err != nil {
		return ScanResult{}, err
	}

	return ScanResult{Matches: matches}, nil
}

// isGitIgnoredDir reports whether relPath (relative to root) is ignored by git.
// Falls back to checking fallbackExcludeDirs by directory base name when git is unavailable.
func isGitIgnoredDir(root, relPath string) bool {
	cmd := exec.Command("git", "check-ignore", "-q", relPath)
	cmd.Dir = root
	if cmd.Run() == nil {
		return true
	}
	return fallbackExcludeDirs[filepath.Base(relPath)]
}
