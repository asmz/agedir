// Package scanner tests.
package scanner_test

import (
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/asmz/agedir/internal/scanner"
)

func TestScan_DefaultPatterns(t *testing.T) {
	root := t.TempDir()

	// files that should be matched
	matchFiles := []string{
		"app.jks",
		"cert.p12",
		"google-services.json",
		"google-services-debug.json",
		"GoogleService-Info.plist",
		"GoogleService-Info-Staging.plist",
		"server.pem",
		"private.key",
		".env",
		".env.local",
		".env.production",
	}

	// files that should not be matched
	noMatchFiles := []string{
		"main.go",
		"README.md",
		"config.yaml",
		"services.json",
		"Info.plist",
	}

	for _, f := range matchFiles {
		path := filepath.Join(root, f)
		if err := os.WriteFile(path, []byte("test"), 0o600); err != nil {
			t.Fatalf("failed to create test file: %v", err)
		}
	}
	for _, f := range noMatchFiles {
		path := filepath.Join(root, f)
		if err := os.WriteFile(path, []byte("test"), 0o600); err != nil {
			t.Fatalf("failed to create test file: %v", err)
		}
	}

	s := scanner.New()
	result, err := s.Scan(root)
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}

	if len(result.Matches) != len(matchFiles) {
		t.Errorf("match count: got %d, want %d\nmatches: %v", len(result.Matches), len(matchFiles), result.Matches)
	}

	matchSet := make(map[string]bool)
	for _, m := range result.Matches {
		matchSet[m] = true
	}
	for _, f := range matchFiles {
		if !matchSet[f] {
			t.Errorf("expected file %q not found in matches", f)
		}
	}
}

func TestScan_SubDirectory(t *testing.T) {
	root := t.TempDir()

	subdir := filepath.Join(root, "android", "app")
	if err := os.MkdirAll(subdir, 0o755); err != nil {
		t.Fatalf("failed to create subdirectory: %v", err)
	}
	if err := os.WriteFile(filepath.Join(subdir, "google-services.json"), []byte("test"), 0o600); err != nil {
		t.Fatalf("failed to create test file: %v", err)
	}

	iosDir := filepath.Join(root, "ios", "Runner")
	if err := os.MkdirAll(iosDir, 0o755); err != nil {
		t.Fatalf("failed to create subdirectory: %v", err)
	}
	if err := os.WriteFile(filepath.Join(iosDir, "GoogleService-Info.plist"), []byte("test"), 0o600); err != nil {
		t.Fatalf("failed to create test file: %v", err)
	}

	s := scanner.New()
	result, err := s.Scan(root)
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}

	if len(result.Matches) != 2 {
		t.Fatalf("match count: got %d, want 2\nmatches: %v", len(result.Matches), result.Matches)
	}

	// verify results are returned as relative paths
	sort.Strings(result.Matches)
	want := []string{
		filepath.Join("android", "app", "google-services.json"),
		filepath.Join("ios", "Runner", "GoogleService-Info.plist"),
	}
	sort.Strings(want)
	for i, w := range want {
		if result.Matches[i] != w {
			t.Errorf("result.Matches[%d]: got %q, want %q", i, result.Matches[i], w)
		}
	}
}

func TestScan_EmptyDirectory(t *testing.T) {
	root := t.TempDir()

	s := scanner.New()
	result, err := s.Scan(root)
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}

	if len(result.Matches) != 0 {
		t.Errorf("expected no matches in empty directory, got: %v", result.Matches)
	}
}

func TestScan_InvalidRoot(t *testing.T) {
	s := scanner.New()
	_, err := s.Scan("/nonexistent/path/that/does/not/exist")
	if err == nil {
		t.Error("expected error for non-existent root, got nil")
	}
}

func TestDefaultPatterns(t *testing.T) {
	patterns := scanner.DefaultPatterns
	if len(patterns) == 0 {
		t.Error("DefaultPatterns is empty")
	}

	required := []string{"*.jks", "*.p12", "google-services*.json", "GoogleService-Info*.plist", "*.pem", "*.key", ".env", ".env.*"}
	patternSet := make(map[string]bool)
	for _, p := range patterns {
		patternSet[p] = true
	}
	for _, r := range required {
		if !patternSet[r] {
			t.Errorf("required pattern %q not found in DefaultPatterns", r)
		}
	}
}
