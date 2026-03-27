package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/asmz/agedir/internal/config"
	"github.com/asmz/agedir/internal/scanner"
)

func TestRunInit_GeneratesConfigFile(t *testing.T) {
	dir := t.TempDir()

	// create a file that should be detected by the scanner
	os.WriteFile(filepath.Join(dir, "google-services.json"), []byte("{}"), 0o644)

	cfgPath := filepath.Join(dir, "agedir.yaml")
	cmd, out, _ := newTestCmd()
	opts := initOpts{configPath: cfgPath, root: dir}

	if err := runInit(cmd, opts, config.New(), scanner.New()); err != nil {
		t.Fatalf("runInit() returned unexpected error: %v", err)
	}

	if _, err := os.Stat(cfgPath); os.IsNotExist(err) {
		t.Error("agedir.yaml was not created")
	}

	if !strings.Contains(out.String(), "agedir.yaml") {
		t.Errorf("completion message not printed: %q", out.String())
	}
}

func TestRunInit_ScannedFilesAppearInMapping(t *testing.T) {
	dir := t.TempDir()

	// create multiple files that should be detected
	os.WriteFile(filepath.Join(dir, "service.key"), []byte("key"), 0o644)
	os.WriteFile(filepath.Join(dir, "cert.pem"), []byte("cert"), 0o644)

	cfgPath := filepath.Join(dir, "agedir.yaml")
	cmd, _, _ := newTestCmd()
	opts := initOpts{configPath: cfgPath, root: dir}

	if err := runInit(cmd, opts, config.New(), scanner.New()); err != nil {
		t.Fatalf("runInit() returned unexpected error: %v", err)
	}

	content, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatalf("cannot read agedir.yaml: %v", err)
	}

	cfgContent := string(content)
	if !strings.Contains(cfgContent, "service.key") {
		t.Errorf("service.key not found in mapping: %q", cfgContent)
	}
	if !strings.Contains(cfgContent, "cert.pem") {
		t.Errorf("cert.pem not found in mapping: %q", cfgContent)
	}
}

func TestRunInit_UpdatesGitignore(t *testing.T) {
	dir := t.TempDir()

	os.WriteFile(filepath.Join(dir, "service.key"), []byte("key"), 0o644)

	cfgPath := filepath.Join(dir, "agedir.yaml")
	cmd, _, _ := newTestCmd()
	opts := initOpts{configPath: cfgPath, root: dir}

	if err := runInit(cmd, opts, config.New(), scanner.New()); err != nil {
		t.Fatalf("runInit() returned unexpected error: %v", err)
	}

	gitignorePath := filepath.Join(dir, ".gitignore")
	gitignoreContent, err := os.ReadFile(gitignorePath)
	if err != nil {
		t.Fatalf(".gitignore was not created: %v", err)
	}

	if !strings.Contains(string(gitignoreContent), "service.key") {
		t.Errorf("service.key not added to .gitignore: %q", string(gitignoreContent))
	}
}

func TestRunInit_ExistingConfigCancelledByNo(t *testing.T) {
	dir := t.TempDir()

	cfgPath := filepath.Join(dir, "agedir.yaml")
	originalContent := []byte("version: \"1\"\nrecipients:\n  - age1xxx\nmapping:\n  - src: old.age\n    dest: old.txt\n")
	os.WriteFile(cfgPath, originalContent, 0o644)

	cmd, out, _ := newTestCmd()
	cmd.SetIn(strings.NewReader("n\n"))
	opts := initOpts{configPath: cfgPath, root: dir}

	if err := runInit(cmd, opts, config.New(), scanner.New()); err != nil {
		t.Fatalf("runInit() returned unexpected error: %v", err)
	}

	newContent, _ := os.ReadFile(cfgPath)
	if string(newContent) != string(originalContent) {
		t.Error("agedir.yaml was modified after answering 'n'")
	}

	if !strings.Contains(out.String(), "cancelled") {
		t.Errorf("cancellation message not printed: %q", out.String())
	}
}

func TestRunInit_ExistingConfigOverwrittenByYes(t *testing.T) {
	dir := t.TempDir()

	cfgPath := filepath.Join(dir, "agedir.yaml")
	os.WriteFile(cfgPath, []byte("version: \"1\"\nrecipients:\n  - old_key_xxx\nmapping:\n  - src: old.age\n    dest: old.txt\n"), 0o644)

	// create a new file that should be picked up by the scanner
	os.WriteFile(filepath.Join(dir, "new.key"), []byte("new key"), 0o644)

	cmd, _, _ := newTestCmd()
	cmd.SetIn(strings.NewReader("y\n"))
	opts := initOpts{configPath: cfgPath, root: dir}

	if err := runInit(cmd, opts, config.New(), scanner.New()); err != nil {
		t.Fatalf("runInit() returned unexpected error: %v", err)
	}

	newContent, _ := os.ReadFile(cfgPath)
	if strings.Contains(string(newContent), "old_key_xxx") {
		t.Error("agedir.yaml was not overwritten after answering 'y' (old content remains)")
	}
}

func TestRunInit_NoSensitiveFilesGeneratesEmptyMapping(t *testing.T) {
	dir := t.TempDir()

	// no sensitive files; only a regular text file
	os.WriteFile(filepath.Join(dir, "README.md"), []byte("readme"), 0o644)

	cfgPath := filepath.Join(dir, "agedir.yaml")
	cmd, out, _ := newTestCmd()
	opts := initOpts{configPath: cfgPath, root: dir}

	if err := runInit(cmd, opts, config.New(), scanner.New()); err != nil {
		t.Fatalf("runInit() returned unexpected error: %v", err)
	}

	if _, err := os.Stat(cfgPath); os.IsNotExist(err) {
		t.Error("agedir.yaml was not created")
	}

	if !strings.Contains(out.String(), "agedir.yaml") {
		t.Errorf("completion message not printed: %q", out.String())
	}
}
