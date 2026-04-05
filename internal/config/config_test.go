package config_test

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/asmz/agedir/internal/config"
)

// ---- test helpers ----

func writeFile(t *testing.T, dir, name, content string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("writeFile: %v", err)
	}
	return path
}

func tempDir(t *testing.T) string {
	t.Helper()
	d, err := os.MkdirTemp("", "agedir-test-*")
	if err != nil {
		t.Fatalf("MkdirTemp: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(d) })
	return d
}

// ---- Load tests ----

const validYAML = `
version: "1"
recipients:
  - age1abc123
storage_dir: ".agedir/secrets"
mapping:
  - enc: "secret.json.age"
    raw: "android/app/secret.json"
`

func TestLoad_ValidConfig(t *testing.T) {
	dir := tempDir(t)
	path := writeFile(t, dir, "agedir.yaml", validYAML)

	loader := config.New()
	cfg, err := loader.Load(path)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	if cfg.Version != "1" {
		t.Errorf("Version = %q, want %q", cfg.Version, "1")
	}
	if len(cfg.Recipients) != 1 || cfg.Recipients[0] != "age1abc123" {
		t.Errorf("Recipients = %v, want [age1abc123]", cfg.Recipients)
	}
	if cfg.StorageDir != ".agedir/secrets" {
		t.Errorf("StorageDir = %q, want %q", cfg.StorageDir, ".agedir/secrets")
	}
	if len(cfg.Mapping) != 1 {
		t.Fatalf("Mapping len = %d, want 1", len(cfg.Mapping))
	}
	if cfg.Mapping[0].Enc != "secret.json.age" || cfg.Mapping[0].Raw != "android/app/secret.json" {
		t.Errorf("Mapping[0] = %+v", cfg.Mapping[0])
	}
}

func TestLoad_DefaultStorageDir(t *testing.T) {
	dir := tempDir(t)
	yaml := `
version: "1"
recipients:
  - age1abc123
mapping:
  - enc: "a.age"
    raw: "a.txt"
`
	path := writeFile(t, dir, "agedir.yaml", yaml)

	loader := config.New()
	cfg, err := loader.Load(path)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.StorageDir != ".agedir/secrets" {
		t.Errorf("StorageDir = %q, want default %q", cfg.StorageDir, ".agedir/secrets")
	}
}

func TestLoad_FileNotFound(t *testing.T) {
	loader := config.New()
	_, err := loader.Load("/nonexistent/path/agedir.yaml")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !errors.Is(err, config.ErrConfigNotFound) {
		t.Errorf("error = %v, want ErrConfigNotFound", err)
	}
	if !strings.Contains(err.Error(), "agedir init") {
		t.Errorf("error message should mention 'agedir init', got: %v", err)
	}
}

func TestLoad_EmptyRecipientsIsAllowed(t *testing.T) {
	dir := tempDir(t)
	yaml := `
version: "1"
recipients: []
mapping:
  - enc: "a.age"
    raw: "a.txt"
`
	path := writeFile(t, dir, "agedir.yaml", yaml)
	loader := config.New()
	if _, err := loader.Load(path); err != nil {
		t.Errorf("expected no error for empty recipients (passphrase mode), got: %v", err)
	}
}

func TestLoad_EmptyMapping(t *testing.T) {
	dir := tempDir(t)
	yaml := `
version: "1"
recipients:
  - age1abc123
mapping: []
`
	path := writeFile(t, dir, "agedir.yaml", yaml)
	loader := config.New()
	_, err := loader.Load(path)
	if !errors.Is(err, config.ErrEmptyMapping) {
		t.Errorf("error = %v, want ErrEmptyMapping", err)
	}
}

func TestLoad_EmptyEncInMapping(t *testing.T) {
	dir := tempDir(t)
	yaml := `
version: "1"
recipients:
  - age1abc123
mapping:
  - enc: ""
    raw: "a.txt"
`
	path := writeFile(t, dir, "agedir.yaml", yaml)
	loader := config.New()
	_, err := loader.Load(path)
	if err == nil {
		t.Fatal("expected error for empty enc, got nil")
	}
}

func TestLoad_EmptyRawInMapping(t *testing.T) {
	dir := tempDir(t)
	yaml := `
version: "1"
recipients:
  - age1abc123
mapping:
  - enc: "a.age"
    raw: ""
`
	path := writeFile(t, dir, "agedir.yaml", yaml)
	loader := config.New()
	_, err := loader.Load(path)
	if err == nil {
		t.Fatal("expected error for empty raw, got nil")
	}
}

func TestLoad_DuplicateRaw(t *testing.T) {
	dir := tempDir(t)
	yaml := `
version: "1"
recipients:
  - age1abc123
mapping:
  - enc: "a.age"
    raw: "shared.txt"
  - enc: "b.age"
    raw: "shared.txt"
`
	path := writeFile(t, dir, "agedir.yaml", yaml)
	loader := config.New()
	_, err := loader.Load(path)
	if err == nil {
		t.Fatal("expected error for duplicate raw, got nil")
	}
}

// ---- Generate tests ----

func TestGenerate_WritesFile(t *testing.T) {
	dir := tempDir(t)
	path := filepath.Join(dir, "agedir.yaml")

	cfg := &config.Config{
		Version:    "1",
		Recipients: []string{"age1abc123"},
		StorageDir: ".agedir/secrets",
		Mapping: []config.FileMapping{
			{Raw: "secret.txt", Enc: "secret.age"},
		},
	}

	loader := config.New()
	if err := loader.Generate(cfg, path); err != nil {
		t.Fatalf("Generate() error = %v", err)
	}

	if _, err := os.Stat(path); err != nil {
		t.Fatalf("file not created: %v", err)
	}

	// reload and verify content
	loaded, err := loader.Load(path)
	if err != nil {
		t.Fatalf("Load() after Generate() error = %v", err)
	}
	if loaded.Recipients[0] != "age1abc123" {
		t.Errorf("Recipients = %v", loaded.Recipients)
	}
}

func TestGenerate_ErrorIfExists(t *testing.T) {
	dir := tempDir(t)
	path := writeFile(t, dir, "agedir.yaml", validYAML)

	loader := config.New()
	err := loader.Generate(&config.Config{}, path)
	if !errors.Is(err, config.ErrConfigExists) {
		t.Errorf("error = %v, want ErrConfigExists", err)
	}
}

// ---- AppendGitignore tests ----

func TestAppendGitignore_CreatesFile(t *testing.T) {
	dir := tempDir(t)
	path := filepath.Join(dir, ".gitignore")

	loader := config.New()
	if err := loader.AppendGitignore(path, []string{"secret.txt", "key.pem"}); err != nil {
		t.Fatalf("AppendGitignore() error = %v", err)
	}

	data, _ := os.ReadFile(path)
	content := string(data)
	if !strings.Contains(content, "secret.txt") || !strings.Contains(content, "key.pem") {
		t.Errorf("gitignore content = %q", content)
	}
}

func TestAppendGitignore_NoDuplicates(t *testing.T) {
	dir := tempDir(t)
	path := writeFile(t, dir, ".gitignore", "secret.txt\n")

	loader := config.New()
	if err := loader.AppendGitignore(path, []string{"secret.txt", "new.txt"}); err != nil {
		t.Fatalf("AppendGitignore() error = %v", err)
	}

	data, _ := os.ReadFile(path)
	content := string(data)
	// secret.txt must not be duplicated
	count := strings.Count(content, "secret.txt")
	if count != 1 {
		t.Errorf("secret.txt appears %d times, want 1", count)
	}
	if !strings.Contains(content, "new.txt") {
		t.Errorf("new.txt not found in gitignore")
	}
}

func TestAppendGitignore_AppendsToExisting(t *testing.T) {
	dir := tempDir(t)
	path := writeFile(t, dir, ".gitignore", "existing.txt\n")

	loader := config.New()
	if err := loader.AppendGitignore(path, []string{"new.txt"}); err != nil {
		t.Fatalf("AppendGitignore() error = %v", err)
	}

	data, _ := os.ReadFile(path)
	content := string(data)
	if !strings.Contains(content, "existing.txt") {
		t.Errorf("existing entry was lost: %q", content)
	}
	if !strings.Contains(content, "new.txt") {
		t.Errorf("new entry not appended: %q", content)
	}
}
