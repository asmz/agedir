// Package config provides loading, validation, and generation of agedir.yaml configuration.
package config

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// Sentinel errors.
var (
	ErrConfigNotFound = errors.New("agedir.yaml not found; run `agedir init` to create one")
	ErrNoRecipients   = errors.New("recipients must have at least one public key")
	ErrEmptyMapping   = errors.New("mapping must have at least one entry")
	ErrConfigExists   = errors.New("agedir.yaml already exists; delete it manually to overwrite")
)

const defaultStorageDir = ".agedir/secrets"

// Config represents the full agedir.yaml configuration.
type Config struct {
	Version    string        `yaml:"version"`
	Recipients []string      `yaml:"recipients"`
	StorageDir string        `yaml:"storage_dir"`
	Mapping    []FileMapping `yaml:"mapping"`
}

// FileMapping represents a 1:1 mapping between an encrypted file (Src) and a plaintext file (Dest).
type FileMapping struct {
	Src  string `yaml:"src"`
	Dest string `yaml:"dest"`
}

// ConfigLoader provides load, generate, and gitignore management for config files.
type ConfigLoader interface {
	// Load reads agedir.yaml from path and returns a validated Config.
	// If path is empty, it defaults to agedir.yaml in the current directory.
	Load(path string) (*Config, error)

	// Generate writes cfg as agedir.yaml to path.
	// Returns ErrConfigExists if the file already exists (no overwrite).
	Generate(cfg *Config, path string) error

	// AppendGitignore appends entries to .gitignore without duplicates.
	// Creates the file if it does not exist.
	AppendGitignore(gitignorePath string, entries []string) error
}

type loader struct{}

// New returns a ConfigLoader implementation.
func New() ConfigLoader {
	return &loader{}
}

func (l *loader) Load(path string) (*Config, error) {
	if path == "" {
		path = "agedir.yaml"
	}

	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("%w: %s", ErrConfigNotFound, path)
		}
		return nil, fmt.Errorf("failed to read agedir.yaml: %w", err)
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("failed to parse agedir.yaml (%s): %w", path, err)
	}

	// apply default value
	if cfg.StorageDir == "" {
		cfg.StorageDir = defaultStorageDir
	}

	if err := validate(&cfg); err != nil {
		return nil, err
	}

	return &cfg, nil
}

func validate(cfg *Config) error {
	if len(cfg.Recipients) == 0 {
		return ErrNoRecipients
	}
	if len(cfg.Mapping) == 0 {
		return ErrEmptyMapping
	}

	seen := make(map[string]bool, len(cfg.Mapping))
	for i, m := range cfg.Mapping {
		if m.Src == "" {
			return fmt.Errorf("mapping[%d].src is empty", i)
		}
		if m.Dest == "" {
			return fmt.Errorf("mapping[%d].dest is empty", i)
		}
		if seen[m.Dest] {
			return fmt.Errorf("duplicate dest in mapping: %q", m.Dest)
		}
		seen[m.Dest] = true
	}

	return nil
}

func (l *loader) Generate(cfg *Config, path string) error {
	if _, err := os.Stat(path); err == nil {
		return ErrConfigExists
	}

	data, err := yaml.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("failed to serialize config: %w", err)
	}

	if err := os.WriteFile(path, data, 0o600); err != nil {
		return fmt.Errorf("failed to write agedir.yaml: %w", err)
	}

	return nil
}

func (l *loader) AppendGitignore(gitignorePath string, entries []string) error {
	// build a set of existing entries to detect duplicates
	existing := make(map[string]bool)
	if data, err := os.ReadFile(gitignorePath); err == nil {
		scanner := bufio.NewScanner(strings.NewReader(string(data)))
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line != "" {
				existing[line] = true
			}
		}
	}

	// filter to only entries that need to be added
	var toAppend []string
	for _, e := range entries {
		if e != "" && !existing[e] {
			toAppend = append(toAppend, e)
		}
	}
	if len(toAppend) == 0 {
		return nil
	}

	f, err := os.OpenFile(gitignorePath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return fmt.Errorf("failed to write .gitignore: %w", err)
	}
	defer f.Close()

	for _, e := range toAppend {
		if _, err := fmt.Fprintln(f, e); err != nil {
			return fmt.Errorf("failed to append to .gitignore: %w", err)
		}
	}

	return nil
}
