// Package fileops provides placement, SHA-256 verification, and atomic writes for secret files.
package fileops

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// PlaceOptions controls the behavior of Place.
type PlaceOptions struct {
	DryRun bool // if true, no file writes are performed
	Verify bool // if true, skip writing when the existing file hash matches
}

// PlaceResult reports the outcome of a Place call.
type PlaceResult struct {
	Skipped bool // true when Verify=true and the hash matched
	Written bool // true when the file was actually written
}

// FileOps is the interface for secret file placement and verification.
type FileOps interface {
	// Place writes the content of src to destPath, creating parent directories automatically.
	Place(src io.Reader, destPath string, opts PlaceOptions) (PlaceResult, error)

	// HashFile returns the SHA-256 hash of the file at path.
	HashFile(path string) ([]byte, error)

	// EnsureDir creates the directory at path (no-op if it already exists).
	EnsureDir(path string) error
}

type service struct{}

// New returns a FileOps implementation.
func New() FileOps {
	return &service{}
}

// EnsureDir creates the directory at path using os.MkdirAll.
func (s *service) EnsureDir(path string) error {
	if err := os.MkdirAll(path, 0o700); err != nil {
		return fmt.Errorf("failed to create directory %q: %w", path, err)
	}
	return nil
}

// HashFile reads the file at path and returns its SHA-256 hash.
func (s *service) HashFile(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("cannot open file %q: %w", path, err)
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return nil, fmt.Errorf("read error during hash computation %q: %w", path, err)
	}

	return h.Sum(nil), nil
}

// Place writes the content of src to destPath.
// DryRun=true skips actual writes.
// Verify=true skips writing when the existing file hash matches.
func (s *service) Place(src io.Reader, destPath string, opts PlaceOptions) (PlaceResult, error) {
	// convert slash-separated paths (from YAML) to the OS-native separator
	destPath = filepath.FromSlash(destPath)

	if opts.DryRun {
		fmt.Printf("[dry-run] %s\n", destPath)
		return PlaceResult{Written: false}, nil
	}

	// read src into memory for both hash comparison and writing
	srcData, err := io.ReadAll(src)
	if err != nil {
		return PlaceResult{}, fmt.Errorf("failed to read source: %w", err)
	}

	// skip if verify mode and hashes match
	if opts.Verify {
		existingHash, err := s.HashFile(destPath)
		if err == nil {
			newHash := sha256.Sum256(srcData)
			if bytes.Equal(existingHash, newHash[:]) {
				return PlaceResult{Skipped: true, Written: false}, nil
			}
		}
		// file not found or hash differs: proceed with write
	}

	// create dest directory if needed
	destDir := filepath.Dir(destPath)
	if err := s.EnsureDir(destDir); err != nil {
		return PlaceResult{}, err
	}

	// atomic write: write to a temp file then rename
	tmpFile, err := os.CreateTemp(destDir, ".agedir-tmp-*")
	if err != nil {
		return PlaceResult{}, fmt.Errorf("failed to create temporary file: %w", err)
	}
	tmpPath := tmpFile.Name()

	// clean up temp file on failure
	defer func() {
		if _, err := os.Stat(tmpPath); err == nil {
			os.Remove(tmpPath)
		}
	}()

	if _, err := tmpFile.Write(srcData); err != nil {
		tmpFile.Close()
		return PlaceResult{}, fmt.Errorf("failed to write to temporary file: %w", err)
	}
	if err := tmpFile.Close(); err != nil {
		return PlaceResult{}, fmt.Errorf("failed to close temporary file: %w", err)
	}

	if err := os.Rename(tmpPath, destPath); err != nil {
		return PlaceResult{}, fmt.Errorf("failed to place file %q: %w", destPath, err)
	}

	return PlaceResult{Written: true}, nil
}
