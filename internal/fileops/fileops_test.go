package fileops_test

import (
	"bytes"
	"crypto/sha256"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/asmz/agedir/internal/fileops"
)

func TestEnsureDir(t *testing.T) {
	t.Run("creates a non-existent directory", func(t *testing.T) {
		dir := t.TempDir()
		target := filepath.Join(dir, "a", "b", "c")
		svc := fileops.New()
		if err := svc.EnsureDir(target); err != nil {
			t.Fatalf("EnsureDir error: %v", err)
		}
		info, err := os.Stat(target)
		if err != nil {
			t.Fatalf("cannot stat created directory: %v", err)
		}
		if !info.IsDir() {
			t.Fatalf("path is not a directory")
		}
	})

	t.Run("is a no-op for an existing directory", func(t *testing.T) {
		dir := t.TempDir()
		svc := fileops.New()
		if err := svc.EnsureDir(dir); err != nil {
			t.Fatalf("EnsureDir on existing dir error: %v", err)
		}
	})
}

func TestHashFile(t *testing.T) {
	t.Run("returns SHA-256 hash of a file", func(t *testing.T) {
		content := []byte("hello world")
		f, err := os.CreateTemp(t.TempDir(), "hash-test")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.Write(content); err != nil {
			t.Fatal(err)
		}
		f.Close()

		svc := fileops.New()
		got, err := svc.HashFile(f.Name())
		if err != nil {
			t.Fatalf("HashFile error: %v", err)
		}

		want := sha256.Sum256(content)
		if !bytes.Equal(got, want[:]) {
			t.Errorf("hash mismatch: got %x, want %x", got, want)
		}
	})

	t.Run("returns error for a non-existent file", func(t *testing.T) {
		svc := fileops.New()
		_, err := svc.HashFile("/nonexistent/path/file.txt")
		if err == nil {
			t.Fatal("expected error, got nil")
		}
	})
}

func TestPlace_Basic(t *testing.T) {
	t.Run("places file at dest path", func(t *testing.T) {
		dir := t.TempDir()
		destPath := filepath.Join(dir, "sub", "output.txt")
		content := "secret content"

		svc := fileops.New()
		result, err := svc.Place(strings.NewReader(content), destPath, fileops.PlaceOptions{})
		if err != nil {
			t.Fatalf("Place error: %v", err)
		}
		if !result.Written {
			t.Error("Written should be true")
		}
		if result.Skipped {
			t.Error("Skipped should be false")
		}

		got, err := os.ReadFile(destPath)
		if err != nil {
			t.Fatalf("cannot read placed file: %v", err)
		}
		if string(got) != content {
			t.Errorf("content mismatch: got %q, want %q", got, content)
		}
	})

	t.Run("auto-creates dest directory when missing", func(t *testing.T) {
		dir := t.TempDir()
		destPath := filepath.Join(dir, "a", "b", "c", "file.txt")

		svc := fileops.New()
		_, err := svc.Place(strings.NewReader("data"), destPath, fileops.PlaceOptions{})
		if err != nil {
			t.Fatalf("Place error: %v", err)
		}

		if _, err := os.Stat(destPath); err != nil {
			t.Fatalf("file not found: %v", err)
		}
	})

	t.Run("converts slash-separated paths to OS-native separator", func(t *testing.T) {
		dir := t.TempDir()
		slashPath := filepath.ToSlash(filepath.Join(dir, "sub", "file.txt"))

		svc := fileops.New()
		_, err := svc.Place(strings.NewReader("data"), slashPath, fileops.PlaceOptions{})
		if err != nil {
			t.Fatalf("Place error: %v", err)
		}
	})
}

func TestPlace_DryRun(t *testing.T) {
	t.Run("does not write file in dry-run mode", func(t *testing.T) {
		dir := t.TempDir()
		destPath := filepath.Join(dir, "should-not-exist.txt")

		svc := fileops.New()
		result, err := svc.Place(strings.NewReader("data"), destPath, fileops.PlaceOptions{DryRun: true})
		if err != nil {
			t.Fatalf("Place error: %v", err)
		}
		if result.Written {
			t.Error("Written should be false in dry-run mode")
		}

		if _, err := os.Stat(destPath); !os.IsNotExist(err) {
			t.Error("file must not be created in dry-run mode")
		}
	})
}

func TestPlace_Verify(t *testing.T) {
	t.Run("skips write when hash matches", func(t *testing.T) {
		dir := t.TempDir()
		destPath := filepath.Join(dir, "file.txt")
		content := "unchanged content"

		if err := os.WriteFile(destPath, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}

		svc := fileops.New()
		result, err := svc.Place(strings.NewReader(content), destPath, fileops.PlaceOptions{Verify: true})
		if err != nil {
			t.Fatalf("Place error: %v", err)
		}
		if !result.Skipped {
			t.Error("Skipped should be true when hash matches")
		}
		if result.Written {
			t.Error("Written should be false when skipped")
		}
	})

	t.Run("writes when hash differs", func(t *testing.T) {
		dir := t.TempDir()
		destPath := filepath.Join(dir, "file.txt")

		if err := os.WriteFile(destPath, []byte("old content"), 0o600); err != nil {
			t.Fatal(err)
		}

		svc := fileops.New()
		newContent := "new content"
		result, err := svc.Place(strings.NewReader(newContent), destPath, fileops.PlaceOptions{Verify: true})
		if err != nil {
			t.Fatalf("Place error: %v", err)
		}
		if result.Skipped {
			t.Error("Skipped should be false when hash differs")
		}
		if !result.Written {
			t.Error("Written should be true when hash differs")
		}

		got, err := os.ReadFile(destPath)
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != newContent {
			t.Errorf("content not updated: got %q, want %q", got, newContent)
		}
	})

	t.Run("writes when file does not exist", func(t *testing.T) {
		dir := t.TempDir()
		destPath := filepath.Join(dir, "new-file.txt")

		svc := fileops.New()
		result, err := svc.Place(strings.NewReader("content"), destPath, fileops.PlaceOptions{Verify: true})
		if err != nil {
			t.Fatalf("Place error: %v", err)
		}
		if result.Skipped {
			t.Error("Skipped should be false for a new file")
		}
		if !result.Written {
			t.Error("Written should be true for a new file")
		}
	})
}

func TestPlace_Atomic(t *testing.T) {
	t.Run("atomic write updates existing file", func(t *testing.T) {
		dir := t.TempDir()
		destPath := filepath.Join(dir, "file.txt")
		original := "original content"
		updated := "updated content"

		if err := os.WriteFile(destPath, []byte(original), 0o600); err != nil {
			t.Fatal(err)
		}

		svc := fileops.New()
		_, err := svc.Place(strings.NewReader(updated), destPath, fileops.PlaceOptions{})
		if err != nil {
			t.Fatalf("Place error: %v", err)
		}

		got, err := os.ReadFile(destPath)
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != updated {
			t.Errorf("content not updated: got %q, want %q", got, updated)
		}
	})
}
