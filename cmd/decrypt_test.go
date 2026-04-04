package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/asmz/agedir/internal/config"
	"github.com/asmz/agedir/internal/crypto"
	"github.com/asmz/agedir/internal/fileops"
)

func TestDecryptCmd_HasFlags(t *testing.T) {
	flags := decryptCmd.Flags()
	for _, name := range []string{"identity", "verify", "dry-run", "config"} {
		if flags.Lookup(name) == nil {
			t.Errorf("flag --%s is not registered", name)
		}
	}
	if flags.ShorthandLookup("i") == nil {
		t.Error("flag -i is not registered")
	}
	if flags.ShorthandLookup("p") == nil {
		t.Error("flag -p is not registered")
	}
}

func TestRunDecrypt_SuccessfulDecryption(t *testing.T) {
	dir := t.TempDir()
	kp := generateTestKeyPair(t)

	content := []byte("secret data")
	storageDir := filepath.Join(dir, ".agedir", "secrets")
	os.MkdirAll(storageDir, 0o755)

	encBytes := encryptContent(t, content, kp.pubkey)
	os.WriteFile(filepath.Join(storageDir, "secret.txt.age"), encBytes, 0o600)

	destPath := filepath.Join(dir, "secret.txt")
	cfg := &config.Config{
		Version:    "1",
		Recipients: []string{kp.pubkey},
		StorageDir: storageDir,
		Mapping:    []config.FileMapping{{Raw: destPath, Enc: "secret.txt.age"}},
	}
	cfgPath := filepath.Join(dir, "agedir.yaml")
	writeAgedir(t, cfgPath, cfg)

	cmd, out, _ := newTestCmd()
	opts := decryptOpts{identityFile: kp.identityFilePath, configPath: cfgPath}

	if err := runDecrypt(cmd, opts, config.New(), crypto.New(), fileops.New()); err != nil {
		t.Fatalf("runDecrypt() returned unexpected error: %v", err)
	}

	got, err := os.ReadFile(destPath)
	if err != nil {
		t.Fatalf("cannot read decrypted file: %v", err)
	}
	if string(got) != string(content) {
		t.Errorf("decrypted content mismatch: got %q, want %q", string(got), string(content))
	}

	if !strings.Contains(out.String(), "succeeded=1") {
		t.Errorf("summary does not contain succeeded count: %q", out.String())
	}
}

func TestRunDecrypt_MissingEncryptedFileIsSkipped(t *testing.T) {
	dir := t.TempDir()
	kp := generateTestKeyPair(t)

	storageDir := filepath.Join(dir, ".agedir", "secrets")
	os.MkdirAll(storageDir, 0o755)
	// intentionally not creating the encrypted file

	cfg := &config.Config{
		Version:    "1",
		Recipients: []string{kp.pubkey},
		StorageDir: storageDir,
		Mapping:    []config.FileMapping{{Raw: filepath.Join(dir, "missing.txt"), Enc: "missing.txt.age"}},
	}
	cfgPath := filepath.Join(dir, "agedir.yaml")
	writeAgedir(t, cfgPath, cfg)

	cmd, out, errOut := newTestCmd()
	opts := decryptOpts{identityFile: kp.identityFilePath, configPath: cfgPath}

	err := runDecrypt(cmd, opts, config.New(), crypto.New(), fileops.New())
	if err != nil {
		t.Errorf("runDecrypt() returned unexpected error for missing encrypted file: %v", err)
	}

	if !strings.Contains(errOut.String(), "warning:") {
		t.Errorf("warning message not written to stderr: %q", errOut.String())
	}
	if !strings.Contains(out.String(), "skipped=1") {
		t.Errorf("summary does not contain skipped count: %q", out.String())
	}
}

func TestRunDecrypt_WrongKeyReturnsError(t *testing.T) {
	dir := t.TempDir()
	kp1 := generateTestKeyPair(t)
	kp2 := generateTestKeyPair(t)

	content := []byte("secret data")
	storageDir := filepath.Join(dir, ".agedir", "secrets")
	os.MkdirAll(storageDir, 0o755)

	encBytes := encryptContent(t, content, kp1.pubkey) // encrypted with kp1
	os.WriteFile(filepath.Join(storageDir, "secret.txt.age"), encBytes, 0o600)

	cfg := &config.Config{
		Version:    "1",
		Recipients: []string{kp1.pubkey},
		StorageDir: storageDir,
		Mapping:    []config.FileMapping{{Raw: filepath.Join(dir, "secret.txt"), Enc: "secret.txt.age"}},
	}
	cfgPath := filepath.Join(dir, "agedir.yaml")
	writeAgedir(t, cfgPath, cfg)

	cmd, out, _ := newTestCmd()
	opts := decryptOpts{
		identityFile: kp2.identityFilePath, // attempt decryption with a different key
		configPath:   cfgPath,
	}

	err := runDecrypt(cmd, opts, config.New(), crypto.New(), fileops.New())
	if err == nil {
		t.Error("expected error when decrypting with wrong key, got nil")
	}

	if !strings.Contains(out.String(), "failed=1") {
		t.Errorf("summary does not contain failed count: %q", out.String())
	}
}

func TestRunDecrypt_DryRunDoesNotWriteFiles(t *testing.T) {
	dir := t.TempDir()
	kp := generateTestKeyPair(t)

	content := []byte("dry run test")
	storageDir := filepath.Join(dir, ".agedir", "secrets")
	os.MkdirAll(storageDir, 0o755)

	encBytes := encryptContent(t, content, kp.pubkey)
	os.WriteFile(filepath.Join(storageDir, "secret.txt.age"), encBytes, 0o600)

	destPath := filepath.Join(dir, "secret.txt")
	cfg := &config.Config{
		Version:    "1",
		Recipients: []string{kp.pubkey},
		StorageDir: storageDir,
		Mapping:    []config.FileMapping{{Raw: destPath, Enc: "secret.txt.age"}},
	}
	cfgPath := filepath.Join(dir, "agedir.yaml")
	writeAgedir(t, cfgPath, cfg)

	cmd, _, _ := newTestCmd()
	opts := decryptOpts{identityFile: kp.identityFilePath, dryRun: true, configPath: cfgPath}

	if err := runDecrypt(cmd, opts, config.New(), crypto.New(), fileops.New()); err != nil {
		t.Fatalf("runDecrypt() returned unexpected error: %v", err)
	}

	if _, err := os.Stat(destPath); !os.IsNotExist(err) {
		t.Error("file was created despite dry-run mode")
	}
}
