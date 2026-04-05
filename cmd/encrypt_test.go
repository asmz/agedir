package cmd

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/asmz/agedir/internal/config"
	"github.com/asmz/agedir/internal/crypto"
	"github.com/asmz/agedir/internal/fileops"
)

func TestEncryptCmd_HasFlags(t *testing.T) {
	flags := encryptCmd.Flags()
	for _, name := range []string{"config", "dry-run"} {
		if flags.Lookup(name) == nil {
			t.Errorf("flag --%s is not registered", name)
		}
	}
}

func TestRunEncrypt_SuccessfulEncryption(t *testing.T) {
	dir := t.TempDir()
	kp := generateTestKeyPair(t)

	destPath := filepath.Join(dir, "secret.txt")
	content := []byte("plaintext data")
	os.WriteFile(destPath, content, 0o600)

	storageDir := filepath.Join(dir, ".agedir", "secrets")
	os.MkdirAll(storageDir, 0o755)

	cfg := &config.Config{
		Version:    "1",
		Recipients: []string{kp.pubkey},
		StorageDir: storageDir,
		Mapping:    []config.FileMapping{{Raw: destPath, Enc: "secret.txt.age"}},
	}
	cfgPath := filepath.Join(dir, "agedir.yaml")
	writeAgedir(t, cfgPath, cfg)

	cmd, out, _ := newTestCmd()
	opts := encryptOpts{configPath: cfgPath}

	if err := runEncrypt(cmd, opts, config.New(), crypto.New(), fileops.New()); err != nil {
		t.Fatalf("runEncrypt() returned unexpected error: %v", err)
	}

	// verify encrypted file was created
	encPath := filepath.Join(storageDir, "secret.txt.age")
	if _, err := os.Stat(encPath); os.IsNotExist(err) {
		t.Error("encrypted file was not created")
	}

	// verify decrypted content matches original
	encData, _ := os.ReadFile(encPath)
	svc := crypto.New()
	var decBuf bytes.Buffer
	decErr := svc.Decrypt(bytes.NewReader(encData), &decBuf, crypto.IdentityOpts{IdentityFile: kp.identityFilePath})
	if decErr != nil {
		t.Fatalf("verification decrypt error: %v", decErr)
	}
	if decBuf.String() != string(content) {
		t.Errorf("content mismatch after encryption: got %q, want %q", decBuf.String(), string(content))
	}

	if !strings.Contains(out.String(), "succeeded=1") {
		t.Errorf("summary does not contain succeeded count: %q", out.String())
	}
}

func TestRunEncrypt_MissingRawFileIsSkipped(t *testing.T) {
	dir := t.TempDir()
	kp := generateTestKeyPair(t)

	// intentionally not creating the raw file
	storageDir := filepath.Join(dir, ".agedir", "secrets")
	os.MkdirAll(storageDir, 0o755)

	cfg := &config.Config{
		Version:    "1",
		Recipients: []string{kp.pubkey},
		StorageDir: storageDir,
		Mapping:    []config.FileMapping{{Raw: filepath.Join(dir, "missing.txt"), Enc: "missing.txt.age"}},
	}
	cfgPath := filepath.Join(dir, "agedir.yaml")
	writeAgedir(t, cfgPath, cfg)

	cmd, out, errOut := newTestCmd()
	opts := encryptOpts{configPath: cfgPath}

	err := runEncrypt(cmd, opts, config.New(), crypto.New(), fileops.New())
	if err != nil {
		t.Errorf("runEncrypt() returned unexpected error for missing raw file: %v", err)
	}

	if !strings.Contains(errOut.String(), "warning:") {
		t.Errorf("warning message not written to stderr: %q", errOut.String())
	}
	if !strings.Contains(out.String(), "skipped=1") {
		t.Errorf("summary does not contain skipped count: %q", out.String())
	}
}

func TestRunEncrypt_InvalidRecipientFailsFast(t *testing.T) {
	dir := t.TempDir()

	destPath := filepath.Join(dir, "secret.txt")
	os.WriteFile(destPath, []byte("data"), 0o600)

	storageDir := filepath.Join(dir, ".agedir", "secrets")
	os.MkdirAll(storageDir, 0o755)

	cfg := &config.Config{
		Version:    "1",
		Recipients: []string{"not-a-valid-age-key"},
		StorageDir: storageDir,
		Mapping:    []config.FileMapping{{Raw: destPath, Enc: "secret.txt.age"}},
	}
	cfgPath := filepath.Join(dir, "agedir.yaml")
	writeAgedir(t, cfgPath, cfg)

	cmd, _, _ := newTestCmd()
	opts := encryptOpts{configPath: cfgPath}

	err := runEncrypt(cmd, opts, config.New(), crypto.New(), fileops.New())
	if err == nil {
		t.Error("expected error for invalid public key, got nil")
	}
}

func TestRunEncrypt_PassphraseMode(t *testing.T) {
	dir := t.TempDir()

	const passphrase = "test-passphrase-encrypt"
	content := []byte("passphrase encryption test")

	rawPath := filepath.Join(dir, "secret.txt")
	os.WriteFile(rawPath, content, 0o600)

	storageDir := filepath.Join(dir, ".agedir", "secrets")
	os.MkdirAll(storageDir, 0o755)

	cfg := &config.Config{
		Version:    "1",
		Recipients: []string{"passphrase-mode"},
		StorageDir: storageDir,
		Mapping:    []config.FileMapping{{Raw: rawPath, Enc: "secret.txt.age"}},
	}
	cfgPath := filepath.Join(dir, "agedir.yaml")
	writeAgedir(t, cfgPath, cfg)

	t.Setenv("AGEDIR_PASSPHRASE", passphrase)

	cmd, out, _ := newTestCmd()
	opts := encryptOpts{configPath: cfgPath, passphraseMode: true}

	if err := runEncrypt(cmd, opts, config.New(), crypto.New(), fileops.New()); err != nil {
		t.Fatalf("runEncrypt() passphrase mode error: %v", err)
	}

	if !strings.Contains(out.String(), "succeeded=1") {
		t.Errorf("summary does not contain succeeded count: %q", out.String())
	}

	// verify the encrypted file can be decrypted with the same passphrase
	encPath := filepath.Join(storageDir, "secret.txt.age")
	encData, err := os.ReadFile(encPath)
	if err != nil {
		t.Fatalf("encrypted file not found: %v", err)
	}

	svc := crypto.New()
	var decBuf bytes.Buffer
	decErr := svc.Decrypt(bytes.NewReader(encData), &decBuf, crypto.IdentityOpts{PassphraseMode: true})
	if decErr != nil {
		t.Fatalf("failed to decrypt passphrase-encrypted file: %v", decErr)
	}
	if decBuf.String() != string(content) {
		t.Errorf("content mismatch: got %q, want %q", decBuf.String(), string(content))
	}
}

func TestRunEncrypt_PassphraseModeWithEmptyRecipients(t *testing.T) {
	dir := t.TempDir()

	const passphrase = "test-passphrase-empty-recipients"
	content := []byte("passphrase mode with empty recipients")

	rawPath := filepath.Join(dir, "secret.txt")
	os.WriteFile(rawPath, content, 0o600)

	storageDir := filepath.Join(dir, ".agedir", "secrets")
	os.MkdirAll(storageDir, 0o755)

	// recipients is intentionally empty: passphrase mode does not require public keys
	cfg := &config.Config{
		Version:    "1",
		Recipients: []string{},
		StorageDir: storageDir,
		Mapping:    []config.FileMapping{{Raw: rawPath, Enc: "secret.txt.age"}},
	}
	cfgPath := filepath.Join(dir, "agedir.yaml")
	writeAgedir(t, cfgPath, cfg)

	t.Setenv("AGEDIR_PASSPHRASE", passphrase)

	cmd, _, _ := newTestCmd()
	if err := runEncrypt(cmd, encryptOpts{configPath: cfgPath, passphraseMode: true}, config.New(), crypto.New(), fileops.New()); err != nil {
		t.Fatalf("runEncrypt() with empty recipients in passphrase mode should succeed, got: %v", err)
	}
}

func TestRunEncrypt_DryRunDoesNotWriteFiles(t *testing.T) {
	dir := t.TempDir()
	kp := generateTestKeyPair(t)

	destPath := filepath.Join(dir, "secret.txt")
	os.WriteFile(destPath, []byte("dry run test"), 0o600)

	storageDir := filepath.Join(dir, ".agedir", "secrets")
	os.MkdirAll(storageDir, 0o755)

	cfg := &config.Config{
		Version:    "1",
		Recipients: []string{kp.pubkey},
		StorageDir: storageDir,
		Mapping:    []config.FileMapping{{Raw: destPath, Enc: "secret.txt.age"}},
	}
	cfgPath := filepath.Join(dir, "agedir.yaml")
	writeAgedir(t, cfgPath, cfg)

	cmd, _, _ := newTestCmd()
	opts := encryptOpts{configPath: cfgPath, dryRun: true}

	if err := runEncrypt(cmd, opts, config.New(), crypto.New(), fileops.New()); err != nil {
		t.Fatalf("runEncrypt() returned unexpected error: %v", err)
	}

	encPath := filepath.Join(storageDir, "secret.txt.age")
	if _, err := os.Stat(encPath); !os.IsNotExist(err) {
		t.Error("encrypted file was created despite dry-run mode")
	}
}
