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

func TestRekeyCmd_HasFlags(t *testing.T) {
	flags := rekeyCmd.Flags()
	if flags.Lookup("config") == nil {
		t.Error("flag --config is not registered")
	}
}

func TestRunRekey_SuccessfulRekey(t *testing.T) {
	dir := t.TempDir()
	kp := generateTestKeyPair(t)

	content := []byte("re-encryption test data")
	destPath := filepath.Join(dir, "secret.txt")
	os.WriteFile(destPath, content, 0o600)

	storageDir := filepath.Join(dir, ".agedir", "secrets")
	os.MkdirAll(storageDir, 0o755)

	cfg := &config.Config{
		Version:    "1",
		Recipients: []string{kp.pubkey},
		StorageDir: storageDir,
		Mapping:    []config.FileMapping{{Src: "secret.txt.age", Dest: destPath}},
	}
	cfgPath := filepath.Join(dir, "agedir.yaml")
	writeAgedir(t, cfgPath, cfg)

	cmd, out, _ := newTestCmd()
	opts := rekeyOpts{configPath: cfgPath}

	if err := runRekey(cmd, opts, config.New(), crypto.New(), fileops.New()); err != nil {
		t.Fatalf("runRekey() returned unexpected error: %v", err)
	}

	// verify encrypted file was created
	encPath := filepath.Join(storageDir, "secret.txt.age")
	if _, err := os.Stat(encPath); os.IsNotExist(err) {
		t.Error("re-encrypted file was not created")
	}

	// verify the original key can still decrypt (content matches)
	encData, _ := os.ReadFile(encPath)
	svc := crypto.New()
	var decBuf bytes.Buffer
	if err := svc.Decrypt(bytes.NewReader(encData), &decBuf, crypto.IdentityOpts{IdentityFile: kp.identityFilePath}); err != nil {
		t.Fatalf("failed to decrypt re-encrypted file: %v", err)
	}
	if decBuf.String() != string(content) {
		t.Errorf("content mismatch after rekey: got %q, want %q", decBuf.String(), string(content))
	}

	if !strings.Contains(out.String(), "succeeded=1") {
		t.Errorf("summary does not contain succeeded count: %q", out.String())
	}
}

func TestRunRekey_MissingDestIsSkipped(t *testing.T) {
	dir := t.TempDir()
	kp := generateTestKeyPair(t)

	// intentionally not creating the dest file
	storageDir := filepath.Join(dir, ".agedir", "secrets")
	os.MkdirAll(storageDir, 0o755)

	cfg := &config.Config{
		Version:    "1",
		Recipients: []string{kp.pubkey},
		StorageDir: storageDir,
		Mapping:    []config.FileMapping{{Src: "missing.txt.age", Dest: filepath.Join(dir, "missing.txt")}},
	}
	cfgPath := filepath.Join(dir, "agedir.yaml")
	writeAgedir(t, cfgPath, cfg)

	cmd, out, errOut := newTestCmd()
	opts := rekeyOpts{configPath: cfgPath}

	err := runRekey(cmd, opts, config.New(), crypto.New(), fileops.New())
	if err != nil {
		t.Errorf("runRekey() returned unexpected error for missing dest: %v", err)
	}

	if !strings.Contains(errOut.String(), "warning:") {
		t.Errorf("warning message not written to stderr: %q", errOut.String())
	}
	if !strings.Contains(out.String(), "skipped=1") {
		t.Errorf("summary does not contain skipped count: %q", out.String())
	}
}

func TestRunRekey_NewRecipientCanDecrypt(t *testing.T) {
	dir := t.TempDir()
	kpOld := generateTestKeyPair(t)
	kpNew := generateTestKeyPair(t)

	content := []byte("key rotation test")
	destPath := filepath.Join(dir, "secret.txt")
	os.WriteFile(destPath, content, 0o600)

	storageDir := filepath.Join(dir, ".agedir", "secrets")
	os.MkdirAll(storageDir, 0o755)

	// initial config with old key only
	cfg := &config.Config{
		Version:    "1",
		Recipients: []string{kpOld.pubkey},
		StorageDir: storageDir,
		Mapping:    []config.FileMapping{{Src: "secret.txt.age", Dest: destPath}},
	}
	cfgPath := filepath.Join(dir, "agedir.yaml")
	writeAgedir(t, cfgPath, cfg)

	// encrypt with old key
	cmd, _, _ := newTestCmd()
	opts := rekeyOpts{configPath: cfgPath}
	runRekey(cmd, opts, config.New(), crypto.New(), fileops.New())

	// update config to new key
	cfg.Recipients = []string{kpNew.pubkey}
	writeAgedir(t, cfgPath, cfg)

	// rekey with new key
	cmd, _, _ = newTestCmd()
	if err := runRekey(cmd, opts, config.New(), crypto.New(), fileops.New()); err != nil {
		t.Fatalf("rekey failed: %v", err)
	}

	// verify new key can decrypt
	encPath := filepath.Join(storageDir, "secret.txt.age")
	encData, _ := os.ReadFile(encPath)
	svc := crypto.New()
	var decBuf bytes.Buffer
	if err := svc.Decrypt(bytes.NewReader(encData), &decBuf, crypto.IdentityOpts{IdentityFile: kpNew.identityFilePath}); err != nil {
		t.Fatalf("new key failed to decrypt: %v", err)
	}
	if decBuf.String() != string(content) {
		t.Errorf("content mismatch after rekey: got %q, want %q", decBuf.String(), string(content))
	}
}
