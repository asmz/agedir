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
	"github.com/asmz/agedir/internal/scanner"
)

// --- Task 7.1: encrypt → decrypt round-trip integration tests ---

// TestIntegration_EncryptDecryptRoundtrip_Pubkey verifies the encrypt → decrypt round-trip using public key encryption.
func TestIntegration_EncryptDecryptRoundtrip_Pubkey(t *testing.T) {
	dir := t.TempDir()
	kp := generateTestKeyPair(t)

	content := []byte("integration test: public key round-trip")
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

	// encrypt
	encCmd, _, _ := newTestCmd()
	if err := runEncrypt(encCmd, encryptOpts{configPath: cfgPath}, config.New(), crypto.New(), fileops.New()); err != nil {
		t.Fatalf("runEncrypt() error: %v", err)
	}

	// remove dest file before decryption
	os.Remove(destPath)

	// decrypt
	decCmd, _, _ := newTestCmd()
	if err := runDecrypt(decCmd, decryptOpts{identityFile: kp.identityFilePath, configPath: cfgPath}, config.New(), crypto.New(), fileops.New()); err != nil {
		t.Fatalf("runDecrypt() error: %v", err)
	}

	got, err := os.ReadFile(destPath)
	if err != nil {
		t.Fatalf("cannot read decrypted file: %v", err)
	}
	if string(got) != string(content) {
		t.Errorf("content mismatch after round-trip: got %q, want %q", string(got), string(content))
	}
}

// TestIntegration_EncryptDecryptRoundtrip_Passphrase verifies decryption via AGEDIR_PASSPHRASE.
func TestIntegration_EncryptDecryptRoundtrip_Passphrase(t *testing.T) {
	dir := t.TempDir()

	const passphrase = "test-passphrase-12345"
	content := []byte("integration test: passphrase round-trip")

	storageDir := filepath.Join(dir, ".agedir", "secrets")
	os.MkdirAll(storageDir, 0o755)

	// encrypt with passphrase directly (encrypt command only supports public keys)
	encPath := filepath.Join(storageDir, "secret.txt.age")
	{
		svc := crypto.New()
		var buf bytes.Buffer
		if err := svc.EncryptWithPassphrase(bytes.NewReader(content), &buf, passphrase); err != nil {
			t.Fatalf("EncryptWithPassphrase() error: %v", err)
		}
		os.WriteFile(encPath, buf.Bytes(), 0o600)
	}

	destPath := filepath.Join(dir, "secret.txt")
	// recipients validation is skipped in passphrase mode; use a placeholder value
	cfg := &config.Config{
		Version:    "1",
		Recipients: []string{"passphrase-mode"},
		StorageDir: storageDir,
		Mapping:    []config.FileMapping{{Src: "secret.txt.age", Dest: destPath}},
	}
	cfgPath := filepath.Join(dir, "agedir.yaml")
	writeAgedir(t, cfgPath, cfg)

	t.Setenv("AGEDIR_PASSPHRASE", passphrase)

	decCmd, _, _ := newTestCmd()
	if err := runDecrypt(decCmd, decryptOpts{passphraseMode: true, configPath: cfgPath}, config.New(), crypto.New(), fileops.New()); err != nil {
		t.Fatalf("runDecrypt() passphrase mode error: %v", err)
	}

	got, err := os.ReadFile(destPath)
	if err != nil {
		t.Fatalf("cannot read decrypted file: %v", err)
	}
	if string(got) != string(content) {
		t.Errorf("content mismatch after passphrase decryption: got %q, want %q", string(got), string(content))
	}
}

// TestIntegration_EncryptDecryptRoundtrip_MultiMapping verifies encrypt → decrypt with multiple mappings.
func TestIntegration_EncryptDecryptRoundtrip_MultiMapping(t *testing.T) {
	dir := t.TempDir()
	kp := generateTestKeyPair(t)

	type fileEntry struct {
		name    string
		content []byte
	}
	entries := []fileEntry{
		{"secret1.txt", []byte("multi-mapping test 1")},
		{"secret2.txt", []byte("multi-mapping test 2")},
		{"secret3.txt", []byte("multi-mapping test 3")},
	}

	storageDir := filepath.Join(dir, ".agedir", "secrets")
	os.MkdirAll(storageDir, 0o755)

	mappings := make([]config.FileMapping, 0, len(entries))
	for _, e := range entries {
		destPath := filepath.Join(dir, e.name)
		os.WriteFile(destPath, e.content, 0o600)
		mappings = append(mappings, config.FileMapping{
			Src:  e.name + ".age",
			Dest: destPath,
		})
	}

	cfg := &config.Config{
		Version:    "1",
		Recipients: []string{kp.pubkey},
		StorageDir: storageDir,
		Mapping:    mappings,
	}
	cfgPath := filepath.Join(dir, "agedir.yaml")
	writeAgedir(t, cfgPath, cfg)

	// encrypt
	encCmd, _, _ := newTestCmd()
	if err := runEncrypt(encCmd, encryptOpts{configPath: cfgPath}, config.New(), crypto.New(), fileops.New()); err != nil {
		t.Fatalf("runEncrypt() error: %v", err)
	}

	// remove all dest files before decryption
	for _, e := range entries {
		os.Remove(filepath.Join(dir, e.name))
	}

	// decrypt
	decCmd, _, _ := newTestCmd()
	if err := runDecrypt(decCmd, decryptOpts{identityFile: kp.identityFilePath, configPath: cfgPath}, config.New(), crypto.New(), fileops.New()); err != nil {
		t.Fatalf("runDecrypt() error: %v", err)
	}

	// verify all files
	for _, e := range entries {
		destPath := filepath.Join(dir, e.name)
		got, err := os.ReadFile(destPath)
		if err != nil {
			t.Errorf("cannot read %s: %v", e.name, err)
			continue
		}
		if string(got) != string(e.content) {
			t.Errorf("%s content mismatch: got %q, want %q", e.name, string(got), string(e.content))
		}
	}
}

// TestIntegration_EncryptDecryptRoundtrip_MultiRecipient verifies that all recipients can decrypt after multi-recipient encryption.
func TestIntegration_EncryptDecryptRoundtrip_MultiRecipient(t *testing.T) {
	dir := t.TempDir()
	kp1 := generateTestKeyPair(t)
	kp2 := generateTestKeyPair(t)

	content := []byte("multi-recipient test")
	destPath := filepath.Join(dir, "secret.txt")
	os.WriteFile(destPath, content, 0o600)

	storageDir := filepath.Join(dir, ".agedir", "secrets")
	os.MkdirAll(storageDir, 0o755)

	cfg := &config.Config{
		Version:    "1",
		Recipients: []string{kp1.pubkey, kp2.pubkey},
		StorageDir: storageDir,
		Mapping:    []config.FileMapping{{Src: "secret.txt.age", Dest: destPath}},
	}
	cfgPath := filepath.Join(dir, "agedir.yaml")
	writeAgedir(t, cfgPath, cfg)

	// encrypt for both recipients
	encCmd, _, _ := newTestCmd()
	if err := runEncrypt(encCmd, encryptOpts{configPath: cfgPath}, config.New(), crypto.New(), fileops.New()); err != nil {
		t.Fatalf("runEncrypt() error: %v", err)
	}

	encPath := filepath.Join(storageDir, "secret.txt.age")
	encData, _ := os.ReadFile(encPath)

	// kp1 must be able to decrypt
	{
		svc := crypto.New()
		var buf bytes.Buffer
		if err := svc.Decrypt(bytes.NewReader(encData), &buf, crypto.IdentityOpts{IdentityFile: kp1.identityFilePath}); err != nil {
			t.Errorf("kp1 decryption failed: %v", err)
		} else if buf.String() != string(content) {
			t.Errorf("kp1 content mismatch: got %q, want %q", buf.String(), string(content))
		}
	}

	// kp2 must also be able to decrypt
	{
		svc := crypto.New()
		var buf bytes.Buffer
		if err := svc.Decrypt(bytes.NewReader(encData), &buf, crypto.IdentityOpts{IdentityFile: kp2.identityFilePath}); err != nil {
			t.Errorf("kp2 decryption failed: %v", err)
		} else if buf.String() != string(content) {
			t.Errorf("kp2 content mismatch: got %q, want %q", buf.String(), string(content))
		}
	}
}

// --- Task 7.2: rekey key rotation integration test ---

// TestIntegration_Rekey_OldKeyCannotDecryptAfterRotation verifies that after rekey,
// the old key cannot decrypt but the new key can.
func TestIntegration_Rekey_OldKeyCannotDecryptAfterRotation(t *testing.T) {
	dir := t.TempDir()
	kpOld := generateTestKeyPair(t)
	kpNew := generateTestKeyPair(t)

	content := []byte("key rotation integration test")
	destPath := filepath.Join(dir, "secret.txt")
	os.WriteFile(destPath, content, 0o600)

	storageDir := filepath.Join(dir, ".agedir", "secrets")
	os.MkdirAll(storageDir, 0o755)

	cfg := &config.Config{
		Version:    "1",
		Recipients: []string{kpOld.pubkey},
		StorageDir: storageDir,
		Mapping:    []config.FileMapping{{Src: "secret.txt.age", Dest: destPath}},
	}
	cfgPath := filepath.Join(dir, "agedir.yaml")
	writeAgedir(t, cfgPath, cfg)

	// initial rekey (old key encrypts dest)
	rekeyCmd, _, _ := newTestCmd()
	if err := runRekey(rekeyCmd, rekeyOpts{configPath: cfgPath}, config.New(), crypto.New(), fileops.New()); err != nil {
		t.Fatalf("initial rekey error: %v", err)
	}

	// update recipients to new key only and rekey
	cfg.Recipients = []string{kpNew.pubkey}
	writeAgedir(t, cfgPath, cfg)

	rekeyCmd, _, _ = newTestCmd()
	if err := runRekey(rekeyCmd, rekeyOpts{configPath: cfgPath}, config.New(), crypto.New(), fileops.New()); err != nil {
		t.Fatalf("key rotation rekey error: %v", err)
	}

	encPath := filepath.Join(storageDir, "secret.txt.age")
	encData, _ := os.ReadFile(encPath)

	// old key must NOT be able to decrypt
	{
		svc := crypto.New()
		var buf bytes.Buffer
		err := svc.Decrypt(bytes.NewReader(encData), &buf, crypto.IdentityOpts{IdentityFile: kpOld.identityFilePath})
		if err == nil {
			t.Error("old key was able to decrypt after rotation (expected failure)")
		}
	}

	// new key must be able to decrypt
	{
		svc := crypto.New()
		var buf bytes.Buffer
		if err := svc.Decrypt(bytes.NewReader(encData), &buf, crypto.IdentityOpts{IdentityFile: kpNew.identityFilePath}); err != nil {
			t.Errorf("new key decryption failed: %v", err)
		} else if buf.String() != string(content) {
			t.Errorf("new key content mismatch: got %q, want %q", buf.String(), string(content))
		}
	}
}

// --- Task 7.3: init command integration tests ---

// TestIntegration_Init_GitignoreNoDuplicates verifies that .gitignore entries are not duplicated on repeated init.
func TestIntegration_Init_GitignoreNoDuplicates(t *testing.T) {
	dir := t.TempDir()

	os.WriteFile(filepath.Join(dir, "service.key"), []byte("key"), 0o644)

	cfgPath := filepath.Join(dir, "agedir.yaml")
	gitignorePath := filepath.Join(dir, ".gitignore")

	// first init
	cmd1, _, _ := newTestCmd()
	if err := runInit(cmd1, initOpts{configPath: cfgPath, root: dir}, config.New(), scanner.New()); err != nil {
		t.Fatalf("first runInit() error: %v", err)
	}

	firstContent, err := os.ReadFile(gitignorePath)
	if err != nil {
		t.Fatalf(".gitignore was not created: %v", err)
	}

	firstCount := strings.Count(string(firstContent), "service.key")
	if firstCount == 0 {
		t.Fatal("service.key not found in .gitignore after first init")
	}

	// second init (answer "y" to overwrite prompt)
	cmd2, _, _ := newTestCmd()
	cmd2.SetIn(strings.NewReader("y\n"))
	if err := runInit(cmd2, initOpts{configPath: cfgPath, root: dir}, config.New(), scanner.New()); err != nil {
		t.Fatalf("second runInit() error: %v", err)
	}

	secondContent, err := os.ReadFile(gitignorePath)
	if err != nil {
		t.Fatalf("cannot read .gitignore after second init: %v", err)
	}

	secondCount := strings.Count(string(secondContent), "service.key")
	if secondCount != firstCount {
		t.Errorf("service.key duplicated in .gitignore: first=%d occurrences, second=%d occurrences", firstCount, secondCount)
	}
}

// TestIntegration_Init_ExistingConfigNotOverwrittenOnNo verifies that agedir.yaml is not overwritten when the user answers "n".
func TestIntegration_Init_ExistingConfigNotOverwrittenOnNo(t *testing.T) {
	dir := t.TempDir()

	cfgPath := filepath.Join(dir, "agedir.yaml")
	originalContent := []byte("version: \"1\"\nrecipients:\n  - age1original\nmapping:\n  - src: original.age\n    dest: original.txt\n")
	os.WriteFile(cfgPath, originalContent, 0o644)

	cmd, out, _ := newTestCmd()
	cmd.SetIn(strings.NewReader("n\n"))

	if err := runInit(cmd, initOpts{configPath: cfgPath, root: dir}, config.New(), scanner.New()); err != nil {
		t.Fatalf("runInit() error: %v", err)
	}

	// file content must be unchanged
	actualContent, _ := os.ReadFile(cfgPath)
	if string(actualContent) != string(originalContent) {
		t.Error("agedir.yaml was modified after answering 'n' (should not be overwritten)")
	}

	// cancellation message must be printed
	if !strings.Contains(out.String(), "cancelled") {
		t.Errorf("cancellation message not printed: %q", out.String())
	}
}
