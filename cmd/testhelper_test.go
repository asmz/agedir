package cmd

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/asmz/agedir/internal/config"
	"github.com/asmz/agedir/internal/crypto"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

// newTestCmd returns a cobra.Command with output buffers for testing.
func newTestCmd() (*cobra.Command, *bytes.Buffer, *bytes.Buffer) {
	cmd := &cobra.Command{}
	out := &bytes.Buffer{}
	errOut := &bytes.Buffer{}
	cmd.SetOut(out)
	cmd.SetErr(errOut)
	return cmd, out, errOut
}

// testKeyPair holds a generated age key pair.
type testKeyPair struct {
	pubkey           string
	identityFilePath string
}

// generateTestKeyPair generates a new age key pair and writes the private key to a temp file.
func generateTestKeyPair(t *testing.T) testKeyPair {
	t.Helper()
	dir := t.TempDir()
	identity, err := crypto.GenerateX25519Identity()
	if err != nil {
		t.Fatalf("failed to generate key pair: %v", err)
	}
	pubkey := identity.Recipient().String()
	privkey := identity.String()
	identityFile := filepath.Join(dir, "key.txt")
	if err := os.WriteFile(identityFile, []byte(privkey+"\n"), 0o600); err != nil {
		t.Fatalf("failed to write identity file: %v", err)
	}
	return testKeyPair{pubkey: pubkey, identityFilePath: identityFile}
}

// encryptContent encrypts content with the given public key and returns the ciphertext.
func encryptContent(t *testing.T, content []byte, pubkey string) []byte {
	t.Helper()
	svc := crypto.New()
	var buf bytes.Buffer
	if err := svc.Encrypt(bytes.NewReader(content), &buf, []string{pubkey}); err != nil {
		t.Fatalf("failed to encrypt test content: %v", err)
	}
	return buf.Bytes()
}

// writeAgedir serializes cfg and writes it as agedir.yaml to path.
func writeAgedir(t *testing.T, path string, cfg *config.Config) {
	t.Helper()
	data, err := yaml.Marshal(cfg)
	if err != nil {
		t.Fatalf("failed to serialize agedir.yaml: %v", err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("failed to write agedir.yaml: %v", err)
	}
}
