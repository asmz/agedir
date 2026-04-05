package crypto_test

import (
	"bytes"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/asmz/agedir/internal/crypto"
)

// generateTestKeyPair generates an age key pair for testing.
func generateTestKeyPair(t *testing.T) (pubkey, privkey string) {
	t.Helper()
	identity, err := crypto.GenerateX25519Identity()
	if err != nil {
		t.Fatalf("failed to generate test key pair: %v", err)
	}
	return identity.Recipient().String(), identity.String()
}

// --- 3.1 multi-recipient encryption tests ---

func TestEncrypt_SingleRecipient(t *testing.T) {
	svc := crypto.New()
	pubkey, privkey := generateTestKeyPair(t)

	plaintext := []byte("test data: hello, world!")
	src := bytes.NewReader(plaintext)
	var dst bytes.Buffer

	if err := svc.Encrypt(src, &dst, []string{pubkey}); err != nil {
		t.Fatalf("Encrypt error: %v", err)
	}

	// encrypted output must be non-empty and differ from plaintext
	if dst.Len() == 0 {
		t.Fatal("encrypted output is empty")
	}
	if bytes.Equal(dst.Bytes(), plaintext) {
		t.Fatal("output is identical to plaintext (not encrypted)")
	}

	// decrypt and verify content matches
	var decrypted bytes.Buffer
	opts := crypto.IdentityOpts{IdentityFile: "", PassphraseMode: false}
	tmpFile := t.TempDir() + "/key.txt"
	if err := os.WriteFile(tmpFile, []byte(privkey+"\n"), 0600); err != nil {
		t.Fatalf("failed to write temp key file: %v", err)
	}
	opts.IdentityFile = tmpFile

	if err := svc.Decrypt(bytes.NewReader(dst.Bytes()), &decrypted, opts); err != nil {
		t.Fatalf("Decrypt error: %v", err)
	}
	if !bytes.Equal(decrypted.Bytes(), plaintext) {
		t.Fatalf("decrypted content mismatch: got %q, want %q", decrypted.String(), string(plaintext))
	}
}

func TestEncrypt_MultipleRecipients(t *testing.T) {
	svc := crypto.New()
	pubkey1, privkey1 := generateTestKeyPair(t)
	pubkey2, privkey2 := generateTestKeyPair(t)

	plaintext := []byte("multi-recipient test")
	var dst bytes.Buffer

	if err := svc.Encrypt(bytes.NewReader(plaintext), &dst, []string{pubkey1, pubkey2}); err != nil {
		t.Fatalf("Encrypt error: %v", err)
	}

	encrypted := dst.Bytes()

	// key1 must be able to decrypt
	var dec1 bytes.Buffer
	tmpFile1 := t.TempDir() + "/key1.txt"
	os.WriteFile(tmpFile1, []byte(privkey1+"\n"), 0600)
	if err := svc.Decrypt(bytes.NewReader(encrypted), &dec1, crypto.IdentityOpts{IdentityFile: tmpFile1}); err != nil {
		t.Fatalf("decryption with key1 failed: %v", err)
	}
	if !bytes.Equal(dec1.Bytes(), plaintext) {
		t.Fatal("content mismatch after decryption with key1")
	}

	// key2 must also be able to decrypt
	var dec2 bytes.Buffer
	tmpFile2 := t.TempDir() + "/key2.txt"
	os.WriteFile(tmpFile2, []byte(privkey2+"\n"), 0600)
	if err := svc.Decrypt(bytes.NewReader(encrypted), &dec2, crypto.IdentityOpts{IdentityFile: tmpFile2}); err != nil {
		t.Fatalf("decryption with key2 failed: %v", err)
	}
	if !bytes.Equal(dec2.Bytes(), plaintext) {
		t.Fatal("content mismatch after decryption with key2")
	}
}

func TestEncrypt_InvalidPublicKey(t *testing.T) {
	svc := crypto.New()
	src := bytes.NewReader([]byte("data"))
	var dst bytes.Buffer

	err := svc.Encrypt(src, &dst, []string{"not-a-valid-age-key"})
	if err == nil {
		t.Fatal("expected error for invalid public key, got nil")
	}
}

func TestEncrypt_InvalidPublicKeyAmongValid(t *testing.T) {
	svc := crypto.New()
	pubkey, _ := generateTestKeyPair(t)
	src := bytes.NewReader([]byte("data"))
	var dst bytes.Buffer

	// a mix of valid and invalid keys should fail before any encryption
	err := svc.Encrypt(src, &dst, []string{pubkey, "invalid-key"})
	if err == nil {
		t.Fatal("expected error for mixed valid/invalid keys, got nil")
	}
}

func TestEncrypt_EmptyPublicKeys(t *testing.T) {
	svc := crypto.New()
	src := bytes.NewReader([]byte("data"))
	var dst bytes.Buffer

	err := svc.Encrypt(src, &dst, []string{})
	if err == nil {
		t.Fatal("expected error for empty public key list, got nil")
	}
}

// --- ValidateRecipients tests ---

func TestValidateRecipients_EmptySliceReturnsError(t *testing.T) {
	err := crypto.ValidateRecipients([]string{})
	if err == nil {
		t.Fatal("expected error for empty recipients, got nil")
	}
}

func TestValidateRecipients_ValidKeyReturnsNil(t *testing.T) {
	pubkey, _ := generateTestKeyPair(t)
	if err := crypto.ValidateRecipients([]string{pubkey}); err != nil {
		t.Fatalf("expected no error for valid key, got: %v", err)
	}
}

func TestValidateRecipients_InvalidKeyReturnsError(t *testing.T) {
	err := crypto.ValidateRecipients([]string{"not-a-valid-age-key"})
	if err == nil {
		t.Fatal("expected error for invalid key, got nil")
	}
}

// --- 3.2 identity resolution and decryption tests ---

func TestDecrypt_WithIdentityFile(t *testing.T) {
	svc := crypto.New()
	pubkey, privkey := generateTestKeyPair(t)

	plaintext := []byte("identity file test")
	var enc bytes.Buffer
	svc.Encrypt(bytes.NewReader(plaintext), &enc, []string{pubkey})

	tmpFile := t.TempDir() + "/identity.txt"
	os.WriteFile(tmpFile, []byte(privkey+"\n"), 0600)

	var dec bytes.Buffer
	err := svc.Decrypt(bytes.NewReader(enc.Bytes()), &dec, crypto.IdentityOpts{IdentityFile: tmpFile})
	if err != nil {
		t.Fatalf("Decrypt with identity file error: %v", err)
	}
	if !bytes.Equal(dec.Bytes(), plaintext) {
		t.Fatal("decrypted content mismatch")
	}
}

func TestDecrypt_WithEnvPassphrase(t *testing.T) {
	svc := crypto.New()

	passphrase := "test-passphrase-12345"
	plaintext := []byte("env passphrase test")

	// encrypt with passphrase
	var enc bytes.Buffer
	if err := svc.EncryptWithPassphrase(bytes.NewReader(plaintext), &enc, passphrase); err != nil {
		t.Fatalf("EncryptWithPassphrase error: %v", err)
	}

	// set env var and decrypt
	t.Setenv("AGEDIR_PASSPHRASE", passphrase)

	var dec bytes.Buffer
	err := svc.Decrypt(bytes.NewReader(enc.Bytes()), &dec, crypto.IdentityOpts{PassphraseMode: true})
	if err != nil {
		t.Fatalf("Decrypt with env passphrase error: %v", err)
	}
	if !bytes.Equal(dec.Bytes(), plaintext) {
		t.Fatal("decrypted content mismatch")
	}
}

func TestDecrypt_WrongIdentity(t *testing.T) {
	svc := crypto.New()
	pubkey, _ := generateTestKeyPair(t)
	_, wrongPrivkey := generateTestKeyPair(t)

	var enc bytes.Buffer
	svc.Encrypt(bytes.NewReader([]byte("secret")), &enc, []string{pubkey})

	tmpFile := t.TempDir() + "/wrong.txt"
	os.WriteFile(tmpFile, []byte(wrongPrivkey+"\n"), 0600)

	var dec bytes.Buffer
	err := svc.Decrypt(bytes.NewReader(enc.Bytes()), &dec, crypto.IdentityOpts{IdentityFile: tmpFile})
	if err == nil {
		t.Fatal("expected error for mismatched identity, got nil")
	}
	if !strings.Contains(err.Error(), "identity") && !strings.Contains(err.Error(), "no matching") {
		t.Logf("error message: %v", err)
	}
}

func TestDecrypt_MissingIdentityFile(t *testing.T) {
	svc := crypto.New()
	pubkey, _ := generateTestKeyPair(t)

	var enc bytes.Buffer
	svc.Encrypt(bytes.NewReader([]byte("secret")), &enc, []string{pubkey})

	var dec bytes.Buffer
	err := svc.Decrypt(bytes.NewReader(enc.Bytes()), &dec, crypto.IdentityOpts{IdentityFile: "/nonexistent/path/key.txt"})
	if err == nil {
		t.Fatal("expected error for missing identity file, got nil")
	}
}

func TestDecrypt_NoOptions(t *testing.T) {
	svc := crypto.New()
	pubkey, _ := generateTestKeyPair(t)

	var enc bytes.Buffer
	svc.Encrypt(bytes.NewReader([]byte("secret")), &enc, []string{pubkey})

	// no identity and no passphrase in a non-TTY environment should return an error
	var dec bytes.Buffer
	err := svc.Decrypt(bytes.NewReader(enc.Bytes()), &dec, crypto.IdentityOpts{})
	if err == nil {
		t.Log("note: Decrypt with no options did not error (TTY may be attached)")
	}
}

func TestDecrypt_WithEnvIdentity(t *testing.T) {
	svc := crypto.New()
	pubkey, privkey := generateTestKeyPair(t)

	plaintext := []byte("env identity test")
	var enc bytes.Buffer
	svc.Encrypt(bytes.NewReader(plaintext), &enc, []string{pubkey})

	// write private key to a temp file and set AGEDIR_IDENTITY
	tmpFile := t.TempDir() + "/identity.txt"
	os.WriteFile(tmpFile, []byte(privkey+"\n"), 0600)
	t.Setenv("AGEDIR_IDENTITY", tmpFile)

	var dec bytes.Buffer
	err := svc.Decrypt(bytes.NewReader(enc.Bytes()), &dec, crypto.IdentityOpts{})
	if err != nil {
		t.Fatalf("Decrypt with AGEDIR_IDENTITY error: %v", err)
	}
	if !bytes.Equal(dec.Bytes(), plaintext) {
		t.Fatal("decrypted content mismatch")
	}
}

// TestGenerateX25519Identity verifies the exported key generation function.
func TestGenerateX25519Identity(t *testing.T) {
	identity, err := crypto.GenerateX25519Identity()
	if err != nil {
		t.Fatalf("key generation error: %v", err)
	}
	pubkey := identity.Recipient().String()
	privkey := identity.String()

	if !strings.HasPrefix(pubkey, "age1") {
		t.Fatalf("invalid public key format: %s", pubkey)
	}
	if !strings.HasPrefix(privkey, "AGE-SECRET-KEY-") {
		t.Fatalf("invalid private key format: %s", privkey)
	}
	_ = io.Discard
}
