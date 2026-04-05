package crypto

import (
	"errors"
	"fmt"
	"io"
	"os"

	"filippo.io/age"
	"golang.org/x/term"
)

// IdentityOpts holds options for identity resolution during decryption.
// Priority: IdentityFile > AGEDIR_IDENTITY env > Passphrase (pre-resolved) > AGEDIR_PASSPHRASE env > terminal prompt (PassphraseMode=true)
type IdentityOpts struct {
	IdentityFile   string // --identity flag value; if empty, AGEDIR_IDENTITY env or PassphraseMode is used
	PassphraseMode bool   // -p flag; if true, passphrase is obtained from Passphrase, AGEDIR_PASSPHRASE env or terminal prompt
	Passphrase     string // pre-resolved passphrase; if set, skips env/prompt resolution
}

// CryptoService is the interface for age encryption and decryption.
type CryptoService interface {
	// Encrypt reads src and encrypts it for all recipients identified by pubkeys (age public key strings),
	// writing the result to dst. All keys are validated before processing begins.
	Encrypt(src io.Reader, dst io.Writer, pubkeys []string) error

	// EncryptWithPassphrase encrypts using a passphrase directly (intended for tests).
	EncryptWithPassphrase(src io.Reader, dst io.Writer, passphrase string) error

	// Decrypt decrypts src using the identity resolved from opts and writes the result to dst.
	Decrypt(src io.Reader, dst io.Writer, opts IdentityOpts) error
}

// X25519Identity is an alias for age.X25519Identity, generated via GenerateX25519Identity.
type X25519Identity = age.X25519Identity

// GenerateX25519Identity generates a new age X25519 key pair.
func GenerateX25519Identity() (*age.X25519Identity, error) {
	return age.GenerateX25519Identity()
}

// ValidateRecipients validates all public keys upfront.
// Returns an error if the list is empty or any key has an invalid format.
func ValidateRecipients(pubkeys []string) error {
	if len(pubkeys) == 0 {
		return errors.New("no recipients specified")
	}
	for _, pk := range pubkeys {
		if _, err := age.ParseX25519Recipient(pk); err != nil {
			return fmt.Errorf("invalid public key format %q: %w", pk, err)
		}
	}
	return nil
}

type service struct{}

// New returns a new CryptoService instance.
func New() CryptoService {
	return &service{}
}

// Encrypt reads src, validates all pubkeys upfront, and encrypts to all recipients writing to dst.
func (s *service) Encrypt(src io.Reader, dst io.Writer, pubkeys []string) error {
	if len(pubkeys) == 0 {
		return errors.New("no recipients specified")
	}

	// validate all public keys before processing
	recipients := make([]age.Recipient, 0, len(pubkeys))
	for _, pk := range pubkeys {
		r, err := age.ParseX25519Recipient(pk)
		if err != nil {
			return fmt.Errorf("invalid public key format %q: %w", pk, err)
		}
		recipients = append(recipients, r)
	}

	w, err := age.Encrypt(dst, recipients...)
	if err != nil {
		return fmt.Errorf("age.Encrypt initialization error: %w", err)
	}

	if _, err := io.Copy(w, src); err != nil {
		return fmt.Errorf("copy error during encryption: %w", err)
	}

	if err := w.Close(); err != nil {
		return fmt.Errorf("error closing encryption stream: %w", err)
	}

	return nil
}

// EncryptWithPassphrase encrypts using a passphrase via age scrypt.
func (s *service) EncryptWithPassphrase(src io.Reader, dst io.Writer, passphrase string) error {
	passphraseBytes := []byte(passphrase)
	defer clear(passphraseBytes)

	r, err := age.NewScryptRecipient(passphrase)
	if err != nil {
		return fmt.Errorf("failed to create passphrase recipient: %w", err)
	}

	w, err := age.Encrypt(dst, r)
	if err != nil {
		return fmt.Errorf("age.Encrypt initialization error: %w", err)
	}

	if _, err := io.Copy(w, src); err != nil {
		return fmt.Errorf("copy error during encryption: %w", err)
	}

	if err := w.Close(); err != nil {
		return fmt.Errorf("error closing encryption stream: %w", err)
	}

	return nil
}

// Decrypt decrypts src using the identity resolved from opts and writes to dst.
// Priority: IdentityFile > AGEDIR_IDENTITY env > AGEDIR_PASSPHRASE env > terminal prompt
func (s *service) Decrypt(src io.Reader, dst io.Writer, opts IdentityOpts) error {
	identities, err := resolveIdentities(opts)
	if err != nil {
		return err
	}

	r, err := age.Decrypt(src, identities...)
	if err != nil {
		var noMatch *age.NoIdentityMatchError
		if errors.As(err, &noMatch) {
			return fmt.Errorf("no matching identity found (key mismatch): %w", err)
		}
		return fmt.Errorf("decryption error: %w", err)
	}

	if _, err := io.Copy(dst, r); err != nil {
		return fmt.Errorf("copy error during decryption: %w", err)
	}

	return nil
}

// resolveIdentities returns an age.Identity slice based on opts.
// Priority: --identity flag > AGEDIR_IDENTITY env > AGEDIR_PASSPHRASE env > terminal prompt (PassphraseMode=true)
func resolveIdentities(opts IdentityOpts) ([]age.Identity, error) {
	if opts.IdentityFile != "" {
		return loadIdentityFile(opts.IdentityFile)
	}

	if envPath := os.Getenv("AGEDIR_IDENTITY"); envPath != "" {
		return loadIdentityFile(envPath)
	}

	if opts.PassphraseMode {
		passphrase := opts.Passphrase
		if passphrase == "" {
			var err error
			passphrase, err = ResolvePassphrase()
			if err != nil {
				return nil, err
			}
		}
		passphraseBytes := []byte(passphrase)
		defer clear(passphraseBytes)

		id, err := age.NewScryptIdentity(passphrase)
		if err != nil {
			return nil, fmt.Errorf("failed to create passphrase identity: %w", err)
		}
		return []age.Identity{id}, nil
	}

	return nil, errors.New("no identity specified; use --identity, -p, or set AGEDIR_IDENTITY")
}

// loadIdentityFile reads an age private key file from the given path.
func loadIdentityFile(path string) ([]age.Identity, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("cannot open identity file %q: %w", path, err)
	}
	defer f.Close()

	identities, err := age.ParseIdentities(f)
	if err != nil {
		return nil, fmt.Errorf("failed to parse identity file %q: %w", path, err)
	}

	return identities, nil
}

// ResolvePassphrase obtains a passphrase from AGEDIR_PASSPHRASE env or a terminal prompt (no echo).
func ResolvePassphrase() (string, error) {
	if passphrase := os.Getenv("AGEDIR_PASSPHRASE"); passphrase != "" {
		return passphrase, nil
	}

	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return "", errors.New("AGEDIR_PASSPHRASE is not set and no terminal is attached")
	}

	fmt.Fprint(os.Stderr, "Enter passphrase: ")
	passphraseBytes, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	defer clear(passphraseBytes)

	if err != nil {
		return "", fmt.Errorf("failed to read passphrase: %w", err)
	}

	return string(passphraseBytes), nil
}
