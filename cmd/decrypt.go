package cmd

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"

	"github.com/asmz/agedir/internal/config"
	"github.com/asmz/agedir/internal/crypto"
	"github.com/asmz/agedir/internal/fileops"
	"github.com/spf13/cobra"
)

var (
	decryptIdentityFile string
	decryptPassphrase   bool
	decryptVerify       bool
	decryptDryRun       bool
	decryptConfig       string
)

var decryptCmd = &cobra.Command{
	Use:          "decrypt",
	Short:        "Decrypt all encrypted files according to the config",
	SilenceUsage: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		opts := decryptOpts{
			identityFile:   decryptIdentityFile,
			passphraseMode: decryptPassphrase,
			verify:         decryptVerify,
			dryRun:         decryptDryRun,
			configPath:     decryptConfig,
		}
		return runDecrypt(cmd, opts, config.New(), crypto.New(), fileops.New())
	},
}

func init() {
	decryptCmd.Flags().StringVarP(&decryptIdentityFile, "identity", "i", "", "path to age private key file")
	decryptCmd.Flags().BoolVarP(&decryptPassphrase, "passphrase", "p", false, "decrypt using passphrase mode")
	decryptCmd.Flags().BoolVar(&decryptVerify, "verify", false, "skip if existing file hash matches")
	decryptCmd.Flags().BoolVar(&decryptDryRun, "dry-run", false, "print files to be processed without performing actual operations")
	decryptCmd.Flags().StringVar(&decryptConfig, "config", "", "path to agedir.yaml (default: current directory)")
}

type decryptOpts struct {
	identityFile   string
	passphraseMode bool
	verify         bool
	dryRun         bool
	configPath     string
}

// runDecrypt implements the business logic for the decrypt command.
func runDecrypt(cmd *cobra.Command, opts decryptOpts, cfgLoader config.ConfigLoader, cryptoSvc crypto.CryptoService, fileOps fileops.FileOps) error {
	cfg, err := cfgLoader.Load(opts.configPath)
	if err != nil {
		return err
	}

	// resolve passphrase once before processing (passphrase mode only)
	var passphrase string
	if opts.passphraseMode {
		var err error
		passphrase, err = crypto.ResolvePassphrase()
		if err != nil {
			return err
		}
		defer clear([]byte(passphrase))
	}

	identityOpts := crypto.IdentityOpts{
		IdentityFile:   opts.identityFile,
		PassphraseMode: opts.passphraseMode,
		Passphrase:     passphrase,
	}

	total := len(cfg.Mapping)
	var failed, skipped, success int

	for _, m := range cfg.Mapping {
		encPath := filepath.Join(cfg.StorageDir, m.Enc)
		rawPath := filepath.FromSlash(m.Raw)

		f, openErr := os.Open(encPath)
		if openErr != nil {
			if os.IsNotExist(openErr) {
				fmt.Fprintf(cmd.ErrOrStderr(), "warning: encrypted file not found: %s\n", encPath)
				skipped++
				continue
			}
			fmt.Fprintf(cmd.ErrOrStderr(), "error: cannot open %s: %v\n", encPath, openErr)
			failed++
			continue
		}

		var buf bytes.Buffer
		decErr := cryptoSvc.Decrypt(f, &buf, identityOpts)
		f.Close()
		if decErr != nil {
			fmt.Fprintf(cmd.ErrOrStderr(), "error: failed to decrypt %s: %v\n", encPath, decErr)
			failed++
			continue
		}

		placeOpts := fileops.PlaceOptions{DryRun: opts.dryRun, Verify: opts.verify}
		result, placeErr := fileOps.Place(&buf, rawPath, placeOpts)
		if placeErr != nil {
			fmt.Fprintf(cmd.ErrOrStderr(), "error: failed to place %s: %v\n", rawPath, placeErr)
			failed++
			continue
		}
		if result.Skipped {
			skipped++
		} else {
			success++
		}
	}

	fmt.Fprintf(cmd.OutOrStdout(), "done: total=%d succeeded=%d failed=%d skipped=%d\n", total, success, failed, skipped)

	if failed > 0 {
		return fmt.Errorf("%d file(s) failed to decrypt", failed)
	}
	return nil
}
