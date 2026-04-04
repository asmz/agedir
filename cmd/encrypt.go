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
	encryptConfig string
	encryptDryRun bool
)

var encryptCmd = &cobra.Command{
	Use:          "encrypt",
	Short:        "Encrypt all plaintext files according to the config",
	SilenceUsage: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		opts := encryptOpts{
			configPath: encryptConfig,
			dryRun:     encryptDryRun,
		}
		return runEncrypt(cmd, opts, config.New(), crypto.New(), fileops.New())
	},
}

func init() {
	encryptCmd.Flags().StringVar(&encryptConfig, "config", "", "path to agedir.yaml (default: current directory)")
	encryptCmd.Flags().BoolVar(&encryptDryRun, "dry-run", false, "print files to be processed without performing actual operations")
}

type encryptOpts struct {
	configPath string
	dryRun     bool
}

// runEncrypt implements the business logic for the encrypt command.
func runEncrypt(cmd *cobra.Command, opts encryptOpts, cfgLoader config.ConfigLoader, cryptoSvc crypto.CryptoService, fileOps fileops.FileOps) error {
	cfg, err := cfgLoader.Load(opts.configPath)
	if err != nil {
		return err
	}

	// validate all public keys before processing
	if err := crypto.ValidateRecipients(cfg.Recipients); err != nil {
		return err
	}

	total := len(cfg.Mapping)
	var failed, skipped, success int

	for _, m := range cfg.Mapping {
		rawPath := filepath.FromSlash(m.Raw)
		encPath := filepath.Join(cfg.StorageDir, m.Enc)

		srcFile, openErr := os.Open(rawPath)
		if openErr != nil {
			if os.IsNotExist(openErr) {
				fmt.Fprintf(cmd.ErrOrStderr(), "warning: raw file not found: %s\n", rawPath)
				skipped++
				continue
			}
			fmt.Fprintf(cmd.ErrOrStderr(), "error: cannot open %s: %v\n", rawPath, openErr)
			failed++
			continue
		}

		if opts.dryRun {
			srcFile.Close()
			fmt.Fprintf(cmd.OutOrStdout(), "[dry-run] %s -> %s\n", rawPath, encPath)
			success++
			continue
		}

		var encBuf bytes.Buffer
		encErr := cryptoSvc.Encrypt(srcFile, &encBuf, cfg.Recipients)
		srcFile.Close()
		if encErr != nil {
			fmt.Fprintf(cmd.ErrOrStderr(), "error: failed to encrypt %s: %v\n", rawPath, encErr)
			failed++
			continue
		}

		placeOpts := fileops.PlaceOptions{}
		if _, placeErr := fileOps.Place(&encBuf, encPath, placeOpts); placeErr != nil {
			fmt.Fprintf(cmd.ErrOrStderr(), "error: failed to write %s: %v\n", encPath, placeErr)
			failed++
			continue
		}
		success++
	}

	fmt.Fprintf(cmd.OutOrStdout(), "done: total=%d succeeded=%d failed=%d skipped=%d\n", total, success, failed, skipped)

	if failed > 0 {
		return fmt.Errorf("%d file(s) failed to encrypt", failed)
	}
	return nil
}
