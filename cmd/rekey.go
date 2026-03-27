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

var rekeyConfig string

var rekeyCmd = &cobra.Command{
	Use:          "rekey",
	Short:        "Re-encrypt all files with the current recipients list",
	SilenceUsage: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		opts := rekeyOpts{configPath: rekeyConfig}
		return runRekey(cmd, opts, config.New(), crypto.New(), fileops.New())
	},
}

func init() {
	rekeyCmd.Flags().StringVar(&rekeyConfig, "config", "", "path to agedir.yaml (default: current directory)")
}

type rekeyOpts struct {
	configPath string
}

// runRekey implements the business logic for the rekey command.
// It reads plaintext files from dest paths and re-encrypts them for all current recipients,
// saving the results to storage_dir/src.
func runRekey(cmd *cobra.Command, opts rekeyOpts, cfgLoader config.ConfigLoader, cryptoSvc crypto.CryptoService, fileOps fileops.FileOps) error {
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
		destPath := filepath.FromSlash(m.Dest)
		encPath := filepath.Join(cfg.StorageDir, m.Src)

		srcFile, openErr := os.Open(destPath)
		if openErr != nil {
			if os.IsNotExist(openErr) {
				fmt.Fprintf(cmd.ErrOrStderr(), "warning: plaintext file not found: %s\n", destPath)
				skipped++
				continue
			}
			fmt.Fprintf(cmd.ErrOrStderr(), "error: cannot open %s: %v\n", destPath, openErr)
			failed++
			continue
		}

		var encBuf bytes.Buffer
		encErr := cryptoSvc.Encrypt(srcFile, &encBuf, cfg.Recipients)
		srcFile.Close()
		if encErr != nil {
			fmt.Fprintf(cmd.ErrOrStderr(), "error: failed to re-encrypt %s: %v\n", destPath, encErr)
			failed++
			continue
		}

		if _, placeErr := fileOps.Place(&encBuf, encPath, fileops.PlaceOptions{}); placeErr != nil {
			fmt.Fprintf(cmd.ErrOrStderr(), "error: failed to write %s: %v\n", encPath, placeErr)
			failed++
			continue
		}
		success++
	}

	fmt.Fprintf(cmd.OutOrStdout(), "done: total=%d succeeded=%d failed=%d skipped=%d\n", total, success, failed, skipped)

	if failed > 0 {
		return fmt.Errorf("%d file(s) failed to re-encrypt", failed)
	}
	return nil
}
