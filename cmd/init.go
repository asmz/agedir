package cmd

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/asmz/agedir/internal/config"
	"github.com/asmz/agedir/internal/scanner"
	"github.com/spf13/cobra"
)

var initConfig string
var initSkipScan bool

var initCmd = &cobra.Command{
	Use:          "init",
	Short:        "Generate an initial agedir.yaml",
	SilenceUsage: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		opts := initOpts{configPath: initConfig, skipScan: initSkipScan}
		return runInit(cmd, opts, config.New(), scanner.New())
	},
}

func init() {
	initCmd.Flags().StringVar(&initConfig, "config", "", "path to agedir.yaml (default: current directory)")
	initCmd.Flags().BoolVar(&initSkipScan, "skip-scan", false, "skip scanning for sensitive files and generate a template-only agedir.yaml")
}

type initOpts struct {
	configPath string
	root       string // project root; defaults to current directory if empty
	skipScan   bool
}

// runInit implements the business logic for the init command.
func runInit(cmd *cobra.Command, opts initOpts, cfgLoader config.ConfigLoader, sc scanner.Scanner) error {
	root := opts.root
	if root == "" {
		var err error
		root, err = os.Getwd()
		if err != nil {
			return fmt.Errorf("failed to get current directory: %w", err)
		}
	}

	configPath := opts.configPath
	if configPath == "" {
		configPath = "agedir.yaml"
	}

	// prompt for confirmation if agedir.yaml already exists
	if _, err := os.Stat(configPath); err == nil {
		overwriteConfirmed, err := confirmYesNo(cmd, "agedir.yaml already exists. Overwrite? [y/N]: ")
		if err != nil {
			return err
		}
		if !overwriteConfirmed {
			fmt.Fprintln(cmd.OutOrStdout(), "cancelled.")
			return nil
		}
		// remove existing file to allow overwrite
		if err := os.Remove(configPath); err != nil {
			return fmt.Errorf("failed to remove existing agedir.yaml: %w", err)
		}
	}

	var result scanner.ScanResult
	var cfg *config.Config
	if opts.skipScan {
		cfg = &config.Config{
			Version:    "1",
			Recipients: []string{},
			StorageDir: ".agedir/secrets",
		}
	} else {
		scanConfirmed, err := confirmScan(cmd)
		if err != nil {
			return err
		}
		if !scanConfirmed {
			cfg = &config.Config{
				Version:    "1",
				Recipients: []string{},
				StorageDir: ".agedir/secrets",
			}
		} else {
			// scan the project for sensitive file candidates
			result, err = sc.Scan(root)
			if err != nil {
				return fmt.Errorf("failed to scan files: %w", err)
			}

			// build a config template
			cfg = &config.Config{
				Version:    "1",
				Recipients: []string{},
				StorageDir: ".agedir/secrets",
			}
			for _, match := range result.Matches {
				cfg.Mapping = append(cfg.Mapping, config.FileMapping{
					Enc: filepath.ToSlash(match) + ".age",
					Raw: match,
				})
			}
		}
	}

	// generate agedir.yaml
	if err := cfgLoader.Generate(cfg, configPath); err != nil {
		return fmt.Errorf("failed to generate agedir.yaml: %w", err)
	}

	// append raw paths to .gitignore, skipping files already covered by git's ignore rules
	gitignorePath := filepath.Join(filepath.Dir(configPath), ".gitignore")
	var rawPaths []string
	for _, m := range cfg.Mapping {
		if !isGitIgnored(root, m.Raw) {
			rawPaths = append(rawPaths, m.Raw)
		}
	}
	if len(rawPaths) > 0 {
		if err := cfgLoader.AppendGitignore(gitignorePath, rawPaths); err != nil {
			fmt.Fprintf(cmd.ErrOrStderr(), "warning: failed to update .gitignore: %v\n", err)
		}
	}

	fmt.Fprintf(cmd.OutOrStdout(), "generated agedir.yaml: %s\n", configPath)
	if opts.skipScan {
		fmt.Fprintln(cmd.OutOrStdout(), "skipped scanning; generated template-only agedir.yaml")
	} else if len(result.Matches) > 0 {
		fmt.Fprintf(cmd.OutOrStdout(), "%d sensitive file(s) detected\n", len(result.Matches))
	}

	return nil
}

func confirmScan(cmd *cobra.Command) (bool, error) {
	return confirmYesNo(cmd, "Scan the project for sensitive files? [y/N]: ")
}

func confirmYesNo(cmd *cobra.Command, prompt string) (bool, error) {
	fmt.Fprint(cmd.OutOrStdout(), prompt)
	answer, err := readLine(cmd.InOrStdin())
	if err != nil {
		return false, fmt.Errorf("failed to read confirmation: %w", err)
	}
	answer = strings.ToLower(strings.TrimSpace(answer))
	if answer == "" {
		return false, nil
	}
	if answer == "n" || answer == "no" {
		return false, nil
	}
	if answer == "y" || answer == "yes" {
		return true, nil
	}
	return false, fmt.Errorf("invalid response %q; expected y or n", answer)
}

func readLine(r io.Reader) (string, error) {
	reader := bufio.NewReader(r)
	line, err := reader.ReadString('\n')
	if err != nil && err != io.EOF {
		return "", err
	}
	return strings.TrimRight(line, "\r\n"), nil
}

// isGitIgnored reports whether path (relative to root) is already covered by git's ignore rules.
// Returns false if git is unavailable or root is not a git repository.
func isGitIgnored(root, path string) bool {
	cmd := exec.Command("git", "check-ignore", "-q", path)
	cmd.Dir = root
	return cmd.Run() == nil
}
