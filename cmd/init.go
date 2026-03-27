package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/asmz/agedir/internal/config"
	"github.com/asmz/agedir/internal/scanner"
	"github.com/spf13/cobra"
)

var initConfig string

var initCmd = &cobra.Command{
	Use:          "init",
	Short:        "Scan the project and generate an initial agedir.yaml",
	SilenceUsage: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		opts := initOpts{configPath: initConfig}
		return runInit(cmd, opts, config.New(), scanner.New())
	},
}

func init() {
	initCmd.Flags().StringVar(&initConfig, "config", "", "path to agedir.yaml (default: current directory)")
}

type initOpts struct {
	configPath string
	root       string // project root; defaults to current directory if empty
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
		fmt.Fprintf(cmd.OutOrStdout(), "agedir.yaml already exists. Overwrite? [y/N]: ")
		var answer string
		fmt.Fscan(cmd.InOrStdin(), &answer)
		if strings.ToLower(strings.TrimSpace(answer)) != "y" {
			fmt.Fprintln(cmd.OutOrStdout(), "cancelled.")
			return nil
		}
		// remove existing file to allow overwrite
		if err := os.Remove(configPath); err != nil {
			return fmt.Errorf("failed to remove existing agedir.yaml: %w", err)
		}
	}

	// scan the project for sensitive file candidates
	result, err := sc.Scan(root)
	if err != nil {
		return fmt.Errorf("failed to scan files: %w", err)
	}

	// build a config template
	cfg := &config.Config{
		Version:    "1",
		Recipients: []string{},
		StorageDir: ".agedir/secrets",
	}
	for _, match := range result.Matches {
		cfg.Mapping = append(cfg.Mapping, config.FileMapping{
			Src:  filepath.Base(match) + ".age",
			Dest: match,
		})
	}

	// generate agedir.yaml
	if err := cfgLoader.Generate(cfg, configPath); err != nil {
		return fmt.Errorf("failed to generate agedir.yaml: %w", err)
	}

	// append dest paths to .gitignore
	gitignorePath := filepath.Join(filepath.Dir(configPath), ".gitignore")
	var destPaths []string
	for _, m := range cfg.Mapping {
		destPaths = append(destPaths, m.Dest)
	}
	if len(destPaths) > 0 {
		if err := cfgLoader.AppendGitignore(gitignorePath, destPaths); err != nil {
			fmt.Fprintf(cmd.ErrOrStderr(), "warning: failed to update .gitignore: %v\n", err)
		}
	}

	fmt.Fprintf(cmd.OutOrStdout(), "generated agedir.yaml: %s\n", configPath)
	if len(result.Matches) > 0 {
		fmt.Fprintf(cmd.OutOrStdout(), "%d sensitive file(s) detected\n", len(result.Matches))
	}

	return nil
}
