package cmd

import (
	"testing"
)

func TestRootCommand_HasFourSubcommands(t *testing.T) {
	expected := []string{"decrypt", "encrypt", "init", "rekey"}
	cmds := rootCmd.Commands()

	names := make(map[string]bool, len(cmds))
	for _, c := range cmds {
		names[c.Name()] = true
	}

	for _, e := range expected {
		if !names[e] {
			t.Errorf("subcommand %q is not registered", e)
		}
	}

	if len(cmds) != len(expected) {
		t.Errorf("subcommand count: got %d, want %d", len(cmds), len(expected))
	}
}

func TestRootCommand_HelpDoesNotError(t *testing.T) {
	rootCmd.SetArgs([]string{"--help"})
	// cobra outputs help and returns nil by default
	if err := rootCmd.Help(); err != nil {
		t.Errorf("Help() returned error: %v", err)
	}
}
