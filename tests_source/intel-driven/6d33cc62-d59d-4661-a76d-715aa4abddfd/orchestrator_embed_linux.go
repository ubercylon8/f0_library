//go:build linux

// Linux embed set for the orchestrator. Stage binaries are Linux ELF binaries
// (no extension), gzip-compressed at build time. Signing is a no-op on Linux.

package main

import (
	_ "embed"
	"fmt"
)

//go:embed 6d33cc62-d59d-4661-a76d-715aa4abddfd-T1552.001.gz
var stage1Compressed []byte

//go:embed 6d33cc62-d59d-4661-a76d-715aa4abddfd-T1005.gz
var stage2Compressed []byte

//go:embed 6d33cc62-d59d-4661-a76d-715aa4abddfd-T1567.gz
var stage3Compressed []byte

// stageBinaryName returns the on-disk filename for a stage binary on Linux.
func stageBinaryName(technique string) string {
	return fmt.Sprintf("%s-%s", TEST_UUID, technique)
}
