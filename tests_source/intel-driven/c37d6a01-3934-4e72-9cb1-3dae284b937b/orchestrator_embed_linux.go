//go:build linux

// Linux embed set for the orchestrator. Stage binaries are Linux ELF binaries
// (no extension), gzip-compressed at build time. Signing is a no-op on Linux.

package main

import (
	_ "embed"
	"fmt"
)

//go:embed c37d6a01-3934-4e72-9cb1-3dae284b937b-T1105.gz
var stage1Compressed []byte

//go:embed c37d6a01-3934-4e72-9cb1-3dae284b937b-T1572.gz
var stage2Compressed []byte

//go:embed c37d6a01-3934-4e72-9cb1-3dae284b937b-T1005.gz
var stage3Compressed []byte

// stageBinaryName returns the on-disk filename for a stage binary on Linux.
func stageBinaryName(technique string) string {
	return fmt.Sprintf("%s-%s", TEST_UUID, technique)
}
