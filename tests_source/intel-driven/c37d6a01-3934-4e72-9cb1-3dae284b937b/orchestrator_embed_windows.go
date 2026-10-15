//go:build windows

// Windows embed set for the orchestrator. Stage binaries are Windows PEs
// (.exe), signed then gzip-compressed at build time.

package main

import (
	_ "embed"
	"fmt"
)

//go:embed c37d6a01-3934-4e72-9cb1-3dae284b937b-T1105.exe.gz
var stage1Compressed []byte

//go:embed c37d6a01-3934-4e72-9cb1-3dae284b937b-T1572.exe.gz
var stage2Compressed []byte

//go:embed c37d6a01-3934-4e72-9cb1-3dae284b937b-T1005.exe.gz
var stage3Compressed []byte

// stageBinaryName returns the on-disk filename for a stage binary on Windows.
func stageBinaryName(technique string) string {
	return fmt.Sprintf("%s-%s.exe", TEST_UUID, technique)
}
