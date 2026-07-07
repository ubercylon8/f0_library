//go:build windows

// Windows embed set for the orchestrator. Stage binaries are Windows PEs
// (.exe), signed then gzip-compressed at build time.

package main

import (
	_ "embed"
	"fmt"
)

//go:embed 6d33cc62-d59d-4661-a76d-715aa4abddfd-T1552.001.exe.gz
var stage1Compressed []byte

//go:embed 6d33cc62-d59d-4661-a76d-715aa4abddfd-T1005.exe.gz
var stage2Compressed []byte

//go:embed 6d33cc62-d59d-4661-a76d-715aa4abddfd-T1567.exe.gz
var stage3Compressed []byte

// stageBinaryName returns the on-disk filename for a stage binary on Windows.
func stageBinaryName(technique string) string {
	return fmt.Sprintf("%s-%s.exe", TEST_UUID, technique)
}
