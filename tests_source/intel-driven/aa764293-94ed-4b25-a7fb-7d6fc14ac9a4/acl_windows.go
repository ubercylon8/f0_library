//go:build windows
// +build windows

package main

import (
	"fmt"
	"os/exec"

	"golang.org/x/sys/windows"
)

// grantUserExecute adds a read+execute ACE for the interactive user (identified
// by userToken) to the file at path, so a payload dropped as SYSTEM into a
// C:\F0 locked by the agent stays launchable as that user. The orchestrator
// runs as SYSTEM, which keeps full control through the folder's inherited ACE,
// so it can rewrite the file's DACL.
func grantUserExecute(userToken windows.Token, path string) error {
	tu, err := userToken.GetTokenUser()
	if err != nil {
		return fmt.Errorf("GetTokenUser: %w", err)
	}
	sid := tu.User.Sid.String()
	argv := grantExecuteArgs(path, sid)
	out, err := exec.Command(argv[0], argv[1:]...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%v: %w: %s", argv[1:], err, out)
	}
	return nil
}
