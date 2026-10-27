package main

import "fmt"

// grantExecuteArgs returns the icacls argv that adds a read+execute ACE for the
// given user SID to a file, without touching the existing ACEs. The SID is
// passed in the "*SID" form so icacls treats it as a SID rather than an account
// name (account names are localized, e.g. "Usuarios" on Spanish Windows).
//
// Needed because the agent locks C:\F0 to SYSTEM + Administrators (agent
// 0.7.1+): a payload this test drops there as SYSTEM inherits that restriction,
// so the interactive user the test launches it as cannot read or execute it
// until this ACE is added.
func grantExecuteArgs(path, sid string) []string {
	return []string{"icacls", path, "/grant", fmt.Sprintf("*%s:(RX)", sid), "/Q"}
}
