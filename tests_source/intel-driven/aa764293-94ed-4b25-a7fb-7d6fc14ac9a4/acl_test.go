package main

import (
	"reflect"
	"strings"
	"testing"
)

// The agent locks C:\F0 to SYSTEM + Administrators (agent 0.7.1+), so a payload
// this test drops there as SYSTEM is not readable by the interactive user the
// test then launches it as. We add an explicit read+execute ACE for that
// user's SID on the dropped file. A raw SID is locale-independent, unlike an
// account name (localized, e.g. "Usuarios" on Spanish Windows).
func TestGrantExecuteArgs_ExactArgv(t *testing.T) {
	const path = `C:\F0\RoguePlanet.exe`
	const sid = "S-1-5-21-1111111111-2222222222-3333333333-1001"
	got := grantExecuteArgs(path, sid)
	want := []string{"icacls", path, "/grant", "*" + sid + ":(RX)", "/Q"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("grantExecuteArgs() =\n  %q\nwant\n  %q", got, want)
	}
}

// The SID must be passed as a "*SID" literal so icacls treats it as a SID, not
// an account name, and the grant must be read+execute only.
func TestGrantExecuteArgs_SidLiteralAndRX(t *testing.T) {
	args := grantExecuteArgs(`C:\F0\x.exe`, "S-1-5-18")
	joined := strings.Join(args, " ")
	if !strings.Contains(joined, "*S-1-5-18:(RX)") {
		t.Fatalf("want a *SID:(RX) grant, got %q", joined)
	}
	// Additive grant, never /grant:r — we must not drop SYSTEM/Administrators.
	for _, a := range args {
		if a == "/grant:r" {
			t.Fatalf("grantExecuteArgs must add an ACE (/grant), not replace (/grant:r): %q", args)
		}
	}
}
