//go:build windows && !seatbelt
// +build windows,!seatbelt

package main

// seatbeltEmbedded holds the embedded Seatbelt binary when the test is built
// with the `seatbelt` tag AND tools/Seatbelt.exe was present (see build_all.sh,
// which generates seatbelt_embed_real.go). Default builds ship nil and the
// test falls back to runtime loading from c:\F0\tools\Seatbelt.exe or skips.
var seatbeltEmbedded []byte
