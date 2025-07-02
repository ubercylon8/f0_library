/*
ID: b484be6c-6e79-4f96-b72d-6526f0f0103a
NAME: Writing Packed Executable to Disk
TECHNIQUE: T1027.002
UNIT: response
CREATED: 2024-01-08 19:12:00.211886
*/
package main

import (
	Dropper "github.com/preludeorg/libraries/go/tests/dropper"
	Endpoint "github.com/preludeorg/libraries/go/tests/endpoint"
)

func dropUpxPackedExe() bool {
	Endpoint.Say("Dropping packed executable to disk")
	mzHeader := []byte{'M', 'Z'}
	upxMagic1 := []byte{0x55, 0x50, 0x58, 0x30, 0x00, 0x00, 0x00} // UPX magic 1
	upxMagic2 := []byte{0x55, 0x50, 0x58, 0x31, 0x00, 0x00, 0x00} // UPX magic 2
	upxHeader := []byte{'U', 'P', 'X', '!'}

	data := append(append(append(append([]byte(nil), mzHeader...), upxMagic1...), upxMagic2...), upxHeader...)

	return !Endpoint.Quarantined("packed.exe", data)
}

func test() {
	if err := Endpoint.Dropper(Dropper.Dropper); err != nil {
		Endpoint.Say("%v", err)
		Endpoint.Stop(Endpoint.UnexpectedTestError)
	}
	if !dropUpxPackedExe() {
		Endpoint.Say("Encountered error when writing packed executable to disk!")
		Endpoint.Stop(Endpoint.FileQuarantinedOnExtraction)
	}
	Endpoint.Say("Successfully extracted UPX-packed exe to disk")
	Endpoint.Stop(Endpoint.Unprotected)
}

func main() {
	Endpoint.Start(test)
}
