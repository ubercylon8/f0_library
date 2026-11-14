package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

type clientInvocation struct {
	name     string
	args     []string
	stdin    string
	classify func(string, error) probeStatus
}

type clientFactory func(int, string) clientInvocation

func probeTLS(ctx context.Context, runtimeName string, testCase tlsCase, factory clientFactory) probeResult {
	result := probeResult{Runtime: runtimeName, Case: testCase.Name, Status: probeError}
	chainPEM, err := testAssets.ReadFile(testCase.ChainPath)
	if err != nil {
		result.Evidence = fmt.Sprintf("failed to read certificate chain: %v", err)
		return result
	}
	keyPEM, err := testAssets.ReadFile(testCase.KeyPath)
	if err != nil {
		result.Evidence = fmt.Sprintf("failed to read leaf key: %v", err)
		return result
	}
	certificate, err := tls.X509KeyPair(chainPEM, keyPEM)
	if err != nil {
		result.Evidence = fmt.Sprintf("failed to load test certificate: %v", err)
		return result
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		result.Evidence = fmt.Sprintf("failed to open loopback listener: %v", err)
		return result
	}
	defer listener.Close()
	port := listener.Addr().(*net.TCPAddr).Port
	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)
		connection, acceptErr := listener.Accept()
		if acceptErr != nil {
			return
		}
		defer connection.Close()
		_ = connection.SetDeadline(time.Now().Add(15 * time.Second))
		tlsConnection := tls.Server(connection, &tls.Config{
			Certificates: []tls.Certificate{certificate},
			MinVersion:   tls.VersionTLS12,
			MaxVersion:   tls.VersionTLS13,
		})
		if handshakeErr := tlsConnection.Handshake(); handshakeErr != nil {
			return
		}
		_ = tlsConnection.SetReadDeadline(time.Now().Add(750 * time.Millisecond))
		_, _ = io.CopyN(io.Discard, tlsConnection, 4096)
		_, _ = io.WriteString(tlsConnection, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK")
	}()

	invocation := factory(port, testCase.Hostname)
	output, runErr := runProcess(ctx, invocation.name, invocation.args, invocation.stdin)
	result.Status = invocation.classify(output, runErr)
	result.Evidence = compactEvidence(output, runErr)
	listener.Close()
	select {
	case <-serverDone:
	case <-time.After(100 * time.Millisecond):
	}
	return result
}

func runProcess(ctx context.Context, name string, args []string, stdin string) (string, error) {
	command := exec.CommandContext(ctx, name, args...)
	if strings.HasPrefix(strings.ToLower(filepath.Base(name)), "python") {
		command.Env = append(os.Environ(), "PYTHONDONTWRITEBYTECODE=1")
	}
	command.Stdin = strings.NewReader(stdin)
	var output bytes.Buffer
	command.Stdout = &output
	command.Stderr = &output
	err := command.Run()
	pid := 0
	if command.Process != nil {
		pid = command.Process.Pid
	}
	exitCode := 0
	if command.ProcessState != nil {
		exitCode = command.ProcessState.ExitCode()
	}
	errorMessage := ""
	if err != nil {
		errorMessage = err.Error()
	}
	LogProcessExecution(filepath.Base(name), name+" "+strings.Join(args, " "), pid, err == nil, exitCode, errorMessage)
	return output.String(), err
}

func classifySentinel(output string, err error) probeStatus {
	switch {
	case strings.Contains(output, "F0_ACCEPTED"):
		return probeAccepted
	case strings.Contains(output, "F0_REJECTED"):
		return probeRejected
	default:
		return probeError
	}
}

func compactEvidence(output string, err error) string {
	text := strings.TrimSpace(output)
	if text == "" && err != nil {
		text = err.Error()
	}
	text = strings.ReplaceAll(text, "\x00", "")
	if len(text) > 1000 {
		text = text[:1000] + "…"
	}
	return text
}

func extractAsset(workdir, assetPath string) (string, error) {
	data, err := testAssets.ReadFile(assetPath)
	if err != nil {
		return "", fmt.Errorf("failed to read embedded asset %s: %v", assetPath, err)
	}
	outputName := filepath.Base(assetPath)
	if strings.HasSuffix(assetPath, ".gz") {
		reader, gzipErr := gzip.NewReader(bytes.NewReader(data))
		if gzipErr != nil {
			return "", fmt.Errorf("failed to open compressed asset %s: %v", assetPath, gzipErr)
		}
		data, err = io.ReadAll(reader)
		closeErr := reader.Close()
		if err != nil {
			return "", fmt.Errorf("failed to decompress asset %s: %v", assetPath, err)
		}
		if closeErr != nil {
			return "", fmt.Errorf("failed to finish decompressing asset %s: %v", assetPath, closeErr)
		}
		outputName = strings.TrimSuffix(outputName, ".gz")
	}
	path := filepath.Join(workdir, outputName)
	if err := os.WriteFile(path, data, 0600); err != nil {
		return "", fmt.Errorf("failed to write validation asset: %v", err)
	}
	return path, nil
}

func portArgument(port int) string {
	return strconv.Itoa(port)
}
