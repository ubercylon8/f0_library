//go:build linux

package main

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"strconv"
	"strings"
)

func runAssessment(ctx context.Context) ([]ControlResult, error) {
	workdir, err := os.MkdirTemp(LOG_DIR, "emudhra-assessment-")
	if err != nil {
		return nil, fmt.Errorf("failed to create assessment workspace: %v", err)
	}
	defer os.RemoveAll(workdir)

	controls := []ControlResult{}
	direct, cross, rollover := offlineTLSPaths()
	openssl := findExecutable("openssl")
	if openssl == "" {
		for _, item := range []struct{ id, name string }{{"CH-EMC-001", "Linux OpenSSL eMudhra G3 chains"}, {"CH-EMC-002", "Linux OpenSSL Sectigo AAA cross-signed chains"}, {"CH-EMC-003", "Linux OpenSSL key-rollover chains"}} {
			controls = append(controls, makeControl(item.id, item.name, "native:openssl", []probeResult{{Runtime: "openssl", Case: "initialization", Status: probeError, Evidence: "openssl executable was not found"}}, []string{"T1557"}))
		}
	} else {
		controls = append(controls,
			makeControl("CH-EMC-001", "Linux OpenSSL eMudhra G3 chains", "native:"+openssl, probeOfflinePaths(ctx, workdir, openssl, direct), []string{"T1557"}),
			makeControl("CH-EMC-002", "Linux OpenSSL Sectigo AAA cross-signed chains", "native:"+openssl, probeOfflinePaths(ctx, workdir, openssl, cross), []string{"T1557"}),
			makeControl("CH-EMC-003", "Linux OpenSSL key-rollover chains", "native:"+openssl, probeOfflinePaths(ctx, workdir, openssl, rollover), []string{"T1557"}),
		)
	}
	controls = append(controls, runRuntimeAssessments(ctx, workdir)...)
	return controls, nil
}

func probeOfflinePaths(ctx context.Context, workdir, openssl string, paths []string) []probeResult {
	probes := []probeResult{}
	for _, assetPath := range paths {
		probe := probeResult{Runtime: "openssl", Case: assetPath, Status: probeError}
		chainPath, err := extractAsset(workdir, assetPath)
		if err != nil {
			probe.Evidence = err.Error()
			probes = append(probes, probe)
			continue
		}
		chainPEM, err := testAssets.ReadFile(assetPath)
		if err != nil {
			probe.Evidence = fmt.Sprintf("failed to read chain metadata: %v", err)
			probes = append(probes, probe)
			continue
		}
		block, _ := pem.Decode(chainPEM)
		if block == nil {
			probe.Evidence = "leaf certificate PEM could not be decoded"
			probes = append(probes, probe)
			continue
		}
		leaf, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			probe.Evidence = fmt.Sprintf("leaf certificate could not be parsed: %v", err)
			probes = append(probes, probe)
			continue
		}
		verificationTime := leaf.NotBefore.Add(24 * 60 * 60 * 1000000000).Unix()
		args := []string{"verify", "-show_chain", "-purpose", "sslserver", "-attime", strconv.FormatInt(verificationTime, 10)}
		if len(leaf.DNSNames) > 0 {
			args = append(args, "-verify_hostname", leaf.DNSNames[0])
		}
		args = append(args, "-untrusted", chainPath, chainPath)
		output, runErr := runProcess(ctx, openssl, args, "")
		lower := strings.ToLower(output)
		switch {
		case strings.Contains(lower, "could not open") || strings.Contains(lower, "no such file"):
			probe.Status = probeError
		case runErr == nil && strings.Contains(lower, ": ok"):
			probe.Status = probeAccepted
		case strings.Contains(lower, "certificate verify failed") || strings.Contains(lower, "verify error") || strings.Contains(lower, "unable to get") || strings.Contains(lower, "unsupported certificate purpose"):
			probe.Status = probeRejected
		default:
			probe.Status = probeError
		}
		probe.Evidence = compactEvidence(output, runErr)
		probes = append(probes, probe)
	}
	return probes
}
