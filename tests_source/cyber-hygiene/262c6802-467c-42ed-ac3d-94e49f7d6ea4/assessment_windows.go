//go:build windows

package main

import (
	"context"
	"fmt"
	"os"
)

func runAssessment(ctx context.Context) ([]ControlResult, error) {
	workdir, err := os.MkdirTemp(LOG_DIR, "emudhra-assessment-")
	if err != nil {
		return nil, fmt.Errorf("failed to create assessment workspace: %v", err)
	}
	defer os.RemoveAll(workdir)
	scriptPath, err := extractAsset(workdir, "helpers/windows_validator.ps1")
	if err != nil {
		return nil, err
	}

	controls := []ControlResult{}
	for _, path := range []string{"direct", "aaa"} {
		probes := []probeResult{}
		for _, testCase := range generatedTLSCases() {
			if testCase.Path != path {
				continue
			}
			probes = append(probes, probeTLS(ctx, "schannel", testCase, windowsTLSFactory(scriptPath)))
		}
		id, name := "CH-EMC-001", "Windows Schannel eMudhra G3 chains"
		if path == "aaa" {
			id, name = "CH-EMC-002", "Windows Schannel Sectigo AAA cross-signed chains"
		}
		controls = append(controls, makeControl(id, name, "native:schannel", probes, []string{"T1557"}))
	}

	_, _, rollover := offlineTLSPaths()
	rolloverProbes := []probeResult{}
	for _, assetPath := range rollover {
		rolloverProbes = append(rolloverProbes, probeWindowsOfflineChain(ctx, workdir, scriptPath, assetPath))
	}
	controls = append(controls, makeControl("CH-EMC-003", "Windows key-rollover chains", "native:x509chain", rolloverProbes, []string{"T1557"}))

	authProbes := []probeResult{}
	for _, kind := range []string{"ov-g3b", "ov-g3c"} {
		for _, path := range []string{"direct", "aaa"} {
			caseName := kind + "-" + path
			assetPath := "generated/forged-" + caseName + ".exe.gz"
			binaryPath, extractErr := extractAsset(workdir, assetPath)
			probe := probeResult{Runtime: "authenticode", Case: caseName, Status: probeError}
			if extractErr != nil {
				probe.Evidence = extractErr.Error()
			} else {
				probe = probeAuthenticode(binaryPath, caseName)
			}
			authProbes = append(authProbes, probe)
		}
	}
	controls = append(controls, makeControl("CH-EMC-004", "Windows Authenticode compromised code-signing CAs", "native:authenticode", authProbes, []string{"T1553.002"}))
	controls = append(controls, runRuntimeAssessments(ctx, workdir)...)
	return controls, nil
}

func windowsTLSFactory(scriptPath string) clientFactory {
	return func(port int, hostname string) clientInvocation {
		args := []string{"-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", scriptPath, "-Mode", "tls", "-Port", portArgument(port), "-ServerName", hostname}
		return clientInvocation{name: "powershell.exe", args: args, classify: classifySentinel}
	}
}

func probeWindowsOfflineChain(ctx context.Context, workdir, scriptPath, assetPath string) probeResult {
	probe := probeResult{Runtime: "x509chain", Case: assetPath, Status: probeError}
	chainPath, err := extractAsset(workdir, assetPath)
	if err != nil {
		probe.Evidence = err.Error()
		return probe
	}
	output, runErr := runProcess(ctx, "powershell.exe", []string{"-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", scriptPath, "-Mode", "chain", "-ChainPath", chainPath}, "")
	probe.Status = classifySentinel(output, runErr)
	probe.Evidence = compactEvidence(output, runErr)
	return probe
}
