package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

const nodeProbeScript = `
const tls = require('tls');
const socket = tls.connect({host: '127.0.0.1', port: Number(process.argv[1]), servername: process.argv[2], rejectUnauthorized: true});
socket.setTimeout(10000);
socket.once('secureConnect', () => { console.log('F0_ACCEPTED ' + socket.getProtocol()); socket.end(); });
socket.once('error', (error) => {
  const text = String(error.code || '') + ' ' + String(error.message || error);
  if (/CERT|UNABLE_TO|SELF_SIGNED|DEPTH|PKIX|TRUST|REVOKE/i.test(text)) {
    console.log('F0_REJECTED ' + text.replace(/[\r\n]/g, ' '));
    process.exitCode = 2;
  } else {
    console.log('F0_ERROR ' + text.replace(/[\r\n]/g, ' '));
    process.exitCode = 3;
  }
});
socket.once('timeout', () => { console.log('F0_ERROR client timeout'); socket.destroy(); process.exitCode = 3; });
`

const pythonProbeScript = `
import socket, ssl, sys
port, hostname = int(sys.argv[1]), sys.argv[2]
try:
    context = ssl.create_default_context(cafile=(sys.argv[3] if len(sys.argv) > 3 else None))
    with socket.create_connection(('127.0.0.1', port), timeout=10) as plain:
        with context.wrap_socket(plain, server_hostname=hostname) as connection:
            print('F0_ACCEPTED ' + connection.version())
except ssl.SSLCertVerificationError as error:
    print('F0_REJECTED ' + str(error).replace('\\n', ' '))
    sys.exit(2)
except ssl.SSLError as error:
    text = str(error)
    if 'certificate' in text.lower() or 'cert' in text.lower():
        print('F0_REJECTED ' + text.replace('\\n', ' '))
        sys.exit(2)
    print('F0_ERROR ' + text.replace('\\n', ' '))
    sys.exit(3)
except Exception as error:
    print('F0_ERROR ' + str(error).replace('\\n', ' '))
    sys.exit(3)
`

func runRuntimeAssessments(ctx context.Context, workdir string) []ControlResult {
	controls := []ControlResult{}
	techniques := []string{"T1557"}

	if executable := findExecutable("node", "nodejs"); executable != "" {
		factory := func(port int, hostname string) clientInvocation {
			return clientInvocation{name: executable, args: []string{"-e", nodeProbeScript, portArgument(port), hostname}, classify: classifySentinel}
		}
		controls = append(controls, makeControl("CH-EMC-010", "Node.js default TLS trust", "runtime:"+executable, probeAllCases(ctx, "node", factory), techniques))
	} else {
		controls = append(controls, makeControl("CH-EMC-010", "Node.js default TLS trust", "runtime:node", nil, techniques))
	}

	if executable := findExecutable("java"); executable != "" {
		classPath, err := extractAsset(workdir, "generated/TlsProbe.class")
		var probes []probeResult
		if err != nil {
			probes = []probeResult{{Runtime: "java", Case: "initialization", Status: probeError, Evidence: err.Error()}}
		} else {
			factory := func(port int, hostname string) clientInvocation {
				return clientInvocation{name: executable, args: []string{"-cp", filepath.Dir(classPath), "TlsProbe", portArgument(port), hostname}, classify: classifySentinel}
			}
			probes = probeAllCases(ctx, "java", factory)
		}
		controls = append(controls, makeControl("CH-EMC-011", "Java JSSE default TLS trust", "runtime:"+executable, probes, techniques))
	} else {
		controls = append(controls, makeControl("CH-EMC-011", "Java JSSE default TLS trust", "runtime:java", nil, techniques))
	}

	if executable := findExecutable("python3", "python"); executable != "" && !pythonStoreAlias(ctx, executable) {
		controls = append(controls, makeControl("CH-EMC-012", "Python default TLS trust", "runtime:"+executable, probeAllCases(ctx, "python-default", pythonFactory(executable, "")), techniques))
		certifi := pythonCAPath(ctx, executable, "import certifi; print(certifi.where())")
		if certifi != "" {
			controls = append(controls, makeControl("CH-EMC-013", "Python certifi TLS trust", "runtime:"+executable, probeAllCases(ctx, "python-certifi", pythonFactory(executable, certifi)), techniques))
		} else {
			controls = append(controls, makeControl("CH-EMC-013", "Python certifi TLS trust", "runtime:"+executable, nil, techniques))
		}
		pipCertifi := pythonCAPath(ctx, executable, "import pip._vendor.certifi; print(pip._vendor.certifi.where())")
		if pipCertifi != "" {
			controls = append(controls, makeControl("CH-EMC-014", "pip vendored certifi TLS trust", "runtime:"+executable, probeAllCases(ctx, "pip-certifi", pythonFactory(executable, pipCertifi)), techniques))
		} else {
			controls = append(controls, makeControl("CH-EMC-014", "pip vendored certifi TLS trust", "runtime:"+executable, nil, techniques))
		}
	} else {
		for _, item := range []struct{ id, name string }{{"CH-EMC-012", "Python default TLS trust"}, {"CH-EMC-013", "Python certifi TLS trust"}, {"CH-EMC-014", "pip vendored certifi TLS trust"}} {
			controls = append(controls, makeControl(item.id, item.name, "runtime:python", nil, techniques))
		}
	}

	if executable := findExecutable("curl"); executable != "" {
		factory := func(port int, hostname string) clientInvocation {
			authority := fmt.Sprintf("%s:%d", hostname, port)
			args := []string{"--silent", "--show-error", "--max-time", "12", "--output", os.DevNull, "--resolve", authority + ":127.0.0.1", "https://" + authority + "/"}
			return clientInvocation{name: executable, args: args, classify: classifyCurl}
		}
		controls = append(controls, makeControl("CH-EMC-015", "curl default TLS trust", "runtime:"+executable, probeAllCases(ctx, "curl", factory), techniques))
	} else {
		controls = append(controls, makeControl("CH-EMC-015", "curl default TLS trust", "runtime:curl", nil, techniques))
	}
	return controls
}

func probeAllCases(ctx context.Context, runtimeName string, factory clientFactory) []probeResult {
	probes := []probeResult{}
	for _, testCase := range generatedTLSCases() {
		if ctx.Err() != nil {
			probes = append(probes, probeResult{Runtime: runtimeName, Case: testCase.Name, Status: probeError, Evidence: "execution context ended"})
			continue
		}
		probes = append(probes, probeTLS(ctx, runtimeName, testCase, factory))
	}
	return probes
}

func pythonFactory(executable, cafile string) clientFactory {
	return func(port int, hostname string) clientInvocation {
		args := []string{"-c", pythonProbeScript, portArgument(port), hostname}
		if cafile != "" {
			args = append(args, cafile)
		}
		return clientInvocation{name: executable, args: args, classify: classifySentinel}
	}
}

func pythonCAPath(ctx context.Context, executable, expression string) string {
	output, err := runProcess(ctx, executable, []string{"-c", expression}, "")
	if err != nil {
		return ""
	}
	path := strings.TrimSpace(output)
	if path == "" || strings.Contains(path, "Traceback") {
		return ""
	}
	if info, statErr := os.Stat(path); statErr != nil || info.IsDir() {
		return ""
	}
	return path
}

func classifyCurl(output string, err error) probeStatus {
	if err == nil {
		return probeAccepted
	}
	lower := strings.ToLower(output)
	if strings.Contains(lower, "certificate") || strings.Contains(lower, "cert") || strings.Contains(lower, "ssl connect error") {
		return probeRejected
	}
	return probeError
}

func pythonStoreAlias(ctx context.Context, executable string) bool {
	output, _ := runProcess(ctx, executable, []string{"--version"}, "")
	return strings.Contains(output, "Python was not found; run without arguments to install from the Microsoft Store")
}

func findExecutable(names ...string) string {
	seen := map[string]bool{}
	for _, name := range names {
		path, err := exec.LookPath(name)
		if err != nil {
			continue
		}
		resolved, resolveErr := filepath.EvalSymlinks(path)
		if resolveErr == nil {
			path = resolved
		}
		if !seen[path] {
			return path
		}
	}
	return ""
}
