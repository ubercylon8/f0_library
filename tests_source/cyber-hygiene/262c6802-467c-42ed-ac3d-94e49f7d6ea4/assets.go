package main

import "embed"

//go:embed generated assets/chains/regular/*.pem assets/chains/rollover/*.pem helpers/windows_validator.ps1
var testAssets embed.FS

type tlsCase struct {
	Name      string
	ChainPath string
	KeyPath   string
	Hostname  string
	Path      string
}

func generatedTLSCases() []tlsCase {
	cases := make([]tlsCase, 0, 12)
	for _, kind := range []string{"dv-g3b", "ov-g3b", "ev-g3b", "dv-g3c", "ov-g3c", "ev-g3c"} {
		for _, path := range []string{"direct", "aaa"} {
			cases = append(cases, tlsCase{
				Name:      kind + "-" + path,
				ChainPath: "generated/tls-" + kind + "-" + path + ".pem",
				KeyPath:   "generated/tls-" + kind + "-leaf.key",
				Hostname:  kind + "-emudhra.f0.test",
				Path:      path,
			})
		}
	}
	return cases
}

func offlineTLSPaths() ([]string, []string, []string) {
	direct := []string{
		"dv-g3b-emudhra", "ov-g3b-emudhra", "ev-g3b-emudhra",
		"dv-g3c-emudhra", "ov-g3c-emudhra", "ev-g3c-emudhra",
		"dv-g3b-noct-emudhra",
	}
	cross := []string{
		"dv-g3b-aaa-emudhra", "ov-g3b-aaa-emudhra", "ev-g3b-aaa-emudhra",
		"dv-g3c-aaa-emudhra", "ov-g3c-aaa-emudhra", "ev-g3c-aaa-emudhra",
		"dv-g3b-aaa-noct-emudhra",
	}
	for i, name := range direct {
		direct[i] = "assets/chains/regular/" + name + ".we-have-a-problem.com.pem"
	}
	for i, name := range cross {
		cross[i] = "assets/chains/regular/" + name + ".we-have-a-problem.com.pem"
	}
	rollover := []string{
		"assets/chains/rollover/dv-g3b-noct-rollover-emudhra.we-have-a-problem.com.pem",
		"assets/chains/rollover/dv-g3b-aaa-noct-rollover-emudhra.we-have-a-problem.com.pem",
	}
	return direct, cross, rollover
}
