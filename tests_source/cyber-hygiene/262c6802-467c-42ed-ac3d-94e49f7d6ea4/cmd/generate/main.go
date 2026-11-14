package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type intermediate struct {
	Name           string `json:"name"`
	Usage          string `json:"usage"`
	IssuerOperator string `json:"issuer_operator"`
	PEM            string `json:"pem"`
}

type root struct {
	Name string `json:"name"`
	PEM  string `json:"pem"`
}

var scalars = map[string]int64{
	"EM DV TLS CA - G3B": 156,
	"EM OV TLS CA - G3B": 155,
	"EM EV TLS CA - G3B": 115,
	"EM DV TLS CA - G3C": 230,
	"EM OV TLS CA - G3C": 4,
	"EM EV TLS CA - G3C": 56,
	"EM OV CS CA - G3B":  66,
	"EM OV CS CA - G3C":  237,
}

func main() {
	if len(os.Args) != 2 {
		fatalf("usage: generate <test-directory>")
	}
	base := os.Args[1]
	out := filepath.Join(base, "generated")
	must(os.MkdirAll(out, 0755))

	intermediates := readIntermediates(filepath.Join(base, "assets", "impacted-intermediates.json"))
	roots := readRoots(filepath.Join(base, "assets", "roots.json"))
	direct, cross := splitIntermediates(intermediates)

	directChain := readCertificates(filepath.Join(base, "assets", "chains", "regular", "dv-g3b-emudhra.we-have-a-problem.com.pem"))
	if len(directChain) != 3 {
		fatalf("unexpected direct TLS chain length: %d", len(directChain))
	}

	for name, scalar := range scalars {
		if !strings.Contains(name, " TLS ") {
			continue
		}
		ca := direct[name]
		signer := caSigner(ca, scalar)
		kind := shortName(name, " TLS CA - ")
		hostname := strings.ToLower(strings.ReplaceAll(kind, "-", "-")) + "-emudhra.f0.test"
		leaf, key, leafDER := makeLeaf(hostname, ca, signer, x509.ExtKeyUsageServerAuth)
		leafPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER})
		keyPEM := marshalKey(key)
		must(os.WriteFile(filepath.Join(out, "tls-"+kind+"-leaf.key"), keyPEM, 0600))
		must(os.WriteFile(filepath.Join(out, "tls-"+kind+"-direct.pem"), joinPEM(leafPEM, pemFor(ca), pemFor(directChain[2])), 0644))
		must(os.WriteFile(filepath.Join(out, "tls-"+kind+"-aaa.pem"), joinPEM(leafPEM, pemFor(cross[name])), 0644))
		_ = leaf
	}

	for _, name := range []string{"EM OV CS CA - G3B", "EM OV CS CA - G3C"} {
		ca := direct[name]
		signer := caSigner(ca, scalars[name])
		kind := shortName(name, " CS CA - ")
		_, key, leafDER := makeLeaf("F0RT1KA eMudhra Trust Validator "+kind, ca, signer, x509.ExtKeyUsageCodeSigning)
		leafPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER})
		must(os.WriteFile(filepath.Join(out, "codesign-"+kind+"-direct-signer.pem"), joinPEM(leafPEM, pemFor(ca), []byte(roots["emSign Root CS CA - G3"])), 0644))
		must(os.WriteFile(filepath.Join(out, "codesign-"+kind+"-aaa-signer.pem"), joinPEM(leafPEM, pemFor(cross[name])), 0644))
		must(os.WriteFile(filepath.Join(out, "codesign-"+kind+"-leaf.key"), marshalKey(key), 0600))
	}
}

func readIntermediates(path string) []intermediate {
	data, err := os.ReadFile(path)
	must(err)
	var entries []intermediate
	must(json.Unmarshal(data, &entries))
	return entries
}

func readRoots(path string) map[string]string {
	data, err := os.ReadFile(path)
	must(err)
	var entries []root
	must(json.Unmarshal(data, &entries))
	result := map[string]string{}
	for _, entry := range entries {
		result[entry.Name] = entry.PEM
	}
	return result
}

func splitIntermediates(entries []intermediate) (map[string]*x509.Certificate, map[string]*x509.Certificate) {
	direct := map[string]*x509.Certificate{}
	cross := map[string]*x509.Certificate{}
	for _, entry := range entries {
		cert := parseCertificate([]byte(entry.PEM))
		switch entry.IssuerOperator {
		case "eMudhra":
			direct[entry.Name] = cert
		case "Sectigo":
			cross[entry.Name] = cert
		}
	}
	for name := range scalars {
		if direct[name] == nil || cross[name] == nil {
			fatalf("missing direct or cross-signed intermediate for %s", name)
		}
	}
	return direct, cross
}

func caSigner(cert *x509.Certificate, scalar int64) *ecdsa.PrivateKey {
	public, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		fatalf("%s does not contain an ECDSA key", cert.Subject.CommonName)
	}
	private := &ecdsa.PrivateKey{PublicKey: ecdsa.PublicKey{Curve: elliptic.P384(), X: public.X, Y: public.Y}, D: big.NewInt(scalar)}
	x, y := private.Curve.ScalarBaseMult(private.D.Bytes())
	if x.Cmp(public.X) != 0 || y.Cmp(public.Y) != 0 {
		fatalf("private scalar does not match %s", cert.Subject.CommonName)
	}
	return private
}

func makeLeaf(commonName string, parent *x509.Certificate, parentKey *ecdsa.PrivateKey, usage x509.ExtKeyUsage) (*x509.Certificate, *ecdsa.PrivateKey, []byte) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	must(err)
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	must(err)
	now := time.Now().UTC()
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: commonName, Organization: []string{"F0RT1KA controlled validation artifact"}},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{usage},
		BasicConstraintsValid: true,
	}
	if usage == x509.ExtKeyUsageServerAuth {
		template.DNSNames = []string{commonName}
	}
	der, err := x509.CreateCertificate(rand.Reader, template, parent, &key.PublicKey, parentKey)
	must(err)
	leaf, err := x509.ParseCertificate(der)
	must(err)
	return leaf, key, der
}

func shortName(name, separator string) string {
	parts := strings.Split(name, separator)
	if len(parts) != 2 {
		fatalf("unexpected intermediate name: %s", name)
	}
	kind := strings.ToLower(strings.TrimPrefix(parts[0], "EM "))
	return kind + "-" + strings.ToLower(parts[1])
}

func parseCertificate(data []byte) *x509.Certificate {
	block, _ := pem.Decode(data)
	if block == nil {
		fatalf("certificate PEM could not be decoded")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	must(err)
	return cert
}

func readCertificates(path string) []*x509.Certificate {
	data, err := os.ReadFile(path)
	must(err)
	var certs []*x509.Certificate
	for len(data) > 0 {
		var block *pem.Block
		block, data = pem.Decode(data)
		if block == nil {
			break
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		must(err)
		certs = append(certs, cert)
	}
	return certs
}

func pemFor(cert *x509.Certificate) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
}

func marshalKey(key *ecdsa.PrivateKey) []byte {
	der, err := x509.MarshalECPrivateKey(key)
	must(err)
	return pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
}

func joinPEM(parts ...[]byte) []byte {
	var result []byte
	for _, part := range parts {
		result = append(result, part...)
		if len(part) > 0 && part[len(part)-1] != '\n' {
			result = append(result, '\n')
		}
	}
	return result
}

func must(err error) {
	if err != nil {
		fatalf("%v", err)
	}
}

func fatalf(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}
