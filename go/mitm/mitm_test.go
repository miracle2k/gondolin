package mitm

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func assertLooksLikeMitmCa(t *testing.T, ca *MitmCa) {
	t.Helper()

	if !strings.Contains(ca.KeyPEM, "BEGIN RSA PRIVATE KEY") {
		t.Fatalf("expected rsa private key pem")
	}
	if !strings.Contains(ca.CertPEM, "BEGIN CERTIFICATE") {
		t.Fatalf("expected cert pem")
	}

	certBlock, _ := pem.Decode([]byte(ca.CertPEM))
	if certBlock == nil {
		t.Fatalf("failed to decode cert pem")
	}
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		t.Fatalf("parse cert: %v", err)
	}

	if cert.Subject.CommonName != "gondolin-mitm-ca" {
		t.Fatalf("unexpected CN: %q", cert.Subject.CommonName)
	}
	if cert.Issuer.CommonName != "gondolin-mitm-ca" {
		t.Fatalf("unexpected issuer CN: %q", cert.Issuer.CommonName)
	}

	if err := cert.CheckSignatureFrom(cert); err != nil {
		t.Fatalf("expected self-signed cert: %v", err)
	}

	if !cert.IsCA {
		t.Fatalf("expected IsCA")
	}

	if cert.KeyUsage&(x509.KeyUsageCertSign|x509.KeyUsageCRLSign) != (x509.KeyUsageCertSign|x509.KeyUsageCRLSign) {
		t.Fatalf("expected key usage certSign+crlSign")
	}

	// Check that the relevant extensions are marked critical.
	var sawBC, sawKU bool
	for _, ext := range cert.Extensions {
		if ext.Id.String() == "2.5.29.19" { // basicConstraints
			sawBC = true
			if !ext.Critical {
				t.Fatalf("expected basicConstraints critical")
			}
		}
		if ext.Id.String() == "2.5.29.15" { // keyUsage
			sawKU = true
			if !ext.Critical {
				t.Fatalf("expected keyUsage critical")
			}
		}
	}
	if !sawBC {
		t.Fatalf("expected basicConstraints extension")
	}
	if !sawKU {
		t.Fatalf("expected keyUsage extension")
	}

	days := cert.NotAfter.Sub(cert.NotBefore).Hours() / 24
	if days <= 3600 || days >= 3700 {
		t.Fatalf("expected validity ~10 years, got %f days", days)
	}

	pub, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok {
		t.Fatalf("expected rsa public key")
	}
	if pub.N.Cmp(ca.Key.N) != 0 {
		t.Fatalf("public/private key mismatch")
	}
}

func makeTempDir(t *testing.T, prefix string) string {
	t.Helper()
	dir, err := os.MkdirTemp("", prefix)
	if err != nil {
		t.Fatalf("mkdtemp: %v", err)
	}
	t.Cleanup(func() {
		_ = os.RemoveAll(dir)
	})
	return dir
}

func TestGetDefaultMitmCertDirRespectsXdgCacheHome(t *testing.T) {
	prev, had := os.LookupEnv("XDG_CACHE_HOME")
	t.Cleanup(func() {
		if !had {
			_ = os.Unsetenv("XDG_CACHE_HOME")
			return
		}
		_ = os.Setenv("XDG_CACHE_HOME", prev)
	})

	_ = os.Setenv("XDG_CACHE_HOME", "/tmp/gondolin-xdg-cache-test")
	got := GetDefaultMitmCertDir()
	want := filepath.Join("/tmp/gondolin-xdg-cache-test", "gondolin", "ssl")
	if got != want {
		t.Fatalf("expected %q, got %q", want, got)
	}
}

func TestResolveMitmCertDirUsesOverride(t *testing.T) {
	if ResolveMitmCertDir("/custom/dir") != "/custom/dir" {
		t.Fatalf("expected override")
	}
}

func TestLoadOrCreateMitmCaSyncCreatesAndPersists(t *testing.T) {
	dir := makeTempDir(t, "gondolin-mitm-")

	ca1, err := LoadOrCreateMitmCaSync(dir)
	if err != nil {
		t.Fatalf("LoadOrCreateMitmCaSync: %v", err)
	}
	assertLooksLikeMitmCa(t, ca1)

	keyPath := filepath.Join(dir, "ca.key")
	certPath := filepath.Join(dir, "ca.crt")

	if _, err := os.Stat(keyPath); err != nil {
		t.Fatalf("expected key file")
	}
	if _, err := os.Stat(certPath); err != nil {
		t.Fatalf("expected cert file")
	}

	keyBytes, _ := os.ReadFile(keyPath)
	certBytes, _ := os.ReadFile(certPath)
	if string(keyBytes) != ca1.KeyPEM {
		t.Fatalf("persisted key pem mismatch")
	}
	if string(certBytes) != ca1.CertPEM {
		t.Fatalf("persisted cert pem mismatch")
	}

	ca2, err := LoadOrCreateMitmCaSync(dir)
	if err != nil {
		t.Fatalf("LoadOrCreateMitmCaSync(2): %v", err)
	}
	if ca2.KeyPEM != ca1.KeyPEM || ca2.CertPEM != ca1.CertPEM {
		t.Fatalf("expected persisted CA to be reused")
	}
}

func TestLoadOrCreateMitmCaAsyncLoadsExistingGeneratedBySync(t *testing.T) {
	dir := makeTempDir(t, "gondolin-mitm-")

	syncCa, err := LoadOrCreateMitmCaSync(dir)
	if err != nil {
		t.Fatalf("sync: %v", err)
	}

	asyncCa, err := LoadOrCreateMitmCa(dir)
	if err != nil {
		t.Fatalf("async: %v", err)
	}

	if asyncCa.KeyPEM != syncCa.KeyPEM || asyncCa.CertPEM != syncCa.CertPEM {
		t.Fatalf("expected async load to reuse materials")
	}
}

func TestLoadOrCreateMitmCaRegeneratesWhenCorrupt(t *testing.T) {
	dir := makeTempDir(t, "gondolin-mitm-")
	_ = os.MkdirAll(dir, 0o755)
	_ = os.WriteFile(filepath.Join(dir, "ca.key"), []byte("not a key"), 0o600)
	// no cert

	ca, err := LoadOrCreateMitmCa(dir)
	if err != nil {
		t.Fatalf("LoadOrCreateMitmCa: %v", err)
	}
	assertLooksLikeMitmCa(t, ca)

	newKeyBytes, _ := os.ReadFile(filepath.Join(dir, "ca.key"))
	if string(newKeyBytes) == "not a key" {
		t.Fatalf("expected corrupt key to be overwritten")
	}

	// Ensure it is not immediately expiring due to clock skew.
	if time.Until(ca.Cert.NotAfter) < 9*365*24*time.Hour {
		t.Fatalf("unexpected notAfter")
	}
}
