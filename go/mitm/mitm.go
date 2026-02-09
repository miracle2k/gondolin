package mitm

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"time"
)

type MitmCa struct {
	Key     *rsa.PrivateKey
	Cert    *x509.Certificate
	KeyPEM  string
	CertPEM string
}

func GetDefaultMitmCertDir() string {
	cacheBase := os.Getenv("XDG_CACHE_HOME")
	if cacheBase == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			// Fall back to a relative .cache if home is unavailable.
			cacheBase = ".cache"
		} else {
			cacheBase = filepath.Join(home, ".cache")
		}
	}
	return filepath.Join(cacheBase, "gondolin", "ssl")
}

func ResolveMitmCertDir(override string) string {
	if override != "" {
		return override
	}
	return GetDefaultMitmCertDir()
}

func LoadOrCreateMitmCa(dir string) (*MitmCa, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	keyPath := filepath.Join(dir, "ca.key")
	certPath := filepath.Join(dir, "ca.crt")

	keyPemBytes, keyErr := os.ReadFile(keyPath)
	certPemBytes, certErr := os.ReadFile(certPath)
	if keyErr == nil && certErr == nil {
		loaded, err := parseCa(string(keyPemBytes), string(certPemBytes))
		if err == nil {
			return loaded, nil
		}
	}

	generated, err := generateMitmCa()
	if err != nil {
		return nil, err
	}
	// Best-effort persistence.
	_ = os.WriteFile(keyPath, []byte(generated.KeyPEM), 0o600)
	_ = os.WriteFile(certPath, []byte(generated.CertPEM), 0o644)
	return generated, nil
}

func LoadOrCreateMitmCaSync(dir string) (*MitmCa, error) {
	return LoadOrCreateMitmCa(dir)
}

func parseCa(keyPem, certPem string) (*MitmCa, error) {
	keyBlock, _ := pem.Decode([]byte(keyPem))
	if keyBlock == nil {
		return nil, errors.New("invalid key pem")
	}
	var key *rsa.PrivateKey
	if keyBlock.Type == "RSA PRIVATE KEY" {
		parsed, err := x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
		if err != nil {
			return nil, err
		}
		key = parsed
	} else if keyBlock.Type == "PRIVATE KEY" {
		parsed, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
		if err != nil {
			return nil, err
		}
		rsaKey, ok := parsed.(*rsa.PrivateKey)
		if !ok {
			return nil, errors.New("not an rsa key")
		}
		key = rsaKey
	} else {
		return nil, errors.New("unsupported key type")
	}

	certBlock, _ := pem.Decode([]byte(certPem))
	if certBlock == nil || certBlock.Type != "CERTIFICATE" {
		return nil, errors.New("invalid cert pem")
	}
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, err
	}

	return &MitmCa{Key: key, Cert: cert, KeyPEM: keyPem, CertPEM: certPem}, nil
}

func generateMitmCa() (*MitmCa, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		return nil, err
	}

	notBefore := time.Now().Add(-5 * time.Minute)
	notAfter := notBefore.Add(3650 * 24 * time.Hour)

	tpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName: "gondolin-mitm-ca",
		},
		Issuer: pkix.Name{
			CommonName: "gondolin-mitm-ca",
		},
		NotBefore: notBefore,
		NotAfter:  notAfter,

		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		// Mark constraints and key usage as critical via Extensions in Go: BasicConstraints is
		// encoded as critical by default when IsCA is set; KeyUsage is also critical.
	}

	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}

	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}

	keyPem := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	certPem := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})

	return &MitmCa{Key: key, Cert: cert, KeyPEM: string(keyPem), CertPEM: string(certPem)}, nil
}
