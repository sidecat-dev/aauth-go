package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"time"

	"gitlab.com/sidecat-dev/aauth-go/jose"
)

func initializeHostPKI(stateDir, origin string) error {
	parsed, err := url.Parse(origin)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.Path != "" {
		return errors.New("host origin must be an HTTPS origin without a path")
	}
	now := time.Now().UTC()
	caPublic, caPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	caTemplate := &x509.Certificate{
		SerialNumber: hostedSerialNumber(), Subject: pkix.Name{CommonName: "AAuth hosted walkthrough CA"},
		NotBefore: now.Add(-time.Minute), NotAfter: now.Add(24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, caPublic, caPrivate)
	if err != nil {
		return err
	}
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		return err
	}
	if err := writeHostedPEM(filepath.Join(stateDir, "ca.pem"), 0o644, "CERTIFICATE", caDER); err != nil {
		return err
	}
	hosts := []string{parsed.Hostname(), hostedRoleHost(parsed.Hostname(), "person"), hostedRoleHost(parsed.Hostname(), "resource")}
	if err := createHostedLeaf(stateDir, hosts, ca, caPrivate, now); err != nil {
		return err
	}
	return createHostedSigningKey(stateDir, "provider")
}

func createHostedLeaf(stateDir string, hosts []string, ca *x509.Certificate, caKey ed25519.PrivateKey, now time.Time) error {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	template := &x509.Certificate{
		SerialNumber: hostedSerialNumber(), Subject: pkix.Name{CommonName: hosts[0]},
		NotBefore: now.Add(-time.Minute), NotAfter: now.Add(24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	for _, host := range hosts {
		if ip := net.ParseIP(host); ip != nil {
			template.IPAddresses = append(template.IPAddresses, ip)
		} else {
			template.DNSNames = append(template.DNSNames, host)
		}
	}
	certificate, err := x509.CreateCertificate(rand.Reader, template, ca, publicKey, caKey)
	if err != nil {
		return err
	}
	privateDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return err
	}
	if err := writeHostedPEM(filepath.Join(stateDir, "server-tls.pem"), 0o644, "CERTIFICATE", certificate); err != nil {
		return err
	}
	return writeHostedPEM(filepath.Join(stateDir, "server-tls.key"), 0o600, "PRIVATE KEY", privateDER)
}

func createHostedSigningKey(stateDir, name string) error {
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(stateDir, name+"-aauth.key"), privateKey, 0o600)
}

func loadHostedSigningKey(stateDir, name string) (jose.SigningKey, error) {
	encoded, err := os.ReadFile(filepath.Join(stateDir, name+"-aauth.key"))
	if err != nil {
		return jose.SigningKey{}, err
	}
	if len(encoded) != ed25519.PrivateKeySize {
		return jose.SigningKey{}, errors.New("stored AAuth private key has the wrong size")
	}
	return jose.NewEd25519SigningKey(name+"-key", ed25519.PrivateKey(encoded))
}

func randomSecret() (string, error) {
	buffer := make([]byte, 32)
	if _, err := rand.Read(buffer); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buffer), nil
}

func hostedSerialNumber() *big.Int {
	value, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	if err != nil {
		panic(err)
	}
	return value
}

func writeHostedPEM(path string, mode os.FileMode, kind string, data []byte) error {
	return os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: kind, Bytes: data}), mode)
}
