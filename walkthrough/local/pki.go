package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"time"

	"gitlab.com/sidecat-dev/aauth-go/jose"
)

func initializePKI(stateDir string) error {
	now := time.Now().UTC()
	caPublic, caPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	caTemplate := &x509.Certificate{
		SerialNumber: serialNumber(),
		Subject:      pkix.Name{CommonName: "AAuth local walkthrough CA"},
		NotBefore:    now.Add(-time.Minute), NotAfter: now.Add(24 * time.Hour),
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
	if err := writePEM(filepath.Join(stateDir, "ca.pem"), 0o644, "CERTIFICATE", caDER); err != nil {
		return err
	}
	if err := createLeaf(stateDir, "agent", []string{"agent.local"}, ca, caPrivate, now); err != nil {
		return err
	}
	if err := createLeaf(stateDir, "service", []string{"person.local", "resource.local"}, ca, caPrivate, now); err != nil {
		return err
	}
	for _, name := range []string{"agent", "person", "resource"} {
		_, privateKey, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(stateDir, name+"-aauth.key"), privateKey, 0o600); err != nil {
			return err
		}
	}
	return nil
}

func createLeaf(stateDir, name string, hosts []string, ca *x509.Certificate, caKey ed25519.PrivateKey, now time.Time) error {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	template := &x509.Certificate{
		SerialNumber: serialNumber(), Subject: pkix.Name{CommonName: hosts[0]}, DNSNames: hosts,
		NotBefore: now.Add(-time.Minute), NotAfter: now.Add(24 * time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	certificate, err := x509.CreateCertificate(rand.Reader, template, ca, publicKey, caKey)
	if err != nil {
		return err
	}
	privateDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return err
	}
	if err := writePEM(filepath.Join(stateDir, name+"-tls.pem"), 0o644, "CERTIFICATE", certificate); err != nil {
		return err
	}
	return writePEM(filepath.Join(stateDir, name+"-tls.key"), 0o600, "PRIVATE KEY", privateDER)
}

func serialNumber() *big.Int {
	value, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	if err != nil {
		panic(err)
	}
	return value
}

func writePEM(path string, mode os.FileMode, kind string, data []byte) error {
	return os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: kind, Bytes: data}), mode)
}

func loadSigningKey(stateDir, name string) (jose.SigningKey, error) {
	encoded, err := os.ReadFile(filepath.Join(stateDir, name+"-aauth.key"))
	if err != nil {
		return jose.SigningKey{}, err
	}
	if len(encoded) != ed25519.PrivateKeySize {
		return jose.SigningKey{}, errors.New("stored AAuth private key has the wrong size")
	}
	return jose.NewEd25519SigningKey(name+"-key", ed25519.PrivateKey(encoded))
}
