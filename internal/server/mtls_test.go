package server_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/kurtserdar/hsm-doctor/internal/agent"
	"github.com/kurtserdar/hsm-doctor/internal/server"
	"github.com/kurtserdar/hsm-doctor/internal/store"
)

// ca is a tiny in-memory certificate authority for the mTLS tests.
type ca struct {
	cert    *x509.Certificate
	key     *ecdsa.PrivateKey
	certPEM []byte
}

func newCA(t *testing.T) *ca {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "HSM Doctor Test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	return &ca{cert: cert, key: key, certPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})}
}

// issue signs a leaf certificate for the given common name and usage.
func (c *ca) issue(t *testing.T, cn string, server bool, ips ...net.IP) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	if server {
		tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		tmpl.IPAddresses = ips
		tmpl.DNSNames = []string{"localhost"}
	} else {
		tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, c.cert, &key.PublicKey, c.key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, _ := x509.MarshalPKCS8PrivateKey(key)
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	return pair
}

// writePEM writes a tls.Certificate's cert and key to files, returning paths.
func writePEM(t *testing.T, dir, name string, cert tls.Certificate) (certPath, keyPath string) {
	t.Helper()
	certPath = filepath.Join(dir, name+".crt")
	keyPath = filepath.Join(dir, name+".key")
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Certificate[0]})
	keyDER, _ := x509.MarshalPKCS8PrivateKey(cert.PrivateKey)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	if err := os.WriteFile(certPath, certPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	return certPath, keyPath
}

// startMTLSServer boots a central server requiring client certs from the CA
// and returns its base URL.
func startMTLSServer(t *testing.T, serverCA *ca) string {
	t.Helper()
	dir := t.TempDir()
	srvCert := serverCA.issue(t, "localhost", true, net.ParseIP("127.0.0.1"))
	certPath, keyPath := writePEM(t, dir, "server", srvCert)
	caPath := filepath.Join(dir, "ca.crt")
	if err := os.WriteFile(caPath, serverCA.certPEM, 0o600); err != nil {
		t.Fatal(err)
	}

	st, err := store.Open(filepath.Join(dir, "mtls.db"))
	if err != nil {
		t.Fatal(err)
	}
	srv := server.NewCentral("test", st, "enroll-secret")
	t.Cleanup(srv.Close)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()

	go func() {
		_ = srv.ListenAndServe(addr, server.TLSOptions{
			CertFile: certPath, KeyFile: keyPath, ClientCAFile: caPath,
		})
	}()
	waitForTLS(t, addr)
	return "https://" + addr
}

func waitForTLS(t *testing.T, addr string) {
	t.Helper()
	for i := 0; i < 100; i++ {
		c, err := net.DialTimeout("tcp", addr, 200*time.Millisecond)
		if err == nil {
			_ = c.Close()
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("server at %s did not come up", addr)
}

func TestMTLSRequiresTrustedClientCert(t *testing.T) {
	serverCA := newCA(t)
	url := startMTLSServer(t, serverCA)

	caPool := x509.NewCertPool()
	caPool.AppendCertsFromPEM(serverCA.certPEM)

	// 1. No client certificate → rejected at the TLS layer.
	noCert := &http.Client{Timeout: 3 * time.Second, Transport: &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: caPool},
	}}
	if _, err := noCert.Get(url + "/api/v1/info"); err == nil {
		t.Error("connection without a client certificate must be rejected")
	}

	// 2. Certificate from an untrusted CA → rejected.
	otherCA := newCA(t)
	badCert := otherCA.issue(t, "intruder", false)
	untrusted := &http.Client{Timeout: 3 * time.Second, Transport: &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: caPool, Certificates: []tls.Certificate{badCert}},
	}}
	if _, err := untrusted.Get(url + "/api/v1/info"); err == nil {
		t.Error("client cert from an untrusted CA must be rejected")
	}

	// 3. Certificate signed by the trusted CA → accepted.
	goodCert := serverCA.issue(t, "edge-01", false)
	trusted := &http.Client{Timeout: 3 * time.Second, Transport: &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: caPool, Certificates: []tls.Certificate{goodCert}},
	}}
	resp, err := trusted.Get(url + "/api/v1/info")
	if err != nil {
		t.Fatalf("trusted client cert should be accepted: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("info endpoint: want 200, got %d", resp.StatusCode)
	}
}

// TestAgentEnrollsOverMTLS proves the agent's TLS options work end to end:
// an agent built with a client cert and the server CA can enroll against an
// mTLS server.
func TestAgentEnrollsOverMTLS(t *testing.T) {
	serverCA := newCA(t)
	dir := t.TempDir()

	// Write the agent's client cert/key and the server CA to files, as the
	// CLI flags expect.
	clientCert := serverCA.issue(t, "edge-01", false)
	certPath, keyPath := writePEM(t, dir, "agent", clientCert)
	caPath := filepath.Join(dir, "server-ca.crt")
	if err := os.WriteFile(caPath, serverCA.certPEM, 0o600); err != nil {
		t.Fatal(err)
	}

	url := startMTLSServer(t, serverCA)

	httpc, err := agent.NewHTTPClient(agent.TLSOptions{
		ClientCertFile: certPath, ClientKeyFile: keyPath, ServerCAFile: caPath,
	})
	if err != nil {
		t.Fatalf("NewHTTPClient: %v", err)
	}
	token, err := agent.Enroll(httpc, url, "edge-01", "enroll-secret")
	if err != nil {
		t.Fatalf("enroll over mTLS: %v", err)
	}
	if token == "" {
		t.Error("expected a non-empty agent token")
	}

	// A client without a certificate must fail to enroll against the same
	// server, confirming mTLS is actually enforced.
	plain, _ := agent.NewHTTPClient(agent.TLSOptions{ServerCAFile: caPath})
	if _, err := agent.Enroll(plain, url, "edge-02", "enroll-secret"); err == nil {
		t.Error("enrollment without a client certificate must fail under mTLS")
	}
}

func TestClientCARequiresServerTLS(t *testing.T) {
	srv := server.NewCentral("test", nil, "")
	err := srv.ListenAndServe("127.0.0.1:0", server.TLSOptions{ClientCAFile: "/some/ca.pem"})
	if err == nil {
		t.Error("--client-ca without --tls-cert/--tls-key must error")
	}
}
