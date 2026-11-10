package cert

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/caddyserver/certmagic"

	"github.com/cedar2025/xboard-node/internal/config"
)

// generateSelfSignedPair returns a fresh self-signed certificate and matching
// private key in PEM form, suitable for storing as a libdns/certmagic site
// resource in tests.
func generateSelfSignedPair(t *testing.T, domain string) (certPEM, keyPEM []byte) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: domain},
		DNSNames:     []string{domain},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return
}

// TestLoadPEMFromStorage_RestartScenario simulates the warm-restart bug fix:
// certmagic.ObtainCertSync returns nil without firing cert_obtained when a
// valid cert already exists in storage. The manager must still populate its
// in-memory PEM cache by reading storage explicitly.
func TestLoadPEMFromStorage_RestartScenario(t *testing.T) {
	dir := t.TempDir()
	storage := &certmagic.FileStorage{Path: dir}
	const domain = "example.test"
	const issuerKey = "test-issuer"

	certPEM, keyPEM := generateSelfSignedPair(t, domain)

	ctx := context.Background()
	if err := storage.Store(ctx, certmagic.StorageKeys.SiteCert(issuerKey, domain), certPEM); err != nil {
		t.Fatalf("seed cert: %v", err)
	}
	if err := storage.Store(ctx, certmagic.StorageKeys.SitePrivateKey(issuerKey, domain), keyPEM); err != nil {
		t.Fatalf("seed key: %v", err)
	}

	m := NewManager(config.CertConfig{})
	if m.HasCert() {
		t.Fatal("manager should start with no cert in memory")
	}

	if err := m.loadPEMFromStorage(ctx, storage, issuerKey, domain); err != nil {
		t.Fatalf("loadPEMFromStorage: %v", err)
	}
	if !m.HasCert() {
		t.Fatal("expected HasCert() == true after explicit load")
	}
	got := m.TLSCert()
	if string(got.CertPEM) != string(certPEM) {
		t.Errorf("certPEM mismatch")
	}
	if string(got.KeyPEM) != string(keyPEM) {
		t.Errorf("keyPEM mismatch")
	}
}

// TestLoadPEMFromStorage_RenewalRefresh confirms that calling load a second
// time with newer bytes on disk swaps the in-memory cache atomically — this
// is the renewal hot-reload path triggered from the cert_obtained event.
func TestLoadPEMFromStorage_RenewalRefresh(t *testing.T) {
	dir := t.TempDir()
	storage := &certmagic.FileStorage{Path: dir}
	const domain = "example.test"
	const issuerKey = "test-issuer"
	ctx := context.Background()

	certV1, keyV1 := generateSelfSignedPair(t, domain)
	if err := storage.Store(ctx, certmagic.StorageKeys.SiteCert(issuerKey, domain), certV1); err != nil {
		t.Fatalf("seed v1 cert: %v", err)
	}
	if err := storage.Store(ctx, certmagic.StorageKeys.SitePrivateKey(issuerKey, domain), keyV1); err != nil {
		t.Fatalf("seed v1 key: %v", err)
	}

	m := NewManager(config.CertConfig{})
	if err := m.loadPEMFromStorage(ctx, storage, issuerKey, domain); err != nil {
		t.Fatalf("initial load: %v", err)
	}

	certV2, keyV2 := generateSelfSignedPair(t, domain)
	if err := storage.Store(ctx, certmagic.StorageKeys.SiteCert(issuerKey, domain), certV2); err != nil {
		t.Fatalf("seed v2 cert: %v", err)
	}
	if err := storage.Store(ctx, certmagic.StorageKeys.SitePrivateKey(issuerKey, domain), keyV2); err != nil {
		t.Fatalf("seed v2 key: %v", err)
	}

	if err := m.loadPEMFromStorage(ctx, storage, issuerKey, domain); err != nil {
		t.Fatalf("refresh load: %v", err)
	}
	got := m.TLSCert()
	if string(got.CertPEM) != string(certV2) {
		t.Error("expected v2 cert after refresh")
	}
	if string(got.KeyPEM) != string(keyV2) {
		t.Error("expected v2 key after refresh")
	}
}

// TestLoadPEMFromStorage_MissingFiles ensures we surface a clear error when
// storage doesn't have the expected keys (defensive — should not happen in
// practice because ObtainCertSync guarantees presence on success).
func TestLoadPEMFromStorage_MissingFiles(t *testing.T) {
	dir := t.TempDir()
	storage := &certmagic.FileStorage{Path: dir}
	m := NewManager(config.CertConfig{})
	err := m.loadPEMFromStorage(context.Background(), storage, "test-issuer", "example.test")
	if err == nil {
		t.Fatal("expected error when storage is empty")
	}
}

// TestLoadPEMFromStorage_RejectsMismatchedPair guards against silently loading
// a cert and key that do not pair (e.g. partial write or external tampering).
func TestLoadPEMFromStorage_RejectsMismatchedPair(t *testing.T) {
	dir := t.TempDir()
	storage := &certmagic.FileStorage{Path: dir}
	const domain = "example.test"
	const issuerKey = "test-issuer"
	ctx := context.Background()

	certA, _ := generateSelfSignedPair(t, domain)
	_, keyB := generateSelfSignedPair(t, domain)
	if err := storage.Store(ctx, certmagic.StorageKeys.SiteCert(issuerKey, domain), certA); err != nil {
		t.Fatalf("seed cert: %v", err)
	}
	if err := storage.Store(ctx, certmagic.StorageKeys.SitePrivateKey(issuerKey, domain), keyB); err != nil {
		t.Fatalf("seed key: %v", err)
	}

	m := NewManager(config.CertConfig{})
	err := m.loadPEMFromStorage(ctx, storage, issuerKey, domain)
	if err == nil {
		t.Fatal("expected error for mismatched cert/key pair")
	}
	if m.HasCert() {
		t.Error("manager should not store invalid pair")
	}
	_ = filepath.Join(dir, "stub")
}

// TestACMEFingerprint covers the config-equality logic that decides whether
// Prepare can retain a running certmagic instance.
func TestACMEFingerprint(t *testing.T) {
	base := config.CertConfig{
		CertMode:    "dns",
		Domain:      "a.example.com",
		Email:       "ops@example.com",
		DNSProvider: "cloudflare",
		DNSEnv:      map[string]string{"CLOUDFLARE_API_TOKEN": "tok"},
	}

	cases := []struct {
		name    string
		mutate  func(*config.CertConfig)
		differs bool
	}{
		{"same", func(*config.CertConfig) {}, false},
		{"domain", func(c *config.CertConfig) { c.Domain = "b.example.com" }, true},
		{"mode", func(c *config.CertConfig) { c.CertMode = "http" }, true},
		{"email", func(c *config.CertConfig) { c.Email = "other@example.com" }, true},
		{"provider", func(c *config.CertConfig) { c.DNSProvider = "alidns" }, true},
		{"env_value", func(c *config.CertConfig) { c.DNSEnv = map[string]string{"CLOUDFLARE_API_TOKEN": "other"} }, true},
		{"env_key_only", func(c *config.CertConfig) { c.DNSEnv = map[string]string{"OTHER": "tok"} }, true},
	}

	baseFp := acmeFingerprint(base)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := base
			if tc.mutate != nil {
				// deep-copy DNSEnv before mutation to avoid sharing
				cfg.DNSEnv = map[string]string{}
				for k, v := range base.DNSEnv {
					cfg.DNSEnv[k] = v
				}
				tc.mutate(&cfg)
			}
			got := acmeFingerprint(cfg)
			if (got != baseFp) != tc.differs {
				t.Errorf("differs=%v but got==base=%v", tc.differs, got == baseFp)
			}
		})
	}
}

// TestACMEFingerprintEnvOrderStable ensures map iteration order does not
// affect the fingerprint (must be sorted internally).
func TestACMEFingerprintEnvOrderStable(t *testing.T) {
	a := config.CertConfig{
		CertMode: "dns", Domain: "x", DNSProvider: "p",
		DNSEnv: map[string]string{"A": "1", "B": "2", "C": "3"},
	}
	b := config.CertConfig{
		CertMode: "dns", Domain: "x", DNSProvider: "p",
		DNSEnv: map[string]string{"C": "3", "A": "1", "B": "2"},
	}
	if acmeFingerprint(a) != acmeFingerprint(b) {
		t.Fatal("fingerprint not order-independent")
	}
}

func TestPrepareCertificatePreservesActiveManager(t *testing.T) {
	ctx := context.Background()
	currentCert, currentKey := generateSelfSignedPair(t, "current.example.com")
	cfg := config.CertConfig{CertMode: "content", CertContent: string(currentCert), KeyContent: string(currentKey), CertDir: t.TempDir()}
	active := NewManager(cfg)
	if err := active.Start(ctx); err != nil {
		t.Fatal(err)
	}
	// A failed replacement must not cancel an existing renewal worker either.
	renewalCtx, cancel := context.WithCancel(ctx)
	active.acmeCancel = cancel
	active.acmeStarted = true
	defer active.Stop()
	for _, invalid := range []config.CertConfig{
		{CertMode: "file", CertFile: filepath.Join(t.TempDir(), "missing.pem"), KeyFile: "missing.key"},
		{CertMode: "content", CertContent: "invalid certificate", KeyContent: "invalid key"},
	} {
		if next, err := active.Prepare(ctx, invalid); err == nil || next != nil {
			t.Fatal("invalid certificate was accepted")
		}
		if renewalCtx.Err() != nil || !active.acmeStarted || active.cfg.CertMode != cfg.CertMode {
			t.Fatal("failed preparation changed the active manager")
		}
		if got := active.TLSCert(); string(got.CertPEM) != string(currentCert) || string(got.KeyPEM) != string(currentKey) {
			t.Fatal("failed preparation changed active certificate material")
		}
	}
	nextCert, nextKey := generateSelfSignedPair(t, "next.example.com")
	next, err := active.Prepare(ctx, config.CertConfig{CertMode: "content", CertContent: string(nextCert), KeyContent: string(nextKey)})
	if err != nil {
		t.Fatal(err)
	}
	defer next.Stop()
	if next == active || renewalCtx.Err() != nil || string(active.TLSCert().CertPEM) != string(currentCert) || string(next.TLSCert().CertPEM) != string(nextCert) {
		t.Fatal("preparation must leave acceptance and old-manager shutdown to the caller")
	}
	path := filepath.Join(cfg.CertDir, "cert.pem")
	if disk, err := os.ReadFile(path); err != nil || string(disk) != string(currentCert) {
		t.Fatalf("candidate replaced the active PEM before acceptance: %v", err)
	}
	active.Stop()
	active.Stop()
	next.Commit()
	if disk, err := os.ReadFile(path); err != nil || string(disk) != string(nextCert) {
		t.Fatalf("accepted PEM was not persisted: %v", err)
	}
	if renewalCtx.Err() == nil || !next.HasCert() {
		t.Fatal("retiring the old manager did not preserve the prepared replacement")
	}
}

func TestSelfSignedPersistedCertificateMatchesDomain(t *testing.T) {
	for _, tc := range []struct {
		name, firstDomain, nextDomain, firstIdentity string
	}{
		{"dns", "old.example.test", "new.example.test", "old.example.test"},
		{"ip", "127.0.0.1", "127.0.0.2", "127.0.0.1"},
		{"default", "", "new.example.test", "localhost"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := config.CertConfig{CertMode: "self", Domain: tc.firstDomain, CertDir: t.TempDir()}
			first := NewManager(cfg)
			if err := first.Start(context.Background()); err != nil {
				t.Fatal(err)
			}
			original := first.TLSCert()

			restarted := NewManager(cfg)
			if err := restarted.Start(context.Background()); err != nil {
				t.Fatal(err)
			}
			if got := restarted.TLSCert(); !bytes.Equal(got.CertPEM, original.CertPEM) || !bytes.Equal(got.KeyPEM, original.KeyPEM) {
				t.Fatal("same-domain restart should reuse persisted certificate")
			}

			cfg.Domain = tc.nextDomain
			changed := NewManager(cfg)
			if err := changed.Start(context.Background()); err != nil {
				t.Fatal(err)
			}
			got := changed.TLSCert()
			pair, err := tls.X509KeyPair(got.CertPEM, got.KeyPEM)
			if err != nil {
				t.Fatal(err)
			}
			leaf, err := x509.ParseCertificate(pair.Certificate[0])
			if err != nil {
				t.Fatal(err)
			}
			if err := leaf.VerifyHostname(tc.nextDomain); err != nil {
				t.Fatalf("certificate does not cover changed domain %q: %v", tc.nextDomain, err)
			}
			if err := leaf.VerifyHostname(tc.firstIdentity); err == nil {
				t.Fatalf("certificate still covers previous domain %q", tc.firstIdentity)
			}
			if bytes.Equal(got.CertPEM, original.CertPEM) {
				t.Fatal("changed domain should generate a new certificate")
			}
			if disk, err := os.ReadFile(filepath.Join(cfg.CertDir, "cert.pem")); err != nil || !bytes.Equal(disk, got.CertPEM) {
				t.Fatalf("new certificate was not persisted: %v", err)
			}
		})
	}
}

func TestContentPersistedCertificateIgnoresConfigDomain(t *testing.T) {
	certPEM, keyPEM := generateSelfSignedPair(t, "cert.example.test")
	cfg := config.CertConfig{CertMode: "content", Domain: "other.example.test", CertDir: t.TempDir(), CertContent: string(certPEM), KeyContent: string(keyPEM)}
	if err := NewManager(cfg).Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	cfg.CertContent, cfg.KeyContent = "", ""
	restarted := NewManager(cfg)
	if err := restarted.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := restarted.TLSCert(); !bytes.Equal(got.CertPEM, certPEM) || !bytes.Equal(got.KeyPEM, keyPEM) {
		t.Fatal("content mode should reuse persisted PEM regardless of config domain")
	}
}

func TestPrepareUnchangedACMEKeepsRenewalWorker(t *testing.T) {
	cfg := config.CertConfig{CertMode: "http", Domain: "example.com", CertDir: t.TempDir()}
	active := NewManager(cfg)
	active.acmeStarted = true
	active.acmeFingerprint = acmeFingerprint(cfg)
	ctx, cancel := context.WithCancel(context.Background())
	active.acmeCancel = cancel
	defer active.Stop()
	next, err := active.Prepare(context.Background(), cfg)
	if err != nil || next != active || ctx.Err() != nil {
		t.Fatal("unchanged ACME config replaced its renewal worker")
	}
}
