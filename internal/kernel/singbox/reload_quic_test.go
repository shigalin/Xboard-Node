//go:build with_quic

package singbox

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/cedar2025/xboard-node/internal/config"
	"github.com/cedar2025/xboard-node/internal/kernel"
	"github.com/cedar2025/xboard-node/internal/model"
)

func selfSignedCert(t *testing.T) kernel.TLSCert {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "localhost"},
		DNSNames: []string{"localhost"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, _ := x509.MarshalECPrivateKey(key)
	return kernel.TLSCert{
		CertPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		KeyPEM:  pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}),
	}
}

func freeUDPPort(t *testing.T) int {
	t.Helper()
	c, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	return c.LocalAddr().(*net.UDPAddr).Port
}

// A panel route-only change must not recreate the inbound: for a QUIC
// inbound that would close the UDP socket carrying every session.
func TestRouteOnlyReloadKeepsQUICInbound(t *testing.T) {
	users := []model.UserSpec{{ID: 1, UUID: "11111111-1111-4111-8111-111111111111"}}
	s := New(config.KernelConfig{Type: "singbox", ConfigDir: t.TempDir(), LogLevel: "error", CustomConfigData: map[string]any{}})
	defer s.Stop()
	tc := selfSignedCert(t)
	for _, spec := range []*model.NodeSpec{
		{Protocol: "hysteria", Version: 1, ServerPort: freeUDPPort(t), UpMbps: 100, DownMbps: 100},
		{Protocol: "hysteria", Version: 2, ServerPort: freeUDPPort(t)},
		{Protocol: "tuic", ServerPort: freeUDPPort(t)},
	} {
		if err := s.Start(spec, users, tc); err != nil {
			t.Fatal(err)
		}
		tag := map[string]string{"hysteria": "hysteria-in", "tuic": "tuic-in"}[spec.Protocol]
		before := runningInbound(t, s, tag)
		changed := *spec
		changed.Routes = []model.RouteRule{{ID: 1, Match: []string{"domain:blocked.example"}, Action: "block"}}
		if err := s.Reload(&changed, users, tc); err != nil {
			t.Fatalf("%s: route-only reload failed: %v", spec.Protocol, err)
		}
		if runningInbound(t, s, tag) != before {
			t.Errorf("%s v%d: route-only panel change recreated the QUIC inbound (all sessions dropped)", spec.Protocol, spec.Version)
		}
	}
}

func TestHysteriaV1UserOperationsLeaveListenerRunning(t *testing.T) {
	users := []model.UserSpec{
		{ID: 1, UUID: "11111111-1111-4111-8111-111111111111"},
		{ID: 2, UUID: "22222222-2222-4222-8222-222222222222"},
	}
	added := model.UserSpec{ID: 3, UUID: "33333333-3333-4333-8333-333333333333"}
	s := New(config.KernelConfig{Type: "singbox", ConfigDir: t.TempDir(), LogLevel: "error"})
	defer s.Stop()
	spec := &model.NodeSpec{Protocol: "hysteria", Version: 1, ServerPort: freeUDPPort(t), UpMbps: 100, DownMbps: 100}
	cert := selfSignedCert(t)
	if err := s.Start(spec, users, cert); err != nil {
		t.Fatal(err)
	}
	before := runningInbound(t, s, "hysteria-in")
	if _, err := s.AddUsers([]model.UserSpec{added}); !errors.Is(err, errInboundUserUpdateUnsupported) {
		t.Fatalf("AddUsers returned %v, want explicit rebuild error", err)
	}
	if _, err := s.RemoveUsers(users); !errors.Is(err, errInboundUserUpdateUnsupported) {
		t.Fatalf("RemoveUsers returned %v, want explicit rebuild error", err)
	}
	if _, _, err := s.UpdateUsers([]model.UserSpec{added}); !errors.Is(err, errInboundUserUpdateUnsupported) {
		t.Fatalf("UpdateUsers returned %v, want explicit rebuild error", err)
	}
	if !s.IsRunning() || runningInbound(t, s, "hysteria-in") != before || len(s.users) != 2 || s.users[0].ID != 1 {
		t.Fatal("a refused user operation changed the running inbound or its users")
	}
	changed := *spec
	changed.Routes = []model.RouteRule{{ID: 1, Match: []string{"domain:blocked.example"}, Action: "block"}}
	if err := s.Reload(&changed, []model.UserSpec{users[1], users[0]}, cert); err != nil {
		t.Fatal(err)
	}
	if runningInbound(t, s, "hysteria-in") != before {
		t.Fatal("route reload with identical credentials in a different order rebound the QUIC listener")
	}
}
