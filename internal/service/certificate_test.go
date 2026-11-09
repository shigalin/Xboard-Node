package service

import (
	"context"
	"testing"
	"testing/synctest"
	"time"

	"github.com/cedar2025/xboard-node/internal/config"
	"github.com/cedar2025/xboard-node/internal/model"
)

func TestOptionalACMEFailureDoesNotBlockConfigAndRetriesAfterCooldown(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		cfg := &config.Config{Kernel: config.KernelConfig{Type: "singbox"}}
		s := NewWithControlPlane(cfg, &kernelTestControlPlane{})
		spec := &model.NodeSpec{Protocol: "vless", CertConfig: &config.CertConfig{CertMode: "http"}}
		// No domain, so this fails before contacting the ACME CA.
		s.applyConfigUpdate(ctx, spec)
		if s.lastConfig != spec || s.pendingConfig != nil || !s.certInFlight {
			t.Fatal("optional ACME preparation blocked config acceptance")
		}
		readFailure := func() {
			synctest.Wait()
			select {
			case result := <-s.certResults:
				if result.err == nil {
					t.Fatal("expected ACME preparation to fail")
				}
				s.handleCertificateResult(ctx, result)
			default:
				t.Fatal("expected an asynchronous ACME result")
			}
		}
		readFailure()
		time.Sleep(acmeRetryInterval - time.Second)
		s.applyPullResult(ctx, pullResult{})
		if s.certInFlight {
			t.Fatal("poll retried ACME before the backoff expired")
		}
		time.Sleep(time.Second)
		s.applyPullResult(ctx, pullResult{})
		readFailure()
		updated := *spec
		updated.CertConfig = &config.CertConfig{CertMode: "http", HTTPPort: 18080}
		s.applyConfigUpdate(ctx, &updated)
		if !s.certInFlight {
			t.Fatal("backoff for the old ACME settings blocked a new configuration")
		}
		readFailure()
	})
}
