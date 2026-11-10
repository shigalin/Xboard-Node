package service

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"time"

	"github.com/cedar2025/xboard-node/internal/cert"
	"github.com/cedar2025/xboard-node/internal/config"
	"github.com/cedar2025/xboard-node/internal/model"
	"github.com/cedar2025/xboard-node/internal/nlog"
)

var errCertificateUnavailable = errors.New("certificate unavailable")

const acmeRetryInterval = 15 * time.Minute

type certificateResult struct {
	config  config.CertConfig
	manager *cert.Manager
	err     error
}

// refreshActiveCertificate uses the already applied config and the active
// manager's renewed PEM. It leaves any candidate config and ACME job alone.
func (s *Service) refreshActiveCertificate() {
	spec := s.appliedState.Config
	if spec == nil || !requiresTLSCertificate(spec) || !s.kernel.IsRunning() {
		return
	}
	tls := s.cert.TLSCert()
	if !tls.HasCert() || (bytes.Equal(tls.CertPEM, s.appliedState.TLS.CertPEM) &&
		bytes.Equal(tls.KeyPEM, s.appliedState.TLS.KeyPEM)) {
		return
	}
	if err := s.reloadRunningKernel(spec, tls, s.appliedState.CustomConfig, &s.certRenewRetry); err != nil {
		if !errors.Is(err, errKernelSwitchDeferred) {
			nlog.Core().Warn("failed to apply renewed certificate", "error", err)
		}
		return
	}
	s.appliedState.TLS = tls
	s.certRenewRetry = rebuildBackoff{}
}

func (s *Service) setCertificateTarget(target *config.CertConfig) {
	if reflect.DeepEqual(s.certTarget, target) {
		return
	}
	if s.certReady != nil {
		s.certReady.Stop()
		s.certReady = nil
	}
	s.certTarget = target
	s.certRetryAt = time.Time{}
}

func (s *Service) prepareNodeCertificate(ctx context.Context, spec *model.NodeSpec) (*cert.Manager, *config.CertConfig, error) {
	cfg := spec.CertConfig
	if cfg == nil {
		s.setCertificateTarget(nil)
		return s.cert, nil, nil
	}
	mode := strings.ToLower(strings.TrimSpace(cfg.CertMode))
	incomplete := (mode == "content" && (cfg.CertContent == "" || cfg.KeyContent == "")) ||
		(mode == "file" && (cfg.CertFile == "" || cfg.KeyFile == ""))
	if mode == "none" || (incomplete && s.cert.HasCert()) {
		s.setCertificateTarget(nil)
		return s.cert, nil, nil
	}

	candidate := *cfg
	candidate.CertDir = s.cfg.Cert.CertDir
	if err := validateRuntimeCertConfig(spec); err != nil {
		s.setCertificateTarget(nil)
		nlog.Core().Warn("optional certificate configuration rejected", "error", err)
		return s.cert, nil, nil
	}
	if cert.UsesACME(candidate) && !s.cert.ReusesACME(candidate) {
		s.setCertificateTarget(&candidate)
		if s.certReady != nil {
			return s.certReady, &candidate, nil
		}
		if !s.certInFlight && !time.Now().Before(s.certRetryAt) {
			s.certInFlight = true
			go s.prepareACME(ctx, candidate)
		}
		if requiresTLSCertificate(spec) {
			return nil, nil, errCertificateUnavailable
		}
		return s.cert, nil, nil
	}

	s.setCertificateTarget(nil)
	next, err := s.cert.Prepare(ctx, candidate)
	if err == nil && !next.HasCert() {
		// Empty panel overrides cannot replace the active certificate.
		if next != s.cert {
			next.Stop()
		}
		return s.cert, nil, nil
	}
	if err != nil {
		if requiresTLSCertificate(spec) {
			return nil, nil, fmt.Errorf("%w: %v", errCertificateUnavailable, err)
		}
		nlog.Core().Warn("optional certificate preparation failed; keeping current certificate", "error", err)
		return s.cert, nil, nil
	}
	return next, &candidate, nil
}

func (s *Service) prepareACME(ctx context.Context, cfg config.CertConfig) {
	next := cert.NewCandidate(cfg)
	err := next.Start(ctx)
	select {
	case s.certResults <- certificateResult{config: cfg, manager: next, err: err}:
	case <-ctx.Done():
		next.Stop()
	}
}

func (s *Service) handleCertificateResult(ctx context.Context, result certificateResult) {
	s.certInFlight = false
	spec := s.pendingConfig
	if spec == nil {
		spec = s.lastConfig
	}
	if s.certTarget == nil || !reflect.DeepEqual(*s.certTarget, result.config) {
		result.manager.Stop()
		if s.certTarget != nil && spec != nil {
			s.applyConfigUpdate(ctx, spec)
		}
		return
	}
	if result.err != nil {
		result.manager.Stop()
		s.certRetryAt = time.Now().Add(acmeRetryInterval)
		nlog.Core().Warn("ACME certificate preparation failed", "retry_after", s.certRetryAt, "error", result.err)
		return
	}
	s.certReady = result.manager
	if spec != nil {
		s.applyConfigUpdate(ctx, spec)
	}
}

func (s *Service) commitCertificate(next *cert.Manager, cfg *config.CertConfig) {
	if next != s.cert {
		s.cert.Stop()
		next.Commit()
		s.cert = next
	}
	if next == s.certReady {
		s.certReady = nil
		s.certTarget = nil
	}
	if cfg != nil {
		s.cfg.Cert = *cfg
	}
}
