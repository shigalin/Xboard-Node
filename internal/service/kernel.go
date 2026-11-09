package service

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/cedar2025/xboard-node/internal/config"
	"github.com/cedar2025/xboard-node/internal/kernel"
	"github.com/cedar2025/xboard-node/internal/kernel/singbox"
	"github.com/cedar2025/xboard-node/internal/kernel/xray"
	"github.com/cedar2025/xboard-node/internal/limiter"
	"github.com/cedar2025/xboard-node/internal/model"
	"github.com/cedar2025/xboard-node/internal/nlog"
)

// errKernelSwitchDeferred means a failed same-port switch is backing off.
var errKernelSwitchDeferred = errors.New("kernel switch is waiting before retrying")

// kernelSwitchRetryDelays grow because a same-port retry briefly stops the
// listener that is currently serving users.
var kernelSwitchRetryDelays = []time.Duration{time.Minute, 5 * time.Minute, 15 * time.Minute, time.Hour}

func newKernel(cfg config.KernelConfig, devices *limiter.DeviceManager) kernel.Kernel {
	switch cfg.Type {
	case "xray":
		return xray.NewWithDeviceManager(cfg, devices)
	case "singbox":
		return singbox.NewWithDeviceManager(cfg, devices)
	default:
		nlog.Core().Warn("unsupported kernel type, defaulting to sing-box", "type", cfg.Type)
		return singbox.NewWithDeviceManager(cfg, devices)
	}
}

// applyNodeConfig publishes a config only after the selected kernel accepts it.
func (s *Service) applyNodeConfig(ctx context.Context, spec *model.NodeSpec) error {
	if spec == nil {
		return fmt.Errorf("node spec is nil")
	}
	kcfg := s.cfg.Kernel
	if !s.cfg.IsStandalone() {
		kcfg.Type = model.ResolveKernelForNode(spec, kcfg.Type)
	}
	if spec.KernelLogLevel != "" {
		kcfg.LogLevel = spec.KernelLogLevel
	}
	next := s.kernel
	if kcfg.Type != s.kernelType {
		next = newKernel(kcfg, s.devices)
	}
	cfg := *s.cfg
	cfg.Kernel = kcfg
	if err := validateNodeRuntime(&cfg, next.Protocols(), spec, s.cert.TLSCert()); err != nil {
		return err
	}
	nextCert, certConfig, err := s.prepareNodeCertificate(ctx, spec)
	if err != nil {
		return err
	}
	defer func() {
		if nextCert != s.cert && nextCert != s.certReady {
			nextCert.Stop()
		}
	}()
	tls := nextCert.TLSCert()
	if requiresTLSCertificate(spec) && !tls.HasCert() {
		return errCertificateUnavailable
	}

	configHash := computeConfigHash(spec)
	unchanged := next == s.kernel && s.kernel.IsRunning() && sameKernelConfig(spec, s.appliedState.Config) &&
		bytes.Equal(tls.CertPEM, s.appliedState.TLS.CertPEM) &&
		bytes.Equal(tls.KeyPEM, s.appliedState.TLS.KeyPEM)
	if next != s.kernel {
		if err := s.switchKernel(ctx, next, kcfg.Type, spec, tls); err != nil {
			return err
		}
	} else if len(s.lastUsers) == 0 {
		s.kernel.Stop()
	} else if s.kernel.IsRunning() {
		if !unchanged {
			if err := s.kernel.Reload(spec, s.lastUsers, tls); err != nil {
				if err := s.kernel.Start(spec, s.lastUsers, tls); err != nil {
					return fmt.Errorf("reload kernel: %w", err)
				}
			}
		}
	} else if err := s.kernel.Start(spec, s.lastUsers, tls); err != nil {
		return fmt.Errorf("start kernel: %w", err)
	}

	s.commitCertificate(nextCert, certConfig)
	s.cfg.Kernel.LogLevel = kcfg.LogLevel
	if spec.CertConfig == nil {
		s.cfg.Cert.AutoTLS = spec.AutoTLS
		if spec.Domain != "" {
			s.cfg.Cert.Domain = spec.Domain
		}
	}
	s.metricsMu.Lock()
	s.lastConfig = spec
	s.metricsMu.Unlock()
	s.lastConfigHash = configHash
	s.appliedState.Config = spec
	if s.kernel.IsRunning() {
		if !unchanged {
			s.recordKernelStarted(spec, s.lastUsers, tls)
		}
	} else {
		s.appliedState.Users = nil
	}
	return nil
}

func sameKernelConfig(a, b *model.NodeSpec) bool {
	if a == nil || b == nil {
		return a == b
	}
	// The kernels consume the resolved PEM, not the panel's certificate policy.
	left, right := *a, *b
	left.CertConfig, right.CertConfig = nil, nil
	return computeConfigHash(&left) == computeConfigHash(&right)
}

func (s *Service) switchKernel(ctx context.Context, next kernel.Kernel, kind string, spec *model.NodeSpec, tls kernel.TLSCert) error {
	old := s.kernel
	previous := s.appliedState.Config
	handoff := old.IsRunning() && previous != nil && previous.ServerPort == spec.ServerPort
	configHash := computeConfigHash(spec)
	if handoff && configHash == s.kernelRetryHash && time.Now().Before(s.kernelRetryAt) {
		return errKernelSwitchDeferred
	}
	next.SetSpeedLimitFunc(s.speedTracker.GetLimiter)
	next.SetDeviceLimitFunc(s.limiter.GetDeviceLimitByUUID)
	if len(s.lastUsers) != 0 {
		if handoff {
			if checker, ok := next.(interface {
				CheckConfig(*model.NodeSpec, []model.UserSpec, kernel.TLSCert) error
			}); ok {
				if err := checker.CheckConfig(spec, s.lastUsers, tls); err != nil {
					return fmt.Errorf("check %s configuration: %w", kind, err)
				}
			}
			s.stopAndCollect(ctx, old)
		}
		if err := next.Start(spec, s.lastUsers, tls); err != nil {
			next.Stop()
			if previous != nil && !old.IsRunning() {
				if restoreErr := old.Start(previous, s.lastUsers, s.appliedState.TLS); restoreErr != nil {
					return fmt.Errorf("start %s: %w; restore %s: %w", kind, err, s.kernelType, restoreErr)
				}
			}
			if handoff {
				// Each attempt interrupts the restored listener, so back off.
				if configHash != s.kernelRetryHash {
					s.kernelRetryFailures = 0
				}
				delay := kernelSwitchRetryDelays[min(s.kernelRetryFailures, len(kernelSwitchRetryDelays)-1)]
				s.kernelRetryFailures++
				s.kernelRetryHash = configHash
				s.kernelRetryAt = time.Now().Add(delay)
				nlog.Core().Warn("kernel switch failed; previous kernel restored",
					"to", kind, "failures", s.kernelRetryFailures, "retry_after", delay)
			}
			return fmt.Errorf("start %s: %w", kind, err)
		}
	}
	if !handoff || len(s.lastUsers) == 0 {
		s.stopAndCollect(ctx, old)
	}
	s.tracker.ResetCounters()
	nlog.Core().Info("switched kernel", "from", s.kernelType, "to", kind,
		"protocol", spec.Protocol, "version", spec.Version, "transport", spec.Network)
	s.metricsMu.Lock()
	s.kernel = next
	s.metricsMu.Unlock()
	s.kernelType = kind
	s.kernelRetryHash = ""
	s.kernelRetryFailures = 0
	return nil
}

func (s *Service) stopAndCollect(ctx context.Context, old kernel.Kernel) {
	old.Stop()
	traffic, _, _, err := old.GetUserTraffic(ctx)
	if err != nil {
		nlog.Core().Warn("failed to collect final kernel traffic", "error", err)
	} else {
		s.tracker.Process(traffic, nil, 0)
	}
}
