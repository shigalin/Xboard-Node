package service

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
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
	// Load custom_config as it is now, validated for the kernel that will run
	// this config, and hand the content to that kernel. The kernel never reads
	// the file itself, so a restart or rollback reuses the validated snapshot.
	customConfig, err := model.LoadCustomConfigForKernel(kcfg.CustomConfig, kcfg.Type)
	if err != nil {
		return err
	}
	kcfg.CustomConfigData = customConfig
	if err := model.ValidateNodeSpec(spec, kcfg); err != nil {
		return err
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
		bytes.Equal(tls.KeyPEM, s.appliedState.TLS.KeyPEM) &&
		sameCustomConfig(customConfig, s.appliedState.CustomConfig)
	if next != s.kernel {
		if err := s.switchKernel(ctx, next, kcfg.Type, spec, tls); err != nil {
			return err
		}
	} else if len(s.lastUsers) == 0 {
		s.kernel.Stop()
	} else if s.kernel.IsRunning() {
		if !unchanged {
			// While an earlier attempt for this exact config is backing off, do
			// not touch the running listener at all.
			if s.rebuildDeferred(rebuildKey(spec, customConfig, tls)) {
				return errKernelSwitchDeferred
			}
			reloaded := false
			if s.appliedState.Config != nil && spec.ServerPort == s.appliedState.Config.ServerPort &&
				sameCustomConfig(customConfig, s.appliedState.CustomConfig) {
				// Hot reload only covers listener-level changes; kernels report
				// anything wider as an error and the config is rebuilt instead.
				// Port moves go straight to a rebuild so the new port can be
				// opened before the serving listener is released.
				if err := s.kernel.Reload(spec, s.lastUsers, tls); err == nil {
					reloaded = true
				} else {
					nlog.Core().Info("hot reload not possible, rebuilding kernel", "reason", err)
				}
			}
			if !reloaded {
				if err := s.rebuildKernel(spec, s.lastUsers, s.lastUsers, tls, customConfig); err != nil {
					if errors.Is(err, errKernelSwitchDeferred) {
						return errKernelSwitchDeferred
					}
					return fmt.Errorf("reload kernel: %w", err)
				}
			}
		}
	} else {
		setKernelCustomConfig(s.kernel, customConfig)
		if err := s.kernel.Start(spec, s.lastUsers, tls); err != nil {
			setKernelCustomConfig(s.kernel, s.appliedState.CustomConfig)
			return fmt.Errorf("start kernel: %w", err)
		}
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
	if !unchanged {
		// A different config now works: earlier failures no longer say
		// anything about the next attempt. A no-op re-apply proves nothing.
		s.kernelRetryHash, s.kernelRetryFailures, s.kernelRetryAt = "", 0, time.Time{}
		s.rebuildRetryKey, s.rebuildRetryFailures, s.rebuildRetryAt = "", 0, time.Time{}
	}
	if s.kernel.IsRunning() {
		if !unchanged {
			s.appliedState.CustomConfig = customConfig
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

// rebuildKey identifies what a failed rebuild was attempted with. Users are
// left out on purpose: routine user churn must not reset the backoff of a
// configuration that keeps failing.
func rebuildKey(spec *model.NodeSpec, customConfig map[string]any, tls kernel.TLSCert) string {
	h := sha256.New()
	io.WriteString(h, computeConfigHash(spec))
	custom, _ := json.Marshal(customConfig)
	h.Write(custom)
	h.Write(tls.CertPEM)
	h.Write(tls.KeyPEM)
	return fmt.Sprintf("%x", h.Sum(nil))
}

func (s *Service) rebuildDeferred(key string) bool {
	return key == s.rebuildRetryKey && time.Now().Before(s.rebuildRetryAt)
}

// rebuildFailed records a failed rebuild attempt and returns the backoff.
func (s *Service) rebuildFailed(key string) time.Duration {
	if key != s.rebuildRetryKey {
		s.rebuildRetryFailures = 0
	}
	delay := kernelSwitchRetryDelays[min(s.rebuildRetryFailures, len(kernelSwitchRetryDelays)-1)]
	s.rebuildRetryFailures++
	s.rebuildRetryKey = key
	s.rebuildRetryAt = time.Now().Add(delay)
	return delay
}

// rebuildKernel replaces the running kernel's configuration with a full
// rebuild of the same kernel. The new configuration is checked before the
// running listener is touched. A kernel that can bind its ports twice is
// replaced in place. Otherwise the running instance releases its listeners
// (existing connections drain in the background), the new configuration
// starts, and if it fails the previous one (restoreUsers, the applied config,
// TLS and custom_config snapshot) is started again. Interrupting attempts back
// off like kernel switches do.
func (s *Service) rebuildKernel(spec *model.NodeSpec, users, restoreUsers []model.UserSpec, tls kernel.TLSCert, customConfig map[string]any) error {
	k := s.kernel
	restoreSnapshot := func() { setKernelCustomConfig(k, s.appliedState.CustomConfig) }
	retryKey := rebuildKey(spec, customConfig, tls)
	if s.rebuildDeferred(retryKey) {
		return errKernelSwitchDeferred
	}
	setKernelCustomConfig(k, customConfig)
	if checker, ok := k.(interface {
		CheckConfig(*model.NodeSpec, []model.UserSpec, kernel.TLSCert) error
	}); ok {
		if err := checker.CheckConfig(spec, users, tls); err != nil {
			restoreSnapshot()
			return fmt.Errorf("check %s configuration: %w", s.kernelType, err)
		}
	}
	// A kernel that can replace its listener in place keeps serving throughout.
	inPlace := true
	if probe, ok := k.(interface{ CanReplaceInPlace(*model.NodeSpec) bool }); ok {
		inPlace = probe.CanReplaceInPlace(spec)
	}
	if inPlace {
		err := k.Start(spec, users, tls)
		if err == nil {
			s.appliedState.CustomConfig = customConfig
			return nil
		}
		// The new config cannot start even next to the running one, so
		// stopping the running one would not help: leave it serving.
		restoreSnapshot()
		delay := s.rebuildFailed(retryKey)
		nlog.Core().Warn("kernel rebuild failed; previous configuration still running",
			"kernel", s.kernelType, "failures", s.rebuildRetryFailures, "retry_after", delay)
		return fmt.Errorf("start %s: %w", s.kernelType, err)
	}

	released := false
	if releaser, ok := k.(interface{ ReleaseListeners() bool }); ok {
		released = releaser.ReleaseListeners()
	}
	if !released {
		k.Stop()
	}
	err := k.Start(spec, users, tls)
	if err == nil {
		s.appliedState.CustomConfig = customConfig
		s.rebuildRetryKey, s.rebuildRetryFailures, s.rebuildRetryAt = "", 0, time.Time{}
		return nil
	}
	restoreSnapshot()
	delay := s.rebuildFailed(retryKey)
	previous := s.appliedState.Config
	if previous == nil || len(restoreUsers) == 0 {
		// Nothing to restore: do not report a kernel without listeners as running.
		k.Stop()
		return fmt.Errorf("start %s: %w", s.kernelType, err)
	}
	// Restore at once: the usual cause is the new config itself, and the
	// previous listener should be back within milliseconds.
	restoreErr := k.Start(previous, restoreUsers, s.appliedState.TLS)
	if restoreErr != nil && released {
		// The previous config cannot start either, so the released instance
		// still holds something besides its listeners. Free everything, then
		// try the new config once more and fall back to the previous one.
		k.Stop()
		setKernelCustomConfig(k, customConfig)
		if retryErr := k.Start(spec, users, tls); retryErr == nil {
			s.appliedState.CustomConfig = customConfig
			s.rebuildRetryKey, s.rebuildRetryFailures, s.rebuildRetryAt = "", 0, time.Time{}
			return nil
		}
		restoreSnapshot()
		restoreErr = k.Start(previous, restoreUsers, s.appliedState.TLS)
	}
	if restoreErr != nil {
		// Stop for real so later polls see a stopped kernel and retry.
		k.Stop()
		return fmt.Errorf("start %s: %w; restore previous config: %w", s.kernelType, err, restoreErr)
	}
	nlog.Core().Warn("kernel rebuild failed; previous configuration restored",
		"kernel", s.kernelType, "failures", s.rebuildRetryFailures, "retry_after", delay)
	return fmt.Errorf("start %s: %w", s.kernelType, err)
}

// setKernelCustomConfig hands a validated custom_config snapshot to a kernel
// that supports snapshots. Other kernels keep reading the file themselves.
func setKernelCustomConfig(k kernel.Kernel, data map[string]any) {
	if setter, ok := k.(interface{ SetCustomConfig(map[string]any) }); ok {
		setter.SetCustomConfig(data)
	}
}

// sameCustomConfig treats "no file" and "not loaded yet" alike.
func sameCustomConfig(a, b map[string]any) bool {
	if len(a) == 0 && len(b) == 0 {
		return true
	}
	return reflect.DeepEqual(a, b)
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
