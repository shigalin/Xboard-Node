package kernel

import (
	"fmt"

	"github.com/cedar2025/xboard-node/internal/config"
	"github.com/cedar2025/xboard-node/internal/model"
	"github.com/cedar2025/xboard-node/internal/nlog"
)

// WithRealityTarget applies a local handshake destination without changing the
// panel's SNI, keys, user configuration or listener port. The panel-owned spec
// and its TLS settings are never mutated.
func WithRealityTarget(nc *model.NodeSpec, targets map[string]string) *model.NodeSpec {
	dest := realityTargetFor(nc, targets)
	if dest == "" {
		return nc
	}
	local := *nc
	local.TLSSettings = make(map[string]any, len(nc.TLSSettings)+1)
	for key, value := range nc.TLSSettings {
		local.TLSSettings[key] = value
	}
	local.TLSSettings["dest"] = dest
	return &local
}

// LogRealityTarget reports whether a configured mapping applies to this node,
// so that a typo in the mapping or a changed panel SNI does not silently keep
// dialing the public destination. Kernels call it from start/reload paths only;
// user hot-updates rebuild the kernel config too and must not repeat it.
func LogRealityTarget(nc *model.NodeSpec, targets map[string]string) {
	if nc == nil || nc.TLS != 2 || len(targets) == 0 {
		return
	}
	if dest := realityTargetFor(nc, targets); dest != "" {
		nlog.Core().Info("reality handshake redirected to local website",
			"server_name", realitySNI(nc), "dest", dest)
		return
	}
	nlog.Core().Warn("reality target mapping has no entry for this node; handshake keeps the panel destination",
		"server_name", realitySNI(nc), "protocol", nc.Protocol)
}

// realityTargetFor returns the configured local destination for this node, or
// an empty string when it is not a REALITY node or its SNI is unmapped.
func realityTargetFor(nc *model.NodeSpec, targets map[string]string) string {
	if nc == nil || nc.TLS != 2 || len(targets) == 0 {
		return ""
	}
	sni := realitySNI(nc)
	if sni == "" {
		return ""
	}
	return targets[config.NormalizeRealitySNI(sni)]
}

// realitySNI returns the panel's REALITY server name as a string, without
// normalizing it — the value handed to the kernel stays untouched.
func realitySNI(nc *model.NodeSpec) string {
	if name := nc.TLSSettings["server_name"]; name != nil {
		return fmt.Sprint(name)
	}
	return ""
}
