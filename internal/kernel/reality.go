package kernel

import (
	"fmt"

	"github.com/cedar2025/xboard-node/internal/config"
	"github.com/cedar2025/xboard-node/internal/model"
)

// WithRealityTarget applies a local handshake destination without changing the
// panel's SNI, keys, user configuration or listener port. The panel-owned spec
// and its TLS settings are never mutated.
func WithRealityTarget(nc *model.NodeSpec, targets map[string]string) *model.NodeSpec {
	if nc == nil || nc.TLS != 2 || (nc.Protocol != "vless" && nc.Protocol != "trojan") {
		return nc
	}
	name := nc.TLSSettings["server_name"]
	if name == nil {
		return nc
	}
	dest := targets[config.NormalizeRealitySNI(fmt.Sprint(name))]
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
