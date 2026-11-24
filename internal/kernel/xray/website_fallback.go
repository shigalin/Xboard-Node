package xray

import (
	"net"
	"strconv"

	"github.com/cedar2025/xboard-node/internal/config"
	"github.com/cedar2025/xboard-node/internal/model"
	"github.com/cedar2025/xboard-node/internal/nlog"
)

// websiteFallback is the TLS website fallback outcome for one inbound. skip is
// empty when the fallback applies.
type websiteFallback struct {
	name, target, network, skip string
}

// decideTLSWebsiteFallback reports whether a TLS website mapping concerns this
// inbound and, if so, whether it can be applied. It does not modify the inbound.
func decideTLSWebsiteFallback(inbound M, nc *model.NodeSpec, targets map[string]string) (websiteFallback, bool) {
	if inbound == nil || len(targets) == 0 || nc.TLS != 1 || nc.Protocol != "vless" {
		return websiteFallback{}, false
	}
	stream, _ := inbound["streamSettings"].(M)
	tls, _ := stream["tlsSettings"].(M)
	name, _ := tls["serverName"].(string)
	network, _ := stream["network"].(string)
	d := websiteFallback{name: config.NormalizeRealitySNI(name), network: network}
	var ok bool
	if d.target, ok = targets[d.name]; !ok {
		d.skip = "tls website mapping has no entry for this node; no website fallback"
		return d, true
	}
	// Never send a connection back into the same listener.
	if _, port, err := net.SplitHostPort(d.target); err != nil || port == strconv.Itoa(nc.ServerPort) {
		d.skip = "tls website target uses the node's own port; no website fallback"
		return d, true
	}
	switch network {
	case "tcp", "raw":
		settings, _ := inbound["settings"].(M)
		// Xray rejects fallbacks combined with VLESS Encryption.
		if dec, _ := settings["decryption"].(string); dec != "none" {
			d.skip = "tls website fallback skipped: VLESS decryption is enabled"
		}
	case "xhttp":
	default:
		d.skip = "tls website fallback skipped: unsupported network"
	}
	return d, true
}

func applyTLSWebsiteFallback(inbound M, nc *model.NodeSpec, targets map[string]string) {
	d, ok := decideTLSWebsiteFallback(inbound, nc, targets)
	if !ok || d.skip != "" {
		return
	}
	stream := inbound["streamSettings"].(M)
	if d.network == "xhttp" {
		stream["xhttpSettings"].(M)["httpFallback"] = d.target
		return
	}
	// The default h2/http/1.1 ALPN is kept so existing clients still connect.
	// Raw fallbacks forward bytes as-is, so the local site must accept both
	// HTTP/1.1 and plaintext HTTP/2 (h2c) from browsers that negotiate h2.
	inbound["settings"].(M)["fallbacks"] = []M{{"name": d.name, "dest": d.target}}
}

// logTLSWebsiteFallback reports the fallback outcome once per start; buildConfig
// itself stays silent because CheckConfig also calls it.
func logTLSWebsiteFallback(cfgMap M, nc *model.NodeSpec, targets map[string]string) {
	inbounds, _ := cfgMap["inbounds"].([]M)
	if len(inbounds) == 0 {
		return
	}
	d, ok := decideTLSWebsiteFallback(inbounds[0], nc, targets)
	switch {
	case !ok:
	case d.skip != "":
		nlog.Core().Warn(d.skip, "server_name", d.name, "dest", d.target, "network", d.network)
	default:
		nlog.Core().Info("tls website fallback enabled", "server_name", d.name, "dest", d.target, "network", d.network)
	}
}
