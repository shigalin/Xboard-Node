package config

import (
	"fmt"
	"net"
	"strconv"
	"strings"
)

// NormalizeRealitySNITargets validates the operator's explicit SNI allowlist.
// Unlike RealityTargets, destinations may be DNS names or non-loopback IPs.
func NormalizeRealitySNITargets(raw map[string]string) (map[string]string, error) {
	if raw == nil {
		return nil, nil
	}
	targets := make(map[string]string, len(raw))
	for name, dest := range raw {
		sni := NormalizeRealitySNI(name)
		if !realityDNSName(sni) || net.ParseIP(sni) != nil {
			return nil, fmt.Errorf("kernel.reality_sni_targets: invalid SNI %q", name)
		}
		if _, exists := targets[sni]; exists {
			return nil, fmt.Errorf("kernel.reality_sni_targets: duplicate SNI %q", sni)
		}
		host, port, err := net.SplitHostPort(dest)
		n, portErr := strconv.Atoi(port)
		if err != nil || portErr != nil || n < 1 || n > 65535 || (net.ParseIP(host) == nil && !realityDNSName(host)) {
			return nil, fmt.Errorf("kernel.reality_sni_targets: destination for %q must be a DNS name or IP with a port", name)
		}
		targets[sni] = net.JoinHostPort(host, strconv.Itoa(n))
	}
	return targets, nil
}

func realityDNSName(name string) bool {
	if len(name) == 0 || len(name) > 253 {
		return false
	}
	for _, label := range strings.Split(name, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, ch := range label {
			if !('a' <= ch && ch <= 'z' || 'A' <= ch && ch <= 'Z' || '0' <= ch && ch <= '9' || ch == '-') {
				return false
			}
		}
	}
	return true
}
