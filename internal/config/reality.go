package config

import (
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// LoadRealityTargets reads an optional SNI -> loopback host:port mapping.
// An explicitly configured missing or invalid file is an error, so a node never
// silently falls back to dialing its own public listener.
func LoadRealityTargets(path string) (map[string]string, error) {
	if path == "" {
		return nil, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read reality targets: %w", err)
	}
	var raw map[string]string
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("parse reality targets: %w", err)
	}
	if len(raw) == 0 {
		return nil, fmt.Errorf("reality targets must contain at least one SNI mapping")
	}
	targets := make(map[string]string, len(raw))
	for name, dest := range raw {
		sni := NormalizeRealitySNI(name)
		if sni == "" || strings.ContainsAny(sni, "/:* \t\r\n") || net.ParseIP(sni) != nil {
			return nil, fmt.Errorf("invalid reality target SNI %q", name)
		}
		host, port, err := net.SplitHostPort(dest)
		ip := net.ParseIP(host)
		n, portErr := strconv.Atoi(port)
		if err != nil || ip == nil || !ip.IsLoopback() || portErr != nil || n < 1 || n > 65535 {
			return nil, fmt.Errorf("reality target for %q must be a loopback IP and port", name)
		}
		if _, exists := targets[sni]; exists {
			return nil, fmt.Errorf("duplicate reality target SNI %q", name)
		}
		targets[sni] = net.JoinHostPort(host, strconv.Itoa(n))
	}
	return targets, nil
}

// NormalizeRealitySNI normalizes mapping keys and lookups without changing the
// SNI value sent to the kernel.
func NormalizeRealitySNI(name string) string {
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(name), "."))
}
