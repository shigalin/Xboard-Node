package model

import (
	"fmt"

	"github.com/cedar2025/xboard-node/internal/config"
)

type NodeSpec struct {
	Protocol        string
	ListenIP        string
	ServerPort      int
	Network         string
	NetworkSettings map[string]any
	Routes          []RouteRule

	KernelType       string
	KernelLogLevel   string
	CustomOutbounds  []OutboundConfig
	CustomRoutes     []map[string]any
	CustomRouteRules []CustomRouteRule
	CertConfig       *config.CertConfig
	AutoTLS          bool
	Domain           string

	Cipher    string
	Plugin    string
	PluginOpt string
	ServerKey string

	TLS         int
	Flow        string
	Decryption  string
	TLSSettings map[string]any

	Host       string
	ServerName string

	Version      int
	UpMbps       int
	DownMbps     int
	Obfs         string
	ObfsPassword string

	CongestionControl string
	PaddingScheme     string
	Transport         string
	TrafficPattern    string
	PSKMode           string
	Mode              string
	ShadowTLSServer   string
	ShadowTLSPort     int
	ShadowTLSPassword string

	Multiplex           *MultiplexConfig
	AcceptProxyProtocol bool
}

type OutboundConfig struct {
	Tag      string
	Protocol string
	Settings map[string]any
	ProxyTag string
}

type RouteRule struct {
	ID          int
	Match       []string
	Action      string
	ActionValue string
}

type MultiplexConfig struct {
	Enabled        bool
	Protocol       string
	MaxConnections int
	MinStreams     int
	MaxStreams     int
	Padding        bool
	Brutal         *BrutalConfig
}

type BrutalConfig struct {
	Enabled  bool
	UpMbps   int
	DownMbps int
}

type UserSpec struct {
	ID          int
	UUID        string
	SpeedLimit  int
	DeviceLimit int
}

func (n *NodeSpec) GetProxyProtocol() bool {
	if n == nil {
		return false
	}
	if n.AcceptProxyProtocol {
		return true
	}
	if n.NetworkSettings != nil {
		if v, ok := n.NetworkSettings["acceptProxyProtocol"]; ok {
			if b, ok := v.(bool); ok {
				return b
			}
		}
	}
	return false
}

// ProxyProtocolTrustedIPs returns networkSettings.proxyProtocolTrustedIPs.
// An omitted or null value returns nil.
func (n *NodeSpec) ProxyProtocolTrustedIPs() ([]string, error) {
	if n == nil || n.NetworkSettings == nil {
		return nil, nil
	}
	raw, ok := n.NetworkSettings["proxyProtocolTrustedIPs"]
	if !ok || raw == nil {
		return nil, nil
	}
	var items []any
	switch v := raw.(type) {
	case []any:
		items = v
	case []string:
		return append([]string(nil), v...), nil
	default:
		return nil, fmt.Errorf("network_settings.proxyProtocolTrustedIPs must be an array of IP or CIDR strings")
	}
	ips := make([]string, 0, len(items))
	for _, item := range items {
		ip, ok := item.(string)
		if !ok {
			return nil, fmt.Errorf("network_settings.proxyProtocolTrustedIPs must be an array of IP or CIDR strings")
		}
		ips = append(ips, ip)
	}
	return ips, nil
}

func cloneAnyMap(src map[string]any) map[string]any {
	if len(src) == 0 {
		return nil
	}
	out := make(map[string]any, len(src))
	for k, v := range src {
		out[k] = v
	}
	return out
}

func cloneMapSlice(src []map[string]any) []map[string]any {
	if len(src) == 0 {
		return nil
	}
	out := make([]map[string]any, 0, len(src))
	for _, item := range src {
		out = append(out, cloneAnyMap(item))
	}
	return out
}

func cloneStringSlice(src []string) []string {
	if len(src) == 0 {
		return nil
	}
	out := make([]string, len(src))
	copy(out, src)
	return out
}
