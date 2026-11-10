package xray

import (
	"encoding/json"
	"testing"

	"github.com/cedar2025/xboard-node/internal/config"
	"github.com/cedar2025/xboard-node/internal/kernel"
	"github.com/cedar2025/xboard-node/internal/model"
)

func TestBuildConfigDoesNotMutateSpec(t *testing.T) {
	users := []model.UserSpec{{ID: 1, UUID: "11111111-1111-4111-8111-111111111111"}}
	tc := kernel.TLSCert{CertPEM: []byte("c"), KeyPEM: []byte("k")}
	specs := []*model.NodeSpec{
		{Protocol: "vless", Network: "xhttp", ServerPort: 443, NetworkSettings: map[string]any{"path": "/x", "extra": map[string]any{"a": []any{}, "b": map[string]any{"c": []any{}}}}},
		{Protocol: "trojan", ServerPort: 443, Network: "ws", NetworkSettings: map[string]any{"path": "/t", "headers": map[string]any{"Host": "h"}}},
		{Protocol: "vless", ServerPort: 443, TLS: 2, TLSSettings: map[string]any{"server_name": "a.example,b.example", "private_key": "x", "short_id": []any{"ab"}, "server_port": "443"}},
		{Protocol: "vmess", ServerPort: 443, TLS: 1, Network: "grpc", NetworkSettings: map[string]any{"serviceName": "g"}, TLSSettings: map[string]any{"alpn": []any{"h2"}}},
		{Protocol: "hysteria", Version: 2, ServerPort: 443, UpMbps: 10, DownMbps: 20},
		{Protocol: "shadowsocks", ServerPort: 443, Cipher: "aes-128-gcm", AcceptProxyProtocol: true},
	}
	for _, spec := range specs {
		before, _ := json.Marshal(spec)
		_ = buildConfig(config.KernelConfig{Type: "xray", CustomConfigData: map[string]any{}}, spec, users, tc)
		after, _ := json.Marshal(spec)
		if string(before) != string(after) {
			t.Errorf("%s/%s mutated:\n%s\n%s", spec.Protocol, spec.Network, before, after)
		}
	}
}
