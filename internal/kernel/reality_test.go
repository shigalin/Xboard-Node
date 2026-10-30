package kernel

import (
	"testing"

	"github.com/cedar2025/xboard-node/internal/model"
)

func TestWithRealityTargetPreservesPanelSpec(t *testing.T) {
	nc := &model.NodeSpec{Protocol: "vless", TLS: 2, ServerPort: 2053,
		TLSSettings: map[string]any{"server_name": "Site.example.com", "dest": "old.example.com:443", "private_key": "test-key"}}
	targets := map[string]string{"site.example.com": "127.0.0.1:48080"}
	local := WithRealityTarget(nc, targets)
	if local.TLSSettings["dest"] != "127.0.0.1:48080" || local.ServerPort != 2053 || local.TLSSettings["server_name"] != "Site.example.com" {
		t.Fatal("destination override changed SNI or the node listener")
	}
	if nc.TLSSettings["dest"] != "old.example.com:443" {
		t.Fatal("panel-owned settings were mutated")
	}
	for _, change := range []func(*model.NodeSpec){
		func(n *model.NodeSpec) { n.TLS = 1 },
		func(n *model.NodeSpec) { n.Protocol = "vmess" },
		func(n *model.NodeSpec) { n.TLSSettings = map[string]any{"server_name": "other.example.com"} },
	} {
		other := *nc
		change(&other)
		if WithRealityTarget(&other, targets) != &other {
			t.Fatal("unmatched or non-REALITY node was changed")
		}
	}
}

func TestWithRealityTargetNormalizesSNI(t *testing.T) {
	type serverName string
	for _, tt := range []struct {
		name  string
		value any
	}{
		{"case", "Site.example.com"},
		{"trailing dot", "Site.example.com."},
		{"whitespace", " \tSite.example.com. \n"},
		{"named string", serverName("Site.example.com")},
	} {
		t.Run(tt.name, func(t *testing.T) {
			nc := &model.NodeSpec{Protocol: "vless", TLS: 2,
				TLSSettings: map[string]any{"server_name": tt.value, "dest": "public.example.com:443"}}
			local := WithRealityTarget(nc, map[string]string{"site.example.com": "127.0.0.1:48080"})
			if local.TLSSettings["dest"] != "127.0.0.1:48080" {
				t.Fatal("normalized SNI did not select the local destination")
			}
			if nc.TLSSettings["dest"] != "public.example.com:443" || local.TLSSettings["server_name"] != tt.value {
				t.Fatal("matching changed the panel destination or SNI")
			}
		})
	}
}
