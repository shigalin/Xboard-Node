package config

import (
	"fmt"
	"reflect"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestNormalizeRealitySNITargets(t *testing.T) {
	for _, tt := range []struct {
		name string
		raw  map[string]string
		want map[string]string
	}{
		{"unset", nil, nil},
		{"domain", map[string]string{" Site.Example.com. ": "www.example.com:443"}, map[string]string{"site.example.com": "www.example.com:443"}},
		{"loopback", map[string]string{"site.example.com": "127.0.0.1:48080"}, map[string]string{"site.example.com": "127.0.0.1:48080"}},
		{"ipv6", map[string]string{"site.example.com": "[::1]:8443"}, map[string]string{"site.example.com": "[::1]:8443"}},
		{"public IP", map[string]string{"site.example.com": "192.0.2.1:443"}, map[string]string{"site.example.com": "192.0.2.1:443"}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NormalizeRealitySNITargets(tt.raw)
			if err != nil || !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("mapping = %v, error = %v", got, err)
			}
		})
	}
	for _, raw := range []map[string]string{
		{"": "example.com:443"}, {"*.example.com": "example.com:443"},
		{"example.com:443": "example.com:443"}, {"127.0.0.1": "example.com:443"},
		{"a..example.com": "example.com:443"}, {"-site.example.com": "example.com:443"},
		{"site.example.com": "example.com"}, {"site.example.com": "https://example.com:443"},
		{"site.example.com": ":443"}, {"site.example.com": "example.com:0"},
		{"site.example.com": "example.com:65536"}, {"site.example.com": "example.com:abc"},
		{"Site.example.com": "a.example.com:443", "site.example.com": "b.example.com:443"},
	} {
		if _, err := NormalizeRealitySNITargets(raw); err == nil {
			t.Fatalf("invalid mapping accepted: %v", raw)
		}
	}
}

func TestRealitySNITargetsLoadAndInheritance(t *testing.T) {
	const panel = "panel: {url: 'https://panel.example.com', token: 'test-token', node_id: 1}\n"
	const mapping = "kernel:\n  type: xray\n  reality_sni_targets:\n    Site.example.com: 127.0.0.1:8443\n    www.example.com: www.example.com:443\n"
	file := writeTemp(t, panel+mapping)
	legacy, err := Load(file)
	if err != nil || legacy.Kernel.RealitySNITargets["site.example.com"] != "127.0.0.1:8443" {
		t.Fatalf("legacy load failed: %v", err)
	}
	root, err := LoadRoot(writeTemp(t, mapping+`instances:
  - panel: {url: 'https://one.example.com', token: 'test-token', node_id: 1}
  - panel: {url: 'https://two.example.com', token: 'test-token', node_id: 2}
    kernel:
      reality_sni_targets: {second.example.com: '127.0.0.1:9443'}
`))
	if err != nil {
		t.Fatal(err)
	}
	instances, err := root.NormalizeInstances()
	if err != nil || len(instances) != 2 {
		t.Fatalf("normalize instances: %v", err)
	}
	if !reflect.DeepEqual(instances[0].Kernel.RealitySNITargets, legacy.Kernel.RealitySNITargets) ||
		!reflect.DeepEqual(instances[1].Kernel.RealitySNITargets, map[string]string{"second.example.com": "127.0.0.1:9443"}) {
		t.Fatal("instance maps must inherit or replace, never merge")
	}
	// xbctl rewrites the typed YAML configuration; the map must survive it.
	data, err := yaml.Marshal(root)
	if err != nil {
		t.Fatal(err)
	}
	reloaded, err := LoadRoot(writeTemp(t, string(data)))
	if err != nil || !reflect.DeepEqual(reloaded.Instances[0].Kernel.RealitySNITargets, instances[0].Kernel.RealitySNITargets) {
		t.Fatalf("mapping lost during write-back: %v", err)
	}
	for _, load := range []func(string) error{
		func(path string) error { _, err := Load(path); return err },
		func(path string) error { _, err := LoadRoot(path); return err },
	} {
		if err := load(writeTemp(t, fmt.Sprint(panel, "kernel:\n  reality_sni_targets: {site.example.com: bad-destination}\n"))); err == nil {
			t.Fatal("invalid mapping must fail at configuration load")
		}
	}
}
