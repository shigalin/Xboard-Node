package xray

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"github.com/cedar2025/xboard-node/internal/config"
	xrayCore "github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/infra/conf/serial"
)

// realitySNIRouter belongs to one main Xray instance. Registering it as a core
// feature keeps it alive through draining and closes it on failed starts and
// final shutdown. A private Unix socket avoids exposing another TCP listener.
type realitySNIRouter struct {
	instance *xrayCore.Instance
	dir      string
	cancel   context.CancelFunc
}

func (*realitySNIRouter) Type() interface{} { return (*realitySNIRouter)(nil) }
func (*realitySNIRouter) Start() error      { return nil } // already listening before REALITY's target probes

func (r *realitySNIRouter) Close() error {
	// Core.Close closes listeners but does not cancel anonymous live streams.
	r.cancel()
	err := r.instance.Close()
	removeErr := os.RemoveAll(r.dir)
	if err != nil {
		return err
	}
	return removeErr
}

// prepareRealitySNIRouting replaces only the generated REALITY destination and
// its SNI allowlist. Panel identity, credentials and application routing stay
// unchanged. An empty map or a non-REALITY inbound preserves existing behavior.
func prepareRealitySNIRouting(cfg M, rawTargets map[string]string) (*realitySNIRouter, error) {
	if len(rawTargets) == 0 {
		return nil, nil
	}
	inbounds, _ := cfg["inbounds"].([]M)
	if len(inbounds) != 1 {
		return nil, nil
	}
	stream, _ := inbounds[0]["streamSettings"].(M)
	reality, _ := stream["realitySettings"].(M)
	if stream["security"] != "reality" || reality == nil {
		return nil, nil
	}
	targets, err := config.NormalizeRealitySNITargets(rawTargets)
	if err != nil {
		return nil, err
	}
	// The default subscription SNI must still work after enabling the feature.
	names, _ := reality["serverNames"].([]string)
	if len(names) != 1 || targets[config.NormalizeRealitySNI(names[0])] == "" {
		return nil, fmt.Errorf("kernel.reality_sni_targets must include the panel's REALITY server_name")
	}
	serverNames := make([]string, 0, len(targets)+1)
	for name := range targets {
		serverNames = append(serverNames, name)
	}
	// Preserve the panel's exact spelling for existing subscriptions. Routing
	// uses Xray's case-insensitive domain matcher, while REALITY matches exactly.
	if names[0] != config.NormalizeRealitySNI(names[0]) {
		serverNames = append(serverNames, names[0])
	}
	sort.Strings(serverNames)

	dir, err := os.MkdirTemp("", "xb-sni-")
	if err != nil {
		return nil, fmt.Errorf("create REALITY SNI socket directory: %w", err)
	}
	ready := false
	ctx, cancel := context.WithCancel(context.Background())
	defer func() {
		if !ready {
			cancel()
			os.RemoveAll(dir)
		}
	}()
	socket := filepath.Join(dir, "route.sock")
	data, err := marshalConfig(buildRealitySNIRouterConfig(socket, targets))
	if err != nil {
		return nil, err
	}
	pb, err := serial.LoadJSONConfig(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("parse REALITY SNI router: %w", err)
	}
	// Core creation shares the dispatcher's registration with main instances.
	xrayCreationMu.Lock()
	inst, err := xrayCore.NewWithContext(ctx, pb)
	xrayCreationMu.Unlock()
	if err != nil {
		return nil, fmt.Errorf("create REALITY SNI router: %w", err)
	}
	if err := startWithTimeout(inst, startTimeout); err != nil {
		inst.Close()
		return nil, fmt.Errorf("start REALITY SNI router: %w", err)
	}
	reality["dest"] = socket
	reality["serverNames"] = serverNames
	ready = true
	return &realitySNIRouter{instance: inst, dir: dir, cancel: cancel}, nil
}

func buildRealitySNIRouterConfig(socket string, targets map[string]string) M {
	names := make([]string, 0, len(targets))
	for name := range targets {
		names = append(names, name)
	}
	sort.Strings(names)
	// Block is first so even missing/non-TLS SNI cannot reach a default target.
	outbounds := []M{{"tag": "block", "protocol": "blackhole"}}
	var rules []M
	for i, name := range names {
		tag := fmt.Sprintf("target-%d", i)
		outbounds = append(outbounds, M{"tag": tag, "protocol": "freedom", "settings": M{
			"redirect": targets[name],
			// The redirect is fixed by the operator, never by client input. This
			// permits explicitly configured local websites without changing the
			// main instance's private-address restrictions for proxy users.
			"finalRules": []M{{"action": "allow"}},
		}})
		rules = append(rules, M{"type": "field", "inboundTag": []string{"sni-in"},
			"protocol": []string{"tls"}, "domain": []string{"full:" + name}, "outboundTag": tag})
	}
	rules = append(rules, M{"type": "field", "inboundTag": []string{"sni-in"}, "outboundTag": "block"})
	return M{
		"log": M{"loglevel": "error"},
		"inbounds": []M{{"tag": "sni-in", "listen": socket, "protocol": "dokodemo-door",
			"settings": M{"address": "127.0.0.1", "port": 443, "network": "tcp"},
			"sniffing": M{"enabled": true, "destOverride": []string{"tls"}, "routeOnly": true},
		}},
		"outbounds": outbounds,
		"routing":   M{"domainStrategy": "AsIs", "rules": rules},
	}
}
