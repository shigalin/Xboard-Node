package xray

import (
	"sync/atomic"
	"testing"

	"github.com/cedar2025/xboard-node/internal/config"
	"github.com/cedar2025/xboard-node/internal/kernel"
	"github.com/cedar2025/xboard-node/internal/model"
	xlog "github.com/xtls/xray-core/common/log"
)

type sniLogSink struct{ n atomic.Int64 }

func (s *sniLogSink) Handle(xlog.Message) { s.n.Add(1) }
func TestRealitySNIFailedMainStartPreservesExistingLogger(t *testing.T) {
	sink := new(sniLogSink)
	xlog.RegisterHandler(sink)
	xlog.Record(&xlog.GeneralMessage{Severity: xlog.Severity_Error, Content: "before failed reload"})
	if sink.n.Load() != 1 {
		t.Fatal("negative-control setup failed")
	}
	server := New(config.KernelConfig{})
	nc := &model.NodeSpec{Protocol: "vless", ListenIP: "127.0.0.1", ServerPort: 443, Network: "tcp", TLS: 2, TLSSettings: M{"server_name": "one.example.com,two.example.com", "private_key": "invalid-test-key", "short_id": "abcd"}}
	if err := server.Start(nc, nil, kernel.TLSCert{}); err == nil {
		server.Stop()
		t.Fatal("expected invalid main configuration to fail")
	}
	xlog.Record(&xlog.GeneralMessage{Severity: xlog.Severity_Error, Content: "after failed reload"})
	if got := sink.n.Load(); got != 2 {
		t.Fatalf("existing log sink received %d messages, want 2; failed startup replaced global logger", got)
	}
}
