package panel

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cedar2025/xboard-node/internal/nlog"
	"github.com/gorilla/websocket"
)

type lockedLogBuffer struct {
	mu sync.Mutex
	bytes.Buffer
}

func (b *lockedLogBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.Buffer.Write(p)
}

func (b *lockedLogBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.Buffer.String()
}

func TestWSDialErrorDoesNotExposeToken(t *testing.T) {
	const token = "sensitive test+value"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, _, err := w.(http.Hijacker).Hijack()
		if err != nil {
			return
		}
		defer conn.Close()
		// A malformed handshake can echo the request token into a dial error.
		fmt.Fprintf(conn, "HTTP/1.1 %s Bad Handshake\r\n\r\n", r.URL.Query().Get("token"))
	}))
	defer server.Close()

	ws := NewWSClient("ws"+strings.TrimPrefix(server.URL, "http"), token, 1, WSClientConfig{}, nil, nil, nil)
	err := ws.connect(context.Background())
	if err == nil || !strings.Contains(err.Error(), "malformed HTTP status code") {
		t.Error("dial error cause was lost")
	}
	if err != nil && (strings.Contains(err.Error(), token) || strings.Contains(err.Error(), url.QueryEscape(token))) {
		t.Error("dial error exposed token")
	}
}

func TestWSAuthFailureDoesNotExposeToken(t *testing.T) {
	const token = "sensitive test+value"
	upgrader := websocket.Upgrader{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()
		conn.WriteJSON(wsMessage{Event: "error", Data: json.RawMessage(`{"message":"invalid ` + token + `"}`)})
	}))
	defer server.Close()

	ws := NewWSClient("ws"+strings.TrimPrefix(server.URL, "http"), token, 1, WSClientConfig{}, nil, nil, nil)
	if err := ws.connect(context.Background()); err == nil || !strings.Contains(err.Error(), "auth failed") {
		t.Error("authentication error cause was lost")
	} else if strings.Contains(err.Error(), token) || strings.Contains(err.Error(), url.QueryEscape(token)) {
		t.Error("authentication error exposed token")
	}

	var logs lockedLogBuffer
	nlog.Init(&logs, slog.LevelDebug, false)
	t.Cleanup(func() { nlog.Init(os.Stdout, slog.LevelInfo, true) })
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	// Stop after the first failure so the test covers the production logging path.
	ws.onStatus = func(WSStatusChange) { cancel() }
	ws.Run(ctx)
	if strings.Contains(logs.String(), token) || strings.Contains(logs.String(), url.QueryEscape(token)) {
		t.Error("WS error log exposed token")
	}
}

func TestWSDebugLogsNeverIncludeRawMessagesOrToken(t *testing.T) {
	const token = "sensitive test+value"
	upgrader := websocket.Upgrader{}
	received := make(chan struct{}, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()
		conn.WriteJSON(wsMessage{Event: "auth.success", Data: json.RawMessage(`{"credential":"` + token + `"}`)})
		conn.WriteJSON(wsMessage{Event: "ping", Data: json.RawMessage(`{"credential":"` + token + `"}`)})
		var msg wsMessage
		for conn.ReadJSON(&msg) == nil {
			if msg.Event == token {
				received <- struct{}{}
			}
		}
	}))
	defer server.Close()

	var logs lockedLogBuffer
	nlog.Init(&logs, slog.LevelDebug, false)
	t.Cleanup(func() { nlog.Init(os.Stdout, slog.LevelInfo, true) })
	ws := NewWSClient("ws"+strings.TrimPrefix(server.URL, "http"), token, 1, WSClientConfig{}, nil, nil, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	connected := make(chan struct{}, 1)
	ws.onStatus = func(status WSStatusChange) {
		if status.Connected {
			connected <- struct{}{}
		}
	}
	done := make(chan struct{})
	go func() { ws.Run(ctx); close(done) }()
	select {
	case <-connected:
	case <-ctx.Done():
		t.Fatal("WS did not connect")
	}
	if !ws.SendRaw(token, json.RawMessage(`{"credential":"`+token+`"}`)) {
		t.Error("failed to queue outgoing message")
	}
	select {
	case <-received:
	case <-ctx.Done():
		t.Error("WS did not send outgoing message")
	}
	cancel()
	<-done
	if strings.Contains(logs.String(), token) || strings.Contains(logs.String(), url.QueryEscape(token)) || strings.Contains(logs.String(), "credential") {
		t.Error("WS debug log exposed authentication or message data")
	}
	if !strings.Contains(logs.String(), "ws connecting") || strings.Count(logs.String(), "ws recv") < 2 || !strings.Contains(logs.String(), "ws send") {
		t.Error("WS debug paths were not exercised")
	}
}

// fakeWSServer simulates a minimal Workerman-style WS server for testing.
// It authenticates via token/node_id query params, sends auth.success, then
// delivers the provided events and handles pongs until the client disconnects.
func fakeWSServer(t *testing.T, events []wsMessage) *httptest.Server {
	t.Helper()
	upgrader := websocket.Upgrader{CheckOrigin: func(r *http.Request) bool { return true }}

	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Validate query params
		q := r.URL.Query()
		if q.Get("token") == "" || q.Get("node_id") == "" {
			http.Error(w, "missing auth params", http.StatusUnauthorized)
			return
		}

		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			t.Logf("upgrade error: %v", err)
			return
		}
		defer conn.Close()

		// Send auth.success
		if err := conn.WriteJSON(wsMessage{Event: "auth.success"}); err != nil {
			return
		}

		// Send test events
		for _, evt := range events {
			time.Sleep(50 * time.Millisecond)
			if err := conn.WriteJSON(evt); err != nil {
				return
			}
		}

		// Handle pongs/messages until connection closes
		for {
			var msg wsMessage
			if err := conn.ReadJSON(&msg); err != nil {
				return
			}
			if msg.Event == "pong" {
				// Client pong — acknowledged
			}
		}
	}))
}

func TestWSClient_ConnectAndReceiveDataEvents(t *testing.T) {
	configPayload := syncConfigPayload{
		Config:    NodeConfig{Protocol: "vless", ServerPort: 443},
		Timestamp: 1234,
	}
	usersPayload := syncUsersPayload{
		Users:     []User{{ID: 1, UUID: "abc", SpeedLimit: 100, DeviceLimit: 3}},
		Timestamp: 1235,
	}

	configData, _ := json.Marshal(configPayload)
	usersData, _ := json.Marshal(usersPayload)

	events := []wsMessage{
		{Event: WSEventSyncConfig, Data: configData},
		{Event: WSEventSyncUsers, Data: usersData},
	}
	server := fakeWSServer(t, events)
	defer server.Close()

	host := strings.TrimPrefix(server.URL, "http://")

	var mu sync.Mutex
	var received []WSEvent

	ws := NewWSClient("ws://"+host, "test-token", 1, WSClientConfig{}, func(event WSEvent) {
		mu.Lock()
		received = append(received, event)
		mu.Unlock()
	}, nil, func() map[string]interface{} { return nil })

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	go ws.Run(ctx)

	// Wait for events
	deadline := time.After(1500 * time.Millisecond)
	for {
		mu.Lock()
		n := len(received)
		mu.Unlock()
		if n >= 2 {
			break
		}
		select {
		case <-deadline:
			t.Fatalf("timed out waiting for events, got %d", n)
		case <-time.After(50 * time.Millisecond):
		}
	}

	mu.Lock()
	defer mu.Unlock()

	if len(received) != 2 {
		t.Fatalf("expected 2 events, got %d", len(received))
	}

	// Verify config event
	if received[0].Type != WSEventSyncConfig {
		t.Errorf("event[0].Type = %q, want %q", received[0].Type, WSEventSyncConfig)
	}
	if received[0].Config == nil {
		t.Fatal("event[0].Config is nil")
	}
	if received[0].Config.Protocol != "vless" {
		t.Errorf("config.Protocol = %q, want %q", received[0].Config.Protocol, "vless")
	}
	if received[0].Config.ServerPort != 443 {
		t.Errorf("config.ServerPort = %d, want 443", received[0].Config.ServerPort)
	}

	// Verify users event
	if received[1].Type != WSEventSyncUsers {
		t.Errorf("event[1].Type = %q, want %q", received[1].Type, WSEventSyncUsers)
	}
	if len(received[1].Users) != 1 {
		t.Fatalf("expected 1 user, got %d", len(received[1].Users))
	}
	if received[1].Users[0].UUID != "abc" {
		t.Errorf("user.UUID = %q, want %q", received[1].Users[0].UUID, "abc")
	}

	if !ws.IsConnected() {
		t.Error("expected IsConnected() = true while server is running")
	}
}

func TestWSClient_EmptyUsersSnapshot(t *testing.T) {
	server := fakeWSServer(t, []wsMessage{
		{Event: WSEventSyncUsers, Data: json.RawMessage(`{"node_id":2,"users":[{"id":1,"uuid":"abc"}]}`)},
		{Event: WSEventSyncUsers, Data: json.RawMessage(`{"node_id":2,"users":[]}`)},
	})
	defer server.Close()

	events := make(chan WSEvent, 2)
	ws := NewWSClient("ws"+strings.TrimPrefix(server.URL, "http"), "test-token", 2, WSClientConfig{}, func(event WSEvent) {
		events <- event
	}, nil, nil)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	go ws.Run(ctx)

	for i := 0; i < 2; i++ {
		select {
		case event := <-events:
			if event.Type != WSEventSyncUsers || event.NodeID != 2 {
				t.Fatalf("event[%d] = %+v, want sync.users for node 2", i, event)
			}
			if i == 0 && len(event.Users) != 1 {
				t.Fatalf("initial snapshot = %+v, want one user", event.Users)
			}
			if i == 1 && (event.Users == nil || len(event.Users) != 0) {
				t.Fatalf("revocation snapshot = %+v, want non-nil empty users", event.Users)
			}
		case <-ctx.Done():
			t.Fatalf("timed out waiting for users snapshot %d", i)
		}
	}
}

func TestWSClientReceivesDeviceBansWithoutReplacingIPSnapshot(t *testing.T) {
	const deadline = int64(1800000123456)
	var received []WSEvent
	ws := NewWSClient("", "", 1, WSClientConfig{}, func(event WSEvent) {
		received = append(received, event)
	}, nil, nil)
	ws.handleMessage(wsMessage{
		Event: WSEventSyncDevices,
		Data:  json.RawMessage(`{"node_id":2,"device_bans":{"42":1800000123456}}`),
	})
	if len(received) != 1 || received[0].NodeID != 2 || received[0].DeviceBans[42] != deadline {
		t.Fatalf("incorrect device ban event: %+v", received)
	}
	if received[0].DeviceUsers != nil {
		t.Fatal("a ban push was decoded as an empty online IP snapshot")
	}
}

func TestWSClient_ReconnectOnDisconnect(t *testing.T) {
	upgrader := websocket.Upgrader{CheckOrigin: func(r *http.Request) bool { return true }}

	var mu sync.Mutex
	connectCount := 0

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}

		mu.Lock()
		connectCount++
		count := connectCount
		mu.Unlock()

		// Send auth.success
		conn.WriteJSON(wsMessage{Event: "auth.success"})

		// Close immediately on first connection to trigger reconnect
		if count == 1 {
			conn.Close()
			return
		}

		// Keep second connection alive
		for {
			var msg wsMessage
			if err := conn.ReadJSON(&msg); err != nil {
				return
			}
		}
	}))
	defer server.Close()

	host := strings.TrimPrefix(server.URL, "http://")
	ws := NewWSClient("ws://"+host, "reconnect-token", 1, WSClientConfig{}, func(WSEvent) {}, nil, func() map[string]interface{} { return nil })

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	go ws.Run(ctx)

	// Wait for reconnection
	deadline := time.After(4 * time.Second)
	for {
		mu.Lock()
		n := connectCount
		mu.Unlock()
		if n >= 2 {
			break
		}
		select {
		case <-deadline:
			mu.Lock()
			t.Fatalf("expected at least 2 connections, got %d", connectCount)
			mu.Unlock()
		case <-time.After(100 * time.Millisecond):
		}
	}

	if !ws.IsConnected() {
		t.Error("expected IsConnected() = true after reconnect")
	}
}

func TestWSClient_FallbackWhenNoServer(t *testing.T) {
	ws := NewWSClient("ws://127.0.0.1:19999", "fallback-token", 1, WSClientConfig{}, func(WSEvent) {}, nil, func() map[string]interface{} { return nil })

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	go ws.Run(ctx)

	time.Sleep(500 * time.Millisecond)
	if ws.IsConnected() {
		t.Error("expected IsConnected() = false when no server")
	}
}

func TestWSClient_UserDeltaEvent(t *testing.T) {
	deltaPayload := syncUserDeltaPayload{
		Action:    "add",
		Users:     []User{{ID: 42, UUID: "delta-uuid"}},
		Timestamp: 1236,
	}
	deltaData, _ := json.Marshal(deltaPayload)

	events := []wsMessage{
		{Event: WSEventSyncUserDelta, Data: deltaData},
	}
	server := fakeWSServer(t, events)
	defer server.Close()

	host := strings.TrimPrefix(server.URL, "http://")

	var mu sync.Mutex
	var received []WSEvent

	ws := NewWSClient("ws://"+host, "delta-token", 1, WSClientConfig{}, func(event WSEvent) {
		mu.Lock()
		received = append(received, event)
		mu.Unlock()
	}, nil, func() map[string]interface{} { return nil })

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	go ws.Run(ctx)

	deadline := time.After(1500 * time.Millisecond)
	for {
		mu.Lock()
		n := len(received)
		mu.Unlock()
		if n >= 1 {
			break
		}
		select {
		case <-deadline:
			t.Fatal("timed out waiting for delta event")
		case <-time.After(50 * time.Millisecond):
		}
	}

	mu.Lock()
	defer mu.Unlock()

	if received[0].Type != WSEventSyncUserDelta {
		t.Errorf("event.Type = %q, want %q", received[0].Type, WSEventSyncUserDelta)
	}
	if received[0].DeltaAction != "add" {
		t.Errorf("event.DeltaAction = %q, want %q", received[0].DeltaAction, "add")
	}
	if len(received[0].DeltaUsers) != 1 || received[0].DeltaUsers[0].ID != 42 {
		t.Errorf("unexpected DeltaUsers: %+v", received[0].DeltaUsers)
	}
}
