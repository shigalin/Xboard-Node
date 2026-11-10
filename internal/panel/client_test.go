package panel

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/cedar2025/xboard-node/internal/config"
)

func newTestServer(handler http.HandlerFunc) (*httptest.Server, *Client) {
	ts := httptest.NewServer(handler)
	client := NewClient(config.PanelConfig{
		URL:    ts.URL,
		Token:  "test-token",
		NodeID: 1,
	})
	return ts, client
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestAuthenticatedGETTransportErrorsDoNotExposeToken(t *testing.T) {
	const token = "sensitive test+value"
	for name, call := range map[string]func(*Client) error{
		"config":      func(c *Client) error { _, err := c.GetConfig(); return err },
		"users":       func(c *Client) error { _, err := c.GetUsers(); return err },
		"devices":     func(c *Client) error { _, err := c.GetDevices(); return err },
		"device bans": func(c *Client) error { _, err := c.SyncDeviceBans(context.Background(), nil); return err },
	} {
		t.Run(name, func(t *testing.T) {
			cause := errors.New("transport unavailable")
			client := NewClient(config.PanelConfig{URL: "http://panel.invalid", Token: token, NodeID: 1})
			client.httpClient.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
				if r.URL.Query().Get("token") != token {
					t.Error("GET request did not authenticate")
				}
				return nil, cause
			})
			err := call(client)
			if err == nil || !errors.Is(err, cause) {
				t.Error("transport cause was lost")
			}
			if err != nil && (strings.Contains(err.Error(), token) || strings.Contains(err.Error(), url.QueryEscape(token))) {
				t.Error("transport error exposed token")
			}
		})
	}
}

func TestAuthenticatedGETTransportErrorWithURLDoesNotExposeToken(t *testing.T) {
	const token = "sensitive test+value"
	client := NewClient(config.PanelConfig{URL: "http://panel.invalid", Token: token, NodeID: 1})
	client.httpClient.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		return nil, fmt.Errorf("transport unavailable: %s", r.URL.String())
	})
	_, err := client.GetConfig()
	if err == nil || !strings.Contains(err.Error(), "transport unavailable") {
		t.Error("transport cause was lost")
	}
	if err != nil && (strings.Contains(err.Error(), token) || strings.Contains(err.Error(), url.QueryEscape(token))) {
		t.Error("transport error exposed token")
	}
}

func TestAuthenticatedGETErrorResponseDoesNotExposeToken(t *testing.T) {
	const token = "sensitive test+value"
	for name, call := range map[string]func(*Client) error{
		"config":      func(c *Client) error { _, err := c.GetConfig(); return err },
		"users":       func(c *Client) error { _, err := c.GetUsers(); return err },
		"devices":     func(c *Client) error { _, err := c.GetDevices(); return err },
		"device bans": func(c *Client) error { _, err := c.SyncDeviceBans(context.Background(), nil); return err },
	} {
		t.Run(name, func(t *testing.T) {
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Query().Get("token") != token {
					t.Error("GET request did not authenticate")
				}
				w.WriteHeader(http.StatusInternalServerError)
				fmt.Fprint(w, "upstream unavailable: ", r.URL.String(), " ", token)
			}))
			defer ts.Close()

			client := NewClient(config.PanelConfig{URL: ts.URL, Token: token, NodeID: 1})
			err := call(client)
			if err == nil {
				t.Fatal("expected error for 500 response")
			}
			if !strings.Contains(err.Error(), "status 500") || strings.Contains(err.Error(), "upstream unavailable") {
				t.Error("status was lost or remote response body was returned")
			}
			if strings.Contains(err.Error(), token) || strings.Contains(err.Error(), url.QueryEscape(token)) {
				t.Error("response error exposed token")
			}
		})
	}
}

func TestAuthenticatedPOSTErrorResponsesDoNotExposeToken(t *testing.T) {
	const token = "sensitive <test+value>&"
	jsonToken, _ := json.Marshal(token)
	escapedToken := string(jsonToken[1 : len(jsonToken)-1])

	for _, tc := range []struct {
		name      string
		path      string
		machineID int
		call      func(*Client) error
	}{
		{"traffic", "/api/v1/server/UniProxy/push", 0, func(c *Client) error {
			return c.PushTraffic(map[int][2]int64{1: {100, 200}})
		}},
		{"handshake", "/api/v2/server/handshake", 0, func(c *Client) error {
			_, err := c.Handshake()
			return err
		}},
		{"machine nodes", "/api/v2/server/machine/nodes", 3, func(c *Client) error {
			_, err := c.GetMachineNodes()
			return err
		}},
		{"machine status", "/api/v2/server/machine/status", 3, func(c *Client) error {
			return c.ReportMachineStatus(1, [2]uint64{}, [2]uint64{}, [2]uint64{}, -1, -1)
		}},
		{"device bans", "/api/v2/server/device-bans", 3, func(c *Client) error {
			_, err := c.SyncDeviceBans(context.Background(), map[int]int64{1: 1})
			return err
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodPost || r.URL.Path != tc.path {
					t.Error("unexpected request method or path")
				}
				requestBody, err := io.ReadAll(r.Body)
				if err != nil {
					t.Error("failed to read request body")
					return
				}
				var payload map[string]interface{}
				if json.Unmarshal(requestBody, &payload) != nil || payload["token"] != token {
					t.Error("POST request did not authenticate")
				}
				w.WriteHeader(http.StatusInternalServerError)
				fmt.Fprint(w, "upstream unavailable: ", string(requestBody), " token=", url.QueryEscape(token), " ", token)
			}))
			defer ts.Close()

			client := NewClient(config.PanelConfig{URL: ts.URL, Token: token, NodeID: 1, MachineID: tc.machineID})
			err := tc.call(client)
			if err == nil {
				t.Fatal("expected error for 500 response")
			}
			message := err.Error()
			if !strings.Contains(message, "status 500") || strings.Contains(message, "upstream unavailable") || strings.Contains(message, "[REDACTED]") {
				t.Error("status was lost or remote response body was returned")
			}
			for _, exposed := range []string{token, url.QueryEscape(token), escapedToken} {
				if strings.Contains(message, exposed) {
					t.Error("response error exposed token")
				}
			}
		})
	}
}

func TestAuthenticatedErrorResponseEscapedTokenDoesNotLeak(t *testing.T) {
	const token = "sek/ret"
	const escapedToken = `sek\\/ret`
	const htmlToken = "sek&#47;ret"
	const diagnostic = "upstream unavailable"

	for _, tc := range []struct {
		name   string
		method string
		call   func(*Client) error
	}{
		{"GET", http.MethodGet, func(c *Client) error { _, err := c.GetConfig(); return err }},
		{"POST", http.MethodPost, func(c *Client) error { return c.PushTraffic(map[int][2]int64{1: {1, 2}}) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != tc.method {
					t.Error("unexpected request method")
				}
				if r.Method == http.MethodGet {
					if r.URL.Query().Get("token") != token {
						t.Error("GET request did not authenticate")
					}
				} else {
					var payload map[string]interface{}
					if json.NewDecoder(r.Body).Decode(&payload) != nil || payload["token"] != token {
						t.Error("POST request did not authenticate")
					}
				}
				w.WriteHeader(http.StatusInternalServerError)
				fmt.Fprint(w, diagnostic, ": ", escapedToken, " ", htmlToken)
			}))
			defer ts.Close()

			client := NewClient(config.PanelConfig{URL: ts.URL, Token: token, NodeID: 1})
			err := tc.call(client)
			if err == nil {
				t.Fatal("expected error for 500 response")
			}
			if !strings.Contains(err.Error(), "status 500") {
				t.Error("response status was lost")
			}
			for _, exposed := range []string{diagnostic, token, url.QueryEscape(token), escapedToken, htmlToken} {
				if strings.Contains(err.Error(), exposed) {
					t.Error("remote response body or token encoding was returned")
				}
			}
		})
	}
}

func TestGetConfig_Success(t *testing.T) {
	ts, client := newTestServer(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/server/UniProxy/config" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		if r.URL.Query().Get("token") != "test-token" {
			t.Errorf("missing token in query")
		}
		if r.URL.Query().Get("node_id") != "1" {
			t.Errorf("missing node_id in query")
		}
		w.Header().Set("ETag", `"etag-1"`)
		json.NewEncoder(w).Encode(NodeConfig{
			Protocol:   "shadowsocks",
			ServerPort: 111,
			Cipher:     "aes-128-gcm",
		})
	})
	defer ts.Close()

	cfg, err := client.GetConfig()
	if err != nil {
		t.Fatalf("GetConfig: %v", err)
	}
	if cfg == nil {
		t.Fatal("expected non-nil config")
	}
	if cfg.Protocol != "shadowsocks" {
		t.Errorf("protocol: got %q", cfg.Protocol)
	}
	if cfg.ServerPort != 111 {
		t.Errorf("server_port: got %d", cfg.ServerPort)
	}
}

func TestGetConfig_NotModified(t *testing.T) {
	callCount := 0
	ts, client := newTestServer(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		if callCount == 1 {
			w.Header().Set("ETag", `"etag-1"`)
			json.NewEncoder(w).Encode(NodeConfig{Protocol: "shadowsocks"})
			return
		}
		if r.Header.Get("If-None-Match") != `"etag-1"` {
			t.Errorf("expected If-None-Match header, got %q", r.Header.Get("If-None-Match"))
		}
		w.WriteHeader(http.StatusNotModified)
	})
	defer ts.Close()

	// First call — get config
	cfg, err := client.GetConfig()
	if err != nil || cfg == nil {
		t.Fatalf("first GetConfig: err=%v cfg=%v", err, cfg)
	}

	// Second call — should be 304
	cfg, err = client.GetConfig()
	if err != nil {
		t.Fatalf("second GetConfig: %v", err)
	}
	if cfg != nil {
		t.Error("expected nil config for 304")
	}
}

func TestGetConfig_ServerError(t *testing.T) {
	ts, client := newTestServer(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("internal error"))
	})
	defer ts.Close()

	_, err := client.GetConfig()
	if err == nil {
		t.Fatal("expected error for 500 response")
	}
}

func TestGetUsers_Success(t *testing.T) {
	ts, client := newTestServer(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/server/UniProxy/user" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		w.Header().Set("ETag", `"users-etag-1"`)
		json.NewEncoder(w).Encode(UsersResponse{
			Users: []User{
				{ID: 1, UUID: "uuid-1", SpeedLimit: 3, DeviceLimit: 2},
				{ID: 2, UUID: "uuid-2", SpeedLimit: 0, DeviceLimit: 0},
			},
		})
	})
	defer ts.Close()

	users, err := client.GetUsers()
	if err != nil {
		t.Fatalf("GetUsers: %v", err)
	}
	if len(users) != 2 {
		t.Fatalf("users count: got %d", len(users))
	}
	if users[0].UUID != "uuid-1" {
		t.Errorf("user[0].uuid: got %q", users[0].UUID)
	}
}

func TestGetUsers_NotModified(t *testing.T) {
	callCount := 0
	ts, client := newTestServer(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		if callCount == 1 {
			w.Header().Set("ETag", `"u-etag"`)
			json.NewEncoder(w).Encode(UsersResponse{Users: []User{{ID: 1, UUID: "u1"}}})
			return
		}
		w.WriteHeader(http.StatusNotModified)
	})
	defer ts.Close()

	users, _ := client.GetUsers()
	if len(users) != 1 {
		t.Fatalf("first call: got %d users", len(users))
	}
	users, err := client.GetUsers()
	if err != nil {
		t.Fatalf("second GetUsers: %v", err)
	}
	if users != nil {
		t.Error("expected nil for 304")
	}
}

func TestPushTraffic_Success(t *testing.T) {
	var received map[string]interface{}
	ts, client := newTestServer(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			t.Errorf("expected POST, got %s", r.Method)
		}
		if r.URL.Path != "/api/v1/server/UniProxy/push" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		json.NewDecoder(r.Body).Decode(&received)
		w.WriteHeader(http.StatusOK)
	})
	defer ts.Close()

	data := map[int][2]int64{
		1: {1024, 2048},
		2: {512, 256},
	}
	if err := client.PushTraffic(data); err != nil {
		t.Fatalf("PushTraffic: %v", err)
	}
	if received == nil {
		t.Fatal("server received nil payload")
	}
	// Verify token was injected
	if received["token"] != "test-token" {
		t.Errorf("token: got %v", received["token"])
	}
}

func TestPushTraffic_Empty(t *testing.T) {
	called := false
	ts, client := newTestServer(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})
	defer ts.Close()

	if err := client.PushTraffic(nil); err != nil {
		t.Fatalf("PushTraffic nil: %v", err)
	}
	if called {
		t.Error("should not call server for empty traffic")
	}
}

func TestPushAlive_Success(t *testing.T) {
	var received map[string]interface{}
	ts, client := newTestServer(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/server/UniProxy/alive" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		json.NewDecoder(r.Body).Decode(&received)
		w.WriteHeader(http.StatusOK)
	})
	defer ts.Close()

	data := map[int][]string{
		1: {"1.2.3.4", "5.6.7.8"},
	}
	if err := client.PushAlive(data); err != nil {
		t.Fatalf("PushAlive: %v", err)
	}
	if received == nil {
		t.Fatal("server received nil")
	}
}

func TestPushStatus_Success(t *testing.T) {
	var received map[string]interface{}
	ts, client := newTestServer(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/server/UniProxy/status" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		json.NewDecoder(r.Body).Decode(&received)
		w.WriteHeader(http.StatusOK)
	})
	defer ts.Close()

	err := client.PushStatus(50.0, [2]uint64{8192, 4096}, [2]uint64{2048, 1024}, [2]uint64{100000, 50000})
	if err != nil {
		t.Fatalf("PushStatus: %v", err)
	}
	if received["cpu"].(float64) != 50.0 {
		t.Errorf("cpu: got %v", received["cpu"])
	}
}

func TestResetETags(t *testing.T) {
	callCount := 0
	ts, client := newTestServer(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		if callCount <= 2 {
			w.Header().Set("ETag", `"e1"`)
			json.NewEncoder(w).Encode(NodeConfig{Protocol: "ss"})
			return
		}
		// After reset, should NOT send If-None-Match
		if r.Header.Get("If-None-Match") != "" {
			t.Errorf("expected no If-None-Match after reset, got %q", r.Header.Get("If-None-Match"))
		}
		json.NewEncoder(w).Encode(NodeConfig{Protocol: "ss"})
	})
	defer ts.Close()

	client.GetConfig()
	client.ResetETags()
	client.GetConfig()
}

func TestCachedConfigFollowsETag(t *testing.T) {
	type reply struct {
		etag     string
		protocol string
	}
	var next reply
	ts, client := newTestServer(func(w http.ResponseWriter, r *http.Request) {
		if next.etag != "" && r.Header.Get("If-None-Match") == next.etag {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		if next.etag != "" {
			w.Header().Set("ETag", next.etag)
		}
		json.NewEncoder(w).Encode(NodeConfig{Protocol: next.protocol})
	})
	defer ts.Close()
	cached := func() string {
		t.Helper()
		cfg, err := client.CachedConfig()
		if err != nil {
			t.Fatal(err)
		}
		if cfg == nil {
			return ""
		}
		return cfg.Protocol
	}

	next = reply{`"a"`, "vless"}
	client.GetConfig()
	if cfg, _ := client.GetConfig(); cfg != nil || cached() != "vless" {
		t.Fatal("HTTP 304 did not resolve to the config behind the ETag")
	}
	next = reply{`"b"`, "trojan"}
	client.GetConfig()
	if cached() != "trojan" {
		t.Fatal("cached body was not replaced together with its ETag")
	}
	next = reply{"", "vmess"}
	client.GetConfig()
	if cached() != "" {
		t.Fatal("a response without ETag left a stale cached config")
	}
	next = reply{`"c"`, "ss"}
	client.GetConfig()
	client.ResetETags()
	if cached() != "" {
		t.Fatal("ResetETags kept the cached config")
	}
}

func TestPushTraffic_ServerError(t *testing.T) {
	ts, client := newTestServer(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
		w.Write([]byte("unavailable"))
	})
	defer ts.Close()

	data := map[int][2]int64{1: {100, 200}}
	err := client.PushTraffic(data)
	if err == nil {
		t.Fatal("expected error for 503")
	}
}

func TestClient_NodeTypeInQuery(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("node_type") != "vmess" {
			t.Errorf("node_type: got %q, want vmess", r.URL.Query().Get("node_type"))
		}
		json.NewEncoder(w).Encode(NodeConfig{Protocol: "vmess"})
	}))
	defer ts.Close()

	client := NewClient(config.PanelConfig{
		URL:      ts.URL,
		Token:    "tok",
		NodeID:   1,
		NodeType: "vmess",
	})
	client.GetConfig()
}

func TestStringOrArrayDecodeHook(t *testing.T) {
	// Test case: []interface{} -> StringOrArray
	input := map[string]interface{}{
		"padding_scheme": []interface{}{"stop=8", "0=30-30", "1=100-400"},
	}

	type TestConfig struct {
		PaddingScheme StringOrArray `json:"padding_scheme"`
	}

	var cfg TestConfig
	if err := decodeWeakRaw(input, &cfg); err != nil {
		t.Fatalf("decodeWeakRaw failed: %v", err)
	}

	want := "stop=8\n0=30-30\n1=100-400"
	if string(cfg.PaddingScheme) != want {
		t.Errorf("got %q, want %q", cfg.PaddingScheme, want)
	}
}

func TestStringOrArrayDecodeHook_String(t *testing.T) {
	// Test case: string -> StringOrArray
	input := map[string]interface{}{
		"padding_scheme": "stop=8\n0=30-30",
	}

	type TestConfig struct {
		PaddingScheme StringOrArray `json:"padding_scheme"`
	}

	var cfg TestConfig
	if err := decodeWeakRaw(input, &cfg); err != nil {
		t.Fatalf("decodeWeakRaw failed: %v", err)
	}

	want := "stop=8\n0=30-30"
	if string(cfg.PaddingScheme) != want {
		t.Errorf("got %q, want %q", cfg.PaddingScheme, want)
	}
}
