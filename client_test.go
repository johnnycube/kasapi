// Copyright 2026 The kasapi Authors
// SPDX-License-Identifier: Apache-2.0

package kasapi

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/johnnycube/kasapi/kasapitest"
)

func newTestClient(t *testing.T, f *kasapitest.Server) *Client {
	c, err := New(Config{
		Login:        "w0123456",
		Password:     "secret",
		AuthType:     AuthSHA1,
		APIEndpoint:  f.APIURL(),
		AuthEndpoint: f.AuthURL(),
		HTTPClient:   f.Client(),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return c
}

func TestExec_AuthenticatesOnceAndReusesSession(t *testing.T) {
	f := kasapitest.New(t, func(action string, params map[string]any) (string, string) {
		return kasapitest.MapItem("ok", "1"), ""
	})
	c := newTestClient(t, f)

	for i := 0; i < 3; i++ {
		if _, err := c.Exec(context.Background(), "noop", nil); err != nil {
			t.Fatalf("Exec %d: %v", i, err)
		}
	}
	if got := f.AuthCalls.Load(); got != 1 {
		t.Fatalf("expected 1 auth call, got %d", got)
	}
	if got := f.APICalls.Load(); got != 3 {
		t.Fatalf("expected 3 api calls, got %d", got)
	}
}

func TestExec_FaultBecomesAPIError(t *testing.T) {
	f := kasapitest.New(t, func(action string, params map[string]any) (string, string) {
		return "", "zone_not_found"
	})
	c := newTestClient(t, f)

	_, err := c.Exec(context.Background(), "get_dns_settings", map[string]any{"zone_host": "x.de."})
	var apiErr *APIError
	if !errors.As(err, &apiErr) || apiErr.Code != "zone_not_found" {
		t.Fatalf("expected APIError zone_not_found, got %v", err)
	}
}

func TestExec_RetriesOnFloodProtection(t *testing.T) {
	first := true
	f := kasapitest.New(t, func(action string, params map[string]any) (string, string) {
		if first {
			first = false
			return "", "flood_protection"
		}
		return kasapitest.MapItem("ok", "1"), ""
	})
	c := newTestClient(t, f)

	start := time.Now()
	if _, err := c.Exec(context.Background(), "noop", nil); err != nil {
		t.Fatalf("Exec: %v", err)
	}
	if got := f.APICalls.Load(); got != 2 {
		t.Fatalf("expected 2 attempts, got %d", got)
	}
	if elapsed := time.Since(start); elapsed < 1900*time.Millisecond {
		t.Fatalf("expected backoff before retry, elapsed only %v", elapsed)
	}
}

func TestExec_ReauthenticatesOnExpiredSession(t *testing.T) {
	f := kasapitest.New(t, func(action string, params map[string]any) (string, string) {
		return kasapitest.MapItem("ok", "1"), ""
	})
	c := newTestClient(t, f)

	if _, err := c.Exec(context.Background(), "noop", nil); err != nil {
		t.Fatalf("Exec: %v", err)
	}
	// Corrupt the cached token; the server answers session_expired and the
	// client must re-auth transparently.
	c.mu.Lock()
	c.token = "stale-token"
	c.mu.Unlock()

	if _, err := c.Exec(context.Background(), "noop", nil); err != nil {
		t.Fatalf("Exec after expiry: %v", err)
	}
	if got := f.AuthCalls.Load(); got != 2 {
		t.Fatalf("expected re-auth (2 auth calls), got %d", got)
	}
}

func TestExec_EmptyActionAndCancelledContext(t *testing.T) {
	f := kasapitest.New(t, func(action string, params map[string]any) (string, string) {
		return kasapitest.MapItem("ok", "1"), ""
	})
	c := newTestClient(t, f)

	if _, err := c.Exec(context.Background(), "", nil); err == nil {
		t.Fatal("empty action must fail")
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := c.Exec(ctx, "noop", nil); err == nil {
		t.Fatal("cancelled context must fail")
	}
}

func TestExec_ConcurrentUseIsSerializedAndSafe(t *testing.T) {
	f := kasapitest.New(t, func(action string, params map[string]any) (string, string) {
		return kasapitest.MapItem("ok", "1"), ""
	})
	c := newTestClient(t, f)

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := c.Exec(context.Background(), "noop", nil); err != nil {
				t.Errorf("concurrent Exec: %v", err)
			}
		}()
	}
	wg.Wait()
	if got := f.AuthCalls.Load(); got != 1 {
		t.Fatalf("expected a single shared auth, got %d", got)
	}
	if got := f.APICalls.Load(); got != 8 {
		t.Fatalf("expected 8 api calls, got %d", got)
	}
}

func TestNew_Validation(t *testing.T) {
	if _, err := New(Config{}); err == nil {
		t.Fatal("expected error for missing credentials")
	}
	if _, err := New(Config{Login: "w1", Password: "p", AuthType: "md5"}); err == nil {
		t.Fatal("expected error for unsupported auth type")
	}
	c, err := New(Config{Login: "w1", Password: "p", SessionLifetime: 99999})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if c.cfg.SessionLifetime != 3600 {
		t.Fatalf("session lifetime not clamped: %d", c.cfg.SessionLifetime)
	}
}
