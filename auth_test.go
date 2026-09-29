// Copyright 2026 The kasapi Authors
// SPDX-License-Identifier: Apache-2.0

package kasapi

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/johnnycube/kasapi/kasapitest"
)

func TestAuth_SessionLifetimeIsSent(t *testing.T) {
	srv := kasapitest.New(t, func(string, map[string]any) (string, string) { return "TRUE", "" })
	c, err := New(Config{
		Login: "w0123456", Password: "secret", SessionLifetime: 7200,
		APIEndpoint: srv.APIURL(), AuthEndpoint: srv.AuthURL(), HTTPClient: srv.Client(),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := c.Exec(context.Background(), "noop", nil); err != nil {
		t.Fatalf("Exec: %v", err)
	}
	if got := srv.SessionLifetime.Load(); got != 7200 {
		t.Fatalf("session_lifetime sent as %d, want 7200", got)
	}
}

func TestAuth_PlainAndWrongPassword(t *testing.T) {
	srv := kasapitest.New(t, func(string, map[string]any) (string, string) { return "TRUE", "" })
	newClient := func(password string, authType AuthType) *Client {
		c, err := New(Config{
			Login: "w0123456", Password: password, AuthType: authType,
			APIEndpoint: srv.APIURL(), AuthEndpoint: srv.AuthURL(), HTTPClient: srv.Client(),
		})
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		return c
	}

	if _, err := newClient("secret", AuthPlain).Exec(context.Background(), "noop", nil); err != nil {
		t.Fatalf("plain auth: %v", err)
	}

	_, err := newClient("wrong-password", AuthSHA1).Exec(context.Background(), "noop", nil)
	var apiErr *APIError
	if !errors.As(err, &apiErr) || apiErr.Code != "kas_login_incorrect" {
		t.Fatalf("expected kas_login_incorrect, got %v", err)
	}
	if !strings.Contains(err.Error(), "authentication failed") {
		t.Fatalf("error must name the failed step: %v", err)
	}
	if strings.Contains(err.Error(), "wrong-password") {
		t.Fatalf("error must not echo credentials: %v", err)
	}
}

func TestAuth_OTP(t *testing.T) {
	ctx := context.Background()
	srv := kasapitest.New(t, func(string, map[string]any) (string, string) { return "TRUE", "" })
	srv.OTP = "123456"

	newClient := func(otp func(context.Context) (string, error)) *Client {
		c, err := New(Config{
			Login: "w0123456", Password: "secret", OTP: otp,
			APIEndpoint: srv.APIURL(), AuthEndpoint: srv.AuthURL(), HTTPClient: srv.Client(),
		})
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		return c
	}

	asked := 0
	c := newClient(func(context.Context) (string, error) { asked++; return "123456", nil })
	if _, err := c.Exec(ctx, "noop", nil); err != nil {
		t.Fatalf("Exec with OTP: %v", err)
	}
	if _, err := c.Exec(ctx, "noop", nil); err != nil {
		t.Fatalf("second Exec: %v", err)
	}
	if asked != 1 {
		t.Fatalf("a live session must not ask again, asked %d times", asked)
	}
	// A new session needs a fresh PIN.
	c.mu.Lock()
	c.token = ""
	c.mu.Unlock()
	if _, err := c.Exec(ctx, "noop", nil); err != nil {
		t.Fatalf("Exec after session loss: %v", err)
	}
	if asked != 2 {
		t.Fatalf("re-authentication must ask again, asked %d times", asked)
	}

	var apiErr *APIError
	_, err := newClient(func(context.Context) (string, error) { return "000000", nil }).Exec(ctx, "noop", nil)
	if !errors.As(err, &apiErr) || apiErr.Code != "kas_2fa_incorrect" {
		t.Fatalf("wrong PIN: expected kas_2fa_incorrect, got %v", err)
	}
	_, err = newClient(nil).Exec(ctx, "noop", nil)
	if !errors.As(err, &apiErr) || apiErr.Code != "kas_2fa_incorrect" {
		t.Fatalf("missing PIN: expected kas_2fa_incorrect, got %v", err)
	}

	boom := errors.New("token device unplugged")
	_, err = newClient(func(context.Context) (string, error) { return "", boom }).Exec(ctx, "noop", nil)
	if !errors.Is(err, boom) {
		t.Fatalf("callback error must be returned, got %v", err)
	}
	_, err = newClient(func(context.Context) (string, error) { return "", nil }).Exec(ctx, "noop", nil)
	if err == nil || !strings.Contains(err.Error(), "must not be empty") {
		t.Fatalf("empty PIN must fail before the request, got %v", err)
	}
	if got := srv.AuthCalls.Load(); got != 4 {
		t.Fatalf("callback failures must not reach the server, auth calls: %d", got)
	}
}

func TestAuth_TokenShapes(t *testing.T) {
	ctx := context.Background()
	okAPI := kasapitest.Envelope(`<return>
  <item><key>Response</key><value>
    <item><key>ReturnString</key><value>TRUE</value></item>
    <item><key>ReturnInfo</key><value>fine</value></item>
  </value></item>
  <item><key>KasFloodDelay</key><value>0.01</value></item>
</return>`)

	// The token may arrive wrapped in a map under "Response".
	wrapped := `<r><return><item><key>Response</key><value>tok-in-map</value></item></return></r>`
	c := rawServer(t, wrapped, 200, okAPI)
	if ret, err := c.Exec(ctx, "noop", nil); err != nil || ret != "fine" {
		t.Fatalf("Exec: %v %v", ret, err)
	}
	if c.token != "tok-in-map" {
		t.Fatalf("token: %q", c.token)
	}

	c = rawServer(t, `<r><return></return></r>`, 200, okAPI)
	if _, err := c.Exec(ctx, "noop", nil); err == nil || !strings.Contains(err.Error(), "no session token") {
		t.Fatalf("empty token must fail, got %v", err)
	}
}

func TestIsSessionError(t *testing.T) {
	for _, code := range []string{"kas_auth_data_incorrect", "session_token_invalid", "session_expired"} {
		if !isSessionError(code) {
			t.Errorf("isSessionError(%s) = false", code)
		}
	}
	if isSessionError("kas_login_incorrect") || isSessionError("") {
		t.Error("isSessionError accepts a non-session code")
	}
}

func TestAuth_WaitsForFloodWindow(t *testing.T) {
	f := kasapitest.New(t, func(string, map[string]any) (string, string) { return "TRUE", "" })
	c := newTestClient(t, f)
	c.notBefore = time.Now().Add(time.Hour)

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if _, err := c.Exec(ctx, "noop", nil); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected the context error, got %v", err)
	}
	if got := f.AuthCalls.Load(); got != 0 {
		t.Fatalf("no request may leave inside the flood window, auth calls: %d", got)
	}
}
