// Copyright 2026 The kasapi Authors
// SPDX-License-Identifier: Apache-2.0

package kasapi

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/johnnycube/kasapi/kasapitest"
)

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
