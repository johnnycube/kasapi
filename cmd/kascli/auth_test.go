// Copyright 2026 The kasapi Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/johnnycube/kasapi/internal/kasconfig"
	"github.com/johnnycube/kasapi/kasapitest"
)

// setupOTP starts a fake KAS server that requires the one-time PIN 123456.
func setupOTP(t *testing.T, twoFactor bool) {
	t.Helper()
	srv := kasapitest.New(t, func(string, map[string]any) (string, string) {
		return entry("domain_name", "example.com", "domain_path", "/web/"), ""
	})
	srv.OTP = "123456"
	t.Setenv("KAS_API_ENDPOINT", srv.APIURL())
	t.Setenv("KAS_AUTH_ENDPOINT", srv.AuthURL())
	for _, env := range []string{"KAS_LOGIN", "KAS_PASSWORD", "KAS_AUTH_TYPE", "KAS_OTP"} {
		t.Setenv(env, "")
	}
	path := filepath.Join(t.TempDir(), "config")
	cfg := &kasconfig.Config{CurrentContext: "test"}
	cfg.Set(kasconfig.Context{Name: "test", Login: "w0123456", Password: "secret", TwoFactor: twoFactor})
	if err := cfg.Save(path); err != nil {
		t.Fatalf("saving kasconfig: %v", err)
	}
	t.Setenv("KASCONFIG", path)
}

func TestCLI_OTP(t *testing.T) {
	setupOTP(t, false)

	// Without a PIN the account rejects the login.
	wantErr(t, "kas_2fa_incorrect", "get", "domains")

	// By flag, before or after the verb.
	if out := capture(t, "--otp", "123456", "get", "domains"); !strings.Contains(out, "example.com") {
		t.Fatalf("--otp before the verb:\n%s", out)
	}
	if out := capture(t, "get", "domains", "--otp", "123456"); !strings.Contains(out, "example.com") {
		t.Fatalf("--otp after the verb:\n%s", out)
	}
	wantErr(t, "kas_2fa_incorrect", "get", "domains", "--otp", "000000")

	// By environment; the flag wins over it.
	t.Setenv("KAS_OTP", "123456")
	if out := capture(t, "get", "domains"); !strings.Contains(out, "example.com") {
		t.Fatalf("KAS_OTP:\n%s", out)
	}
	t.Setenv("KAS_OTP", "000000")
	if out := capture(t, "get", "domains", "--otp", "123456"); !strings.Contains(out, "example.com") {
		t.Fatalf("--otp must win over KAS_OTP:\n%s", out)
	}
}

func TestCLI_OTPPrompt(t *testing.T) {
	// A context marked two-factor asks for the PIN.
	setupOTP(t, true)
	setStdin(t, "123456\n")
	if out := capture(t, "get", "domains"); !strings.Contains(out, "example.com") {
		t.Fatalf("prompted PIN:\n%s", out)
	}
	setStdin(t, "")
	wantErr(t, "obtaining one-time PIN", "get", "domains")

	// Password and PIN are read from the same stream, in that order.
	t.Setenv("KASCONFIG", filepath.Join(t.TempDir(), "config"))
	capture(t, "config", "set-context", "prompted", "--login", "w0123456", "--two-factor")
	setStdin(t, "secret\n123456\n")
	if out := capture(t, "get", "domains"); !strings.Contains(out, "example.com") {
		t.Fatalf("prompted password and PIN:\n%s", out)
	}
}

func TestCLI_ExecShorthandSkipsOTPValue(t *testing.T) {
	// "--otp 12_34" must not be taken for a bare action name.
	got := legacyExecRewrite([]string{"--otp", "12_34", "get", "domains"})
	if !reflect.DeepEqual(got, []string{"--otp", "12_34", "get", "domains"}) {
		t.Fatalf("got %v", got)
	}
	got = legacyExecRewrite([]string{"--otp", "123456", "get_domains"})
	if !reflect.DeepEqual(got, []string{"--otp", "123456", "exec", "get_domains"}) {
		t.Fatalf("got %v", got)
	}
}

func TestOTPSource(t *testing.T) {
	ctx := context.Background()
	if otpSource("w1", "", false) != nil {
		t.Fatal("an account without 2FA must not get a callback")
	}

	// A given PIN serves one login; the next one asks.
	src := otpSource("w1", "123456", false)
	if pin, err := src(ctx); err != nil || pin != "123456" {
		t.Fatalf("first login: %q %v", pin, err)
	}
	setStdin(t, "654321\n")
	if pin, err := src(ctx); err != nil || pin != "654321" {
		t.Fatalf("a used PIN must not be sent again: %q %v", pin, err)
	}

	setStdin(t, "111111\n222222\n")
	src = otpSource("w1", "", true)
	for _, want := range []string{"111111", "222222"} {
		if pin, err := src(ctx); err != nil || pin != want {
			t.Fatalf("prompted PIN: %q %v, want %q", pin, err, want)
		}
	}
}

func TestPromptSecretAndReadSecretLine(t *testing.T) {
	for input, want := range map[string]string{
		"secret\n": "secret", "secret\r\n": "secret", "no newline": "no newline", " spaced \n": " spaced ",
	} {
		setStdin(t, input)
		if got, err := readSecretLine(); err != nil || got != want {
			t.Errorf("readSecretLine(%q) = %q, %v; want %q", input, got, err, want)
		}
	}
	for _, input := range []string{"", "\n", "\r\n"} {
		setStdin(t, input)
		if _, err := readSecretLine(); err == nil {
			t.Errorf("readSecretLine(%q) must fail", input)
		}
	}

	// Under "go test" stdin is no terminal, so the prompt reads a line.
	setStdin(t, "from-prompt\n")
	if got, err := promptSecret("Password"); err != nil || got != "from-prompt" {
		t.Fatalf("promptSecret: %q %v", got, err)
	}
}
