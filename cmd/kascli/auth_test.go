// Copyright 2026 The kasapi Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"os"
	"os/exec"
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

func TestLegacyExecRewrite(t *testing.T) {
	for _, tc := range []struct{ in, want []string }{
		{[]string{"get_ftpusers"}, []string{"exec", "get_ftpusers"}},
		{[]string{"-o", "yaml", "get_ftpusers", "a=b"}, []string{"-o", "yaml", "exec", "get_ftpusers", "a=b"}},
		{[]string{"--no-headers", "get_x"}, []string{"--no-headers", "exec", "get_x"}},
		{[]string{"--timeout", "5s", "--context", "p", "get_x"}, []string{"--timeout", "5s", "--context", "p", "exec", "get_x"}},
		{[]string{"--output=json", "get_x"}, []string{"--output=json", "exec", "get_x"}},
		{[]string{"get", "domains"}, []string{"get", "domains"}},
		{[]string{"exec", "get_x"}, []string{"exec", "get_x"}},
		{[]string{"create", "dns", "--data", "v=spf1_x"}, []string{"create", "dns", "--data", "v=spf1_x"}},
		{[]string{"--context"}, []string{"--context"}},
		{nil, nil},
	} {
		if got := legacyExecRewrite(tc.in); !reflect.DeepEqual(got, tc.want) {
			t.Errorf("legacyExecRewrite(%v) = %v, want %v", tc.in, got, tc.want)
		}
	}
	if tok, idx := firstPositional([]string{"-o", "json"}); tok != "" || idx != -1 {
		t.Fatalf("firstPositional without positional: %q %d", tok, idx)
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

func TestCLI_PasswordPrompt(t *testing.T) {
	setupFake(t, map[string]string{"get_domains": entry("domain_name", "example.com")})
	t.Setenv("KASCONFIG", filepath.Join(t.TempDir(), "config"))
	t.Setenv("KAS_LOGIN", "w0123456")

	setStdin(t, "secret\n")
	if out := capture(t, "get", "domains"); !strings.Contains(out, "example.com") {
		t.Fatalf("prompted password:\n%s", out)
	}
	setStdin(t, "")
	wantErr(t, "reading input", "get", "domains")
	setStdin(t, "wrong\n")
	wantErr(t, "kas_login_incorrect", "get", "domains")
}

func TestCLI_CredentialSources(t *testing.T) {
	setupFake(t, map[string]string{"get_domains": entry("domain_name", "example.com")})

	// The environment overrides the context.
	t.Setenv("KAS_PASSWORD", "wrong")
	wantErr(t, "kas_login_incorrect", "get", "domains")
	t.Setenv("KAS_PASSWORD", "secret")
	t.Setenv("KAS_AUTH_TYPE", "plain")
	capture(t, "get", "domains")
	t.Setenv("KAS_AUTH_TYPE", "md5")
	wantErr(t, "unsupported auth type", "get", "domains")
	t.Setenv("KAS_AUTH_TYPE", "")

	wantErr(t, `context "missing" not found`, "--context", "missing", "get", "domains")

	path := filepath.Join(t.TempDir(), "config")
	if err := os.WriteFile(path, []byte("contexts: [\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("KASCONFIG", path)
	wantErr(t, "parsing", "get", "domains")
	wantErr(t, "parsing", "config", "get-contexts")
	wantErr(t, "parsing", "config", "current-context")
	wantErr(t, "parsing", "config", "use-context", "x")
	wantErr(t, "parsing", "config", "set-context", "x", "--login", "w1")
	wantErr(t, "parsing", "config", "delete-context", "x")
	wantErr(t, "parsing", "config", "view")
}

// TestMain_ExitCode runs the binary: main ends the process.
func TestMain_ExitCode(t *testing.T) {
	if os.Getenv("KASCLI_RUN_MAIN") == "1" {
		os.Args = append([]string{"kascli"}, strings.Fields(os.Getenv("KASCLI_ARGS"))...)
		main()
		return
	}
	runMain := func(args string) (string, error) {
		cmd := exec.Command(os.Args[0], "-test.run=^TestMain_ExitCode$")
		cmd.Env = append(os.Environ(), "KASCLI_RUN_MAIN=1", "KASCLI_ARGS="+args,
			"KASCONFIG="+filepath.Join(t.TempDir(), "config"))
		out, err := cmd.CombinedOutput()
		return string(out), err
	}

	out, err := runMain("version")
	if err != nil || !strings.Contains(out, "kascli version") {
		t.Fatalf("version: %v\n%s", err, out)
	}

	out, err = runMain("get pods")
	var exitErr *exec.ExitError
	if !errorsAs(err, &exitErr) || exitErr.ExitCode() != 1 {
		t.Fatalf("a failing command must exit with 1, got %v\n%s", err, out)
	}
	if !strings.Contains(out, "error: the server doesn't have a resource type") {
		t.Fatalf("the error must be printed:\n%s", out)
	}
}
