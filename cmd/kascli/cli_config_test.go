// Copyright 2026 The kasapi Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/johnnycube/kasapi/kasapitest"
)

func TestCLI_ConfigLifecycle(t *testing.T) {
	t.Setenv("KASCONFIG", filepath.Join(t.TempDir(), "config"))

	// set two contexts; first becomes current automatically
	capture(t, "config", "set-context", "prod", "--login", "w0123456", "--password", "s3cret")
	capture(t, "config", "set-context", "staging", "--login", "w0999999", "--auth-type", "plain")

	out := capture(t, "config", "get-contexts")
	if !strings.Contains(out, "*") || !strings.Contains(out, "staging") || !strings.Contains(out, "plain") {
		t.Fatalf("get-contexts:\n%s", out)
	}

	out = capture(t, "config", "current-context")
	if strings.TrimSpace(out) != "prod" {
		t.Fatalf("current-context: %q", out)
	}

	// view redacts; --raw shows
	out = capture(t, "config", "view")
	if !strings.Contains(out, "password: REDACTED") || strings.Contains(out, "s3cret") {
		t.Fatalf("view must redact:\n%s", out)
	}
	out = capture(t, "config", "view", "--raw")
	if !strings.Contains(out, "s3cret") {
		t.Fatalf("view --raw must include password:\n%s", out)
	}

	capture(t, "config", "use-context", "staging")
	out = capture(t, "config", "current-context")
	if strings.TrimSpace(out) != "staging" {
		t.Fatalf("after use-context: %q", out)
	}
	if err := run([]string{"config", "use-context", "missing"}); err == nil {
		t.Fatal("use-context with unknown name must fail")
	}

	// patching one field keeps the others (kubectl behavior)
	capture(t, "config", "set-context", "prod", "--auth-type", "plain")
	out = capture(t, "config", "view", "--raw")
	if !strings.Contains(out, "s3cret") {
		t.Fatalf("patching auth-type must keep password:\n%s", out)
	}

	capture(t, "config", "delete-context", "prod")
	out = capture(t, "config", "get-contexts", "--no-headers")
	if strings.Contains(out, "prod") {
		t.Fatalf("prod not deleted:\n%s", out)
	}
}

func TestCLI_GetMailAndSubdomains(t *testing.T) {
	setupCLI(t, func(action string, params map[string]any) (string, string) {
		switch action {
		case "get_mailaccounts":
			return "<item>" +
				kasapitest.MapItem("mail_login", "m1") +
				kasapitest.MapItem("mail_adresses", "info@example.com") +
				kasapitest.MapItem("mail_responder", "Y") +
				kasapitest.MapItem("mail_copy_adress", "a@x.org,b@x.org") +
				"</item>", ""
		case "get_mailforwards":
			return "<item>" +
				kasapitest.MapItem("mail_forward_adress", "sales@example.com") +
				kasapitest.MapItem("mail_forward_targets", "a@x.org") +
				"</item>", ""
		case "get_subdomains":
			return "<item>" +
				kasapitest.MapItem("subdomain_name", "blog.example.com") +
				kasapitest.MapItem("subdomain_path", "/blog/") +
				"</item>", ""
		}
		return "", "unknown_action"
	})

	out := capture(t, "get", "ma", "-o", "wide")
	if !strings.Contains(out, "COPY-ADDRESSES") || !strings.Contains(out, "a@x.org,b@x.org") {
		t.Fatalf("mailaccounts wide:\n%s", out)
	}
	out = capture(t, "get", "mf")
	if !strings.Contains(out, "sales@example.com") {
		t.Fatalf("mailforwards:\n%s", out)
	}
	out = capture(t, "get", "sub", "-o", "name")
	if strings.TrimSpace(out) != "subdomain/blog.example.com" {
		t.Fatalf("subdomains name output: %q", out)
	}
}

func TestCLI_DeleteOtherResources(t *testing.T) {
	setupCLI(t, func(action string, params map[string]any) (string, string) {
		switch action {
		case "delete_mailaccount", "delete_mailforward", "delete_subdomain":
			return "TRUE", ""
		}
		return "", "unknown_action"
	})

	for _, tc := range [][2]string{
		{"mailaccount", "m1"},
		{"mailforward", "sales@example.com"},
		{"subdomain", "blog.example.com"},
	} {
		out := capture(t, "delete", tc[0], tc[1])
		if !strings.Contains(out, tc[0]+"/"+tc[1]+" deleted") {
			t.Fatalf("delete %s output: %q", tc[0], out)
		}
	}

	// domains have no delete verb
	if err := run([]string{"delete", "domain", "example.com"}); err == nil ||
		!strings.Contains(err.Error(), "cannot be deleted") {
		t.Fatalf("expected a refusal, got %v", err)
	}
}

func TestCLI_UsageErrors(t *testing.T) {
	if err := run([]string{}); err == nil {
		t.Fatal("no command must fail")
	}
	if err := run([]string{"frobnicate"}); err == nil {
		t.Fatal("unknown verb must fail")
	}
	if err := run([]string{"get"}); err == nil {
		t.Fatal("get without resource must fail")
	}
	if err := run([]string{"delete", "dnsrecord"}); err == nil {
		t.Fatal("delete without id must fail")
	}
	if err := run([]string{"exec"}); err == nil {
		t.Fatal("exec without action must fail")
	}
	if err := run([]string{"exec", "get_x", "novalue"}); err == nil {
		t.Fatal("exec with malformed param must fail")
	}
	if err := run([]string{"config"}); err == nil {
		t.Fatal("config without subcommand must fail")
	}
	if err := run([]string{"config", "bogus"}); err == nil {
		t.Fatal("unknown config subcommand must fail")
	}
	t.Setenv("KASCONFIG", filepath.Join(t.TempDir(), "config"))
	t.Setenv("KAS_LOGIN", "")
	t.Setenv("KAS_PASSWORD", "")
	if err := run([]string{"get", "domains"}); err == nil ||
		!strings.Contains(err.Error(), "no credentials") {
		t.Fatalf("expected credentials error, got %v", err)
	}
}

func TestCLI_ConfigTwoFactor(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config")
	t.Setenv("KASCONFIG", path)

	capture(t, "config", "set-context", "prod", "--login", "w0123456", "--two-factor")
	out := capture(t, "config", "view")
	if !strings.Contains(out, "two-factor: true") {
		t.Fatalf("view:\n%s", out)
	}
	out = capture(t, "config", "get-contexts", "-o", "wide")
	if !strings.Contains(out, "TWO-FACTOR") || !strings.Contains(out, "true") {
		t.Fatalf("get-contexts wide:\n%s", out)
	}
	if out := capture(t, "config", "get-contexts"); strings.Contains(out, "TWO-FACTOR") {
		t.Fatalf("wide column leaked into the default table:\n%s", out)
	}
	if out := capture(t, "config", "get-contexts", "-o", "json"); !strings.Contains(out, `"twoFactor": true`) {
		t.Fatalf("get-contexts json:\n%s", out)
	}

	// Patching another field keeps the flag; --two-factor=false clears it.
	capture(t, "config", "set-context", "prod", "--auth-type", "plain")
	if out := capture(t, "config", "view"); !strings.Contains(out, "two-factor: true") {
		t.Fatalf("patching auth-type must keep two-factor:\n%s", out)
	}
	capture(t, "config", "set-context", "prod", "--two-factor=false")
	if out := capture(t, "config", "view"); strings.Contains(out, "two-factor") {
		t.Fatalf("two-factor not cleared:\n%s", out)
	}
	data, err := os.ReadFile(path)
	if err != nil || strings.Contains(string(data), "two-factor") {
		t.Fatalf("an unset flag must not be written: %v\n%s", err, data)
	}
}

func TestCLI_ConfigSetContextErrors(t *testing.T) {
	t.Setenv("KASCONFIG", filepath.Join(t.TempDir(), "config"))

	wantErr(t, "--login is required", "config", "set-context", "new")
	wantErr(t, "--auth-type must be", "config", "set-context", "new", "--login", "w1", "--auth-type", "md5")
	wantErr(t, "mutually exclusive", "config", "set-context", "new", "--login", "w1", "--password", "x", "--password-stdin")
	wantErr(t, "accepts 1 arg(s)", "config", "set-context")
	wantErr(t, "current-context is not set", "config", "current-context")
	wantErr(t, "not found", "config", "delete-context", "missing")
	wantErr(t, "accepts 1 arg(s)", "config", "delete-context")
	wantErr(t, "accepts 1 arg(s)", "config", "use-context")

	// A config file that cannot be written.
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "file"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("KASCONFIG", filepath.Join(dir, "file", "config"))
	wantErr(t, "config", "config", "set-context", "new", "--login", "w1")
}

func TestCLI_ConfigSetContextPasswordStdin(t *testing.T) {
	t.Setenv("KASCONFIG", filepath.Join(t.TempDir(), "config"))

	old := os.Stdin
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdin = r
	t.Cleanup(func() { os.Stdin = old })
	if _, err := w.WriteString("from-stdin\n"); err != nil {
		t.Fatal(err)
	}
	_ = w.Close()

	capture(t, "config", "set-context", "prod", "--login", "w0123456", "--password-stdin", "--current")
	if out := capture(t, "config", "view", "--raw"); !strings.Contains(out, "password: from-stdin") {
		t.Fatalf("password not stored:\n%s", out)
	}
	if out := capture(t, "config", "current-context"); strings.TrimSpace(out) != "prod" {
		t.Fatalf("--current: %q", out)
	}

	// An empty stdin is an error, not an empty password.
	r2, w2, _ := os.Pipe()
	_ = w2.Close()
	os.Stdin = r2
	wantErr(t, "reading password from stdin", "config", "set-context", "prod", "--password-stdin")
	if out := capture(t, "config", "view", "--raw"); !strings.Contains(out, "password: from-stdin") {
		t.Fatalf("a failed update must keep the stored password:\n%s", out)
	}
}

func TestCLI_ConfigDeleteCurrentContext(t *testing.T) {
	t.Setenv("KASCONFIG", filepath.Join(t.TempDir(), "config"))
	capture(t, "config", "set-context", "only", "--login", "w1")
	out := capture(t, "config", "delete-context", "only")
	if !strings.Contains(out, "only") {
		t.Fatalf("delete-context output: %q", out)
	}
	wantErr(t, "current-context is not set", "config", "current-context")
	if out := capture(t, "config", "get-contexts", "-o", "json"); strings.TrimSpace(out) != "[]" {
		t.Fatalf("contexts left: %q", out)
	}
}
