// Copyright 2026 The kasapi Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
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

	// domains are read-only via the delete verb
	if err := run([]string{"delete", "domain", "example.com"}); err == nil ||
		!strings.Contains(err.Error(), "read-only") {
		t.Fatalf("expected read-only error, got %v", err)
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
