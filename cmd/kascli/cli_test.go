// Copyright 2026 The kasapi Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/johnnycube/kasapi/internal/kasconfig"
	"github.com/johnnycube/kasapi/kasapitest"
)

// setupCLI starts a fake KAS server, writes a kasconfig with one context and
// points the CLI at both via env.
func setupCLI(t *testing.T, handler kasapitest.Handler) {
	t.Helper()
	srv := kasapitest.New(t, handler)
	t.Setenv("KAS_API_ENDPOINT", srv.APIURL())
	t.Setenv("KAS_AUTH_ENDPOINT", srv.AuthURL())
	t.Setenv("KAS_LOGIN", "")
	t.Setenv("KAS_PASSWORD", "")
	t.Setenv("KAS_AUTH_TYPE", "")

	path := filepath.Join(t.TempDir(), "config")
	cfg := &kasconfig.Config{CurrentContext: "test"}
	cfg.Set(kasconfig.Context{Name: "test", Login: "w0123456", Password: "secret"})
	if err := cfg.Save(path); err != nil {
		t.Fatalf("saving kasconfig: %v", err)
	}
	t.Setenv("KASCONFIG", path)
}

// capture runs the CLI and returns its stdout.
func capture(t *testing.T, args ...string) string {
	t.Helper()
	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	os.Stdout = w
	runErr := run(args)
	_ = w.Close()
	os.Stdout = old
	out, _ := io.ReadAll(r)
	if runErr != nil {
		t.Fatalf("run(%v): %v\noutput:\n%s", args, runErr, out)
	}
	return string(out)
}

func dnsHandler(t *testing.T) kasapitest.Handler {
	return func(action string, params map[string]any) (string, string) {
		switch action {
		case "get_domains":
			return "<item>" +
				kasapitest.MapItem("domain_name", "example.com") +
				kasapitest.MapItem("domain_path", "/web/") +
				"</item>", ""
		case "get_dns_settings":
			return `<item>` +
				kasapitest.MapItem("record_id", "11") +
				kasapitest.MapItem("record_name", "www") +
				kasapitest.MapItem("record_type", "A") +
				kasapitest.MapItem("record_data", "203.0.113.10") +
				kasapitest.MapItem("record_aux", "0") +
				kasapitest.MapItem("record_changeable", "Y") +
				`</item>`, ""
		case "delete_dns_settings":
			if params["record_id"] != "11" {
				return "", "record_id_not_found"
			}
			return "TRUE", ""
		}
		return "", "unknown_action"
	}
}

func TestCLI_GetDomains_Table(t *testing.T) {
	setupCLI(t, dnsHandler(t))
	out := capture(t, "get", "domains")
	if !strings.Contains(out, "NAME") || !strings.Contains(out, "example.com") {
		t.Fatalf("unexpected table output:\n%s", out)
	}
	// --no-headers
	out = capture(t, "get", "domains", "--no-headers")
	if strings.Contains(out, "NAME") {
		t.Fatalf("headers not suppressed:\n%s", out)
	}
}

func TestCLI_GetDNS_AllFormats(t *testing.T) {
	setupCLI(t, dnsHandler(t))

	// table with flag after resource (interspersed parsing)
	out := capture(t, "get", "dns", "--zone", "example.com")
	if !strings.Contains(out, "www") || !strings.Contains(out, "203.0.113.10") {
		t.Fatalf("table output:\n%s", out)
	}
	if strings.Contains(out, "CHANGEABLE") {
		t.Fatalf("wide column leaked into default table:\n%s", out)
	}

	// wide
	out = capture(t, "get", "dnsrecords", "--zone", "example.com", "-o", "wide")
	if !strings.Contains(out, "CHANGEABLE") || !strings.Contains(out, "ZONE") {
		t.Fatalf("wide output:\n%s", out)
	}

	// json round-trips
	out = capture(t, "get", "dns", "--zone", "example.com", "-o", "json")
	var items []map[string]any
	if err := json.Unmarshal([]byte(out), &items); err != nil {
		t.Fatalf("json output not parseable: %v\n%s", err, out)
	}
	if len(items) != 1 || items[0]["id"] != "11" || items[0]["changeable"] != true {
		t.Fatalf("json content: %#v", items)
	}

	// yaml
	out = capture(t, "get", "dns", "--zone", "example.com", "-o", "yaml")
	if !strings.Contains(out, "- aux: 0") || !strings.Contains(out, "type: A") {
		t.Fatalf("yaml output:\n%s", out)
	}

	// name
	out = capture(t, "get", "dns", "--zone", "example.com", "-o", "name")
	if strings.TrimSpace(out) != "dnsrecord/11" {
		t.Fatalf("name output: %q", out)
	}
}

func TestCLI_DeleteDNSRecord(t *testing.T) {
	setupCLI(t, dnsHandler(t))
	out := capture(t, "delete", "dnsrecord", "11")
	if !strings.Contains(out, "dnsrecord/11 deleted") {
		t.Fatalf("delete output: %q", out)
	}
}

func TestCLI_ExecRaw(t *testing.T) {
	setupCLI(t, func(action string, params map[string]any) (string, string) {
		if action != "get_ftpusers" {
			return "", "unknown_action"
		}
		return kasapitest.MapItem("ftp_user", "f012345"), ""
	})
	out := capture(t, "exec", "get_ftpusers")
	var m map[string]any
	if err := json.Unmarshal([]byte(out), &m); err != nil || m["ftp_user"] != "f012345" {
		t.Fatalf("exec output: %v %q", err, out)
	}

	// legacy shorthand: bare action routes to exec
	out = capture(t, "get_ftpusers", "-o", "yaml")
	if !strings.Contains(out, "ftp_user: f012345") {
		t.Fatalf("shorthand exec yaml: %q", out)
	}

	// shorthand still works with a global flag (and its value) ahead of the
	// action: the action must be found past "--context test".
	out = capture(t, "--context", "test", "get_ftpusers")
	if !strings.Contains(out, "f012345") {
		t.Fatalf("shorthand after global flag: %q", out)
	}
}

func TestCLI_BadOutputFormat(t *testing.T) {
	setupCLI(t, dnsHandler(t))
	if err := run([]string{"get", "domains", "-o", "xml"}); err == nil ||
		!strings.Contains(err.Error(), "allowed formats") {
		t.Fatalf("expected printer error, got %v", err)
	}
}

func TestCLI_UnknownResource(t *testing.T) {
	if err := run([]string{"get", "pods"}); err == nil ||
		!strings.Contains(err.Error(), "resource type") {
		t.Fatalf("expected resource error, got %v", err)
	}
}

func TestCLI_VersionAndAPIResources(t *testing.T) {
	out := capture(t, "version")
	if !strings.Contains(out, "kascli version") {
		t.Fatalf("version output: %q", out)
	}
	out = capture(t, "api-resources", "-o", "json")
	var items []map[string]any
	if err := json.Unmarshal([]byte(out), &items); err != nil || len(items) != 5 {
		t.Fatalf("api-resources json: %v %q", err, out)
	}
	out = capture(t, "api-resources", "--no-headers")
	if strings.Contains(out, "SHORTNAMES") {
		t.Fatalf("headers not suppressed: %q", out)
	}
}
