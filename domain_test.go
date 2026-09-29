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

func TestDomains_List(t *testing.T) {
	f := kasapitest.New(t, func(action string, params map[string]any) (string, string) {
		if action != "get_domains" {
			return "", "unknown_action"
		}
		return `
 <item>
  <item><key>domain_name</key><value>example.com</value></item>
  <item><key>domain_path</key><value>/web/</value></item>
 </item>
 <item>
  <item><key>domain_name</key><value>example.org</value></item>
  <item><key>domain_path</key><value>/org/</value></item>
 </item>`, ""
	})
	c := newTestClient(t, f)

	domains, err := c.Domains.List(context.Background())
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(domains) != 2 || domains[0].Name != "example.com" || domains[1].Path != "/org/" {
		t.Fatalf("unexpected domains: %+v", domains)
	}
}

func TestDomains_GetNotFound(t *testing.T) {
	f := kasapitest.New(t, func(action string, params map[string]any) (string, string) {
		return "<item>" + kasapitest.MapItem("domain_name", "example.com") +
			kasapitest.MapItem("domain_path", "/web/") + "</item>", ""
	})
	c := newTestClient(t, f)

	if _, err := c.Domains.Get(context.Background(), "EXAMPLE.com"); err != nil {
		t.Fatalf("Get must be case-insensitive: %v", err)
	}
	if _, err := c.Domains.Get(context.Background(), "nope.de"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
}

func domainEntry(name string) string {
	return entry(
		"domain_name", name,
		"domain_redirect_status", "0",
		"domain_path", "/"+name+"/",
		"dkim_selector", "abc190101010000",
		"ssl_certificate_sni_is_active", "j",
		"ssl_certificate_sni_key", "-----BEGIN PRIVATE KEY-----",
		"ssl_certificate_sni_crt", "-----BEGIN CERTIFICATE-----",
		"ssl_certificate_sni_type", "custom",
		"ssl_certificate_sni_force_https", "N",
		"ssl_certificate_sni_hsts_max_age", "-1",
		"php_version", "7.4",
		"php_deprecated", "Y",
		"is_active", "N",
		"in_progress", "TRUE",
	)
}

func TestDomains_ListEmptyAndFault(t *testing.T) {
	ctx := context.Background()
	c, _ := newFake(t, map[string]string{"get_domains": ""})
	if domains, err := c.Domains.List(ctx); err != nil || len(domains) != 0 {
		t.Fatalf("empty: %v %v", domains, err)
	}
	c, _ = newFake(t, map[string]string{"get_domains": "!kas_error"})
	if _, err := c.Domains.List(ctx); err == nil || !strings.Contains(err.Error(), "listing domains") {
		t.Fatalf("fault must be returned with context, got %v", err)
	}
}

func TestDomains_GetFiltersOnTheServer(t *testing.T) {
	ctx := context.Background()
	c, rec := newFake(t, map[string]string{"get_domains": domainEntry("example.com")})

	d, err := c.Domains.Get(ctx, "EXAMPLE.com")
	if err != nil || d.Name != "example.com" {
		t.Fatalf("Get: %+v %v", d, err)
	}
	wantParams(t, rec.last(t, "get_domains"), map[string]string{"domain_name": "EXAMPLE.com"})

	if _, err := c.Domains.Get(ctx, "other.com"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
	if _, err := c.Domains.Get(ctx, ""); err == nil {
		t.Fatal("Get without name must fail")
	}
	c, _ = newFake(t, map[string]string{"get_domains": "!domain_not_found_in_kas"})
	if _, err := c.Domains.Get(ctx, "gone.com"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("not-found fault: expected ErrNotFound, got %v", err)
	}
	c, _ = newFake(t, map[string]string{"get_domains": "!kas_error"})
	if _, err := c.Domains.Get(ctx, "x.com"); err == nil || errors.Is(err, ErrNotFound) ||
		!strings.Contains(err.Error(), "reading domain x.com") {
		t.Fatalf("other faults must be returned with context, got %v", err)
	}
}
