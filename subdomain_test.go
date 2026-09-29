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

func TestSubdomains_ListCreateDelete(t *testing.T) {
	f := kasapitest.New(t, func(action string, params map[string]any) (string, string) {
		switch action {
		case "get_subdomains":
			return `
 <item>
  <item><key>subdomain_name</key><value>blog.example.com</value></item>
  <item><key>subdomain_path</key><value>/blog/</value></item>
 </item>`, ""
		case "add_subdomain":
			if params["subdomain_name"] != "shop" || params["domain_name"] != "example.com" {
				return "", "invalid_params"
			}
			return "TRUE", ""
		case "delete_subdomain":
			if params["subdomain_name"] != "blog.example.com" {
				return "", "subdomain_not_found"
			}
			return "TRUE", ""
		}
		return "", "unknown_action"
	})
	c := newTestClient(t, f)
	ctx := context.Background()

	subs, err := c.Subdomains.List(ctx)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(subs) != 1 || subs[0].FQDN != "blog.example.com" || subs[0].Path != "/blog/" {
		t.Fatalf("unexpected subdomains: %+v", subs)
	}

	if _, err := c.Subdomains.Get(ctx, "blog.example.com"); err != nil {
		t.Fatalf("Get: %v", err)
	}
	if _, err := c.Subdomains.Get(ctx, "missing.example.com"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}

	if err := c.Subdomains.Create(ctx, "shop", "example.com", "/shop/"); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := c.Subdomains.Delete(ctx, "blog.example.com"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
}

func TestSubdomains_UpdateAndValidation(t *testing.T) {
	f := kasapitest.New(t, func(action string, params map[string]any) (string, string) {
		switch action {
		case "update_subdomain":
			if params["subdomain_name"] != "blog.example.com" || params["subdomain_path"] != "/new/" {
				return "", "subdomain_not_found"
			}
			return "TRUE", ""
		case "delete_subdomain":
			return "", "subdomain_not_found"
		}
		return "", "unknown_action"
	})
	c := newTestClient(t, f)
	ctx := context.Background()

	if err := c.Subdomains.UpdatePath(ctx, "blog.example.com", "/new/"); err != nil {
		t.Fatalf("UpdatePath: %v", err)
	}
	if err := c.Subdomains.UpdatePath(ctx, "", "/x/"); err == nil {
		t.Fatal("UpdatePath without fqdn must fail")
	}
	if err := c.Subdomains.Create(ctx, "", "example.com", ""); err == nil {
		t.Fatal("Create without name must fail")
	}
	if err := c.Subdomains.Delete(ctx, ""); err == nil {
		t.Fatal("Delete without fqdn must fail")
	}
	if err := c.Subdomains.Delete(ctx, "gone.example.com"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
}

// subdomainEntry is a get_subdomains entry as KAS sends it.
func subdomainEntry(name string) string {
	return entry(
		"subdomain_name", name,
		"subdomain_redirect_status", "301",
		"subdomain_path", "https://example.org",
		"ssl_certificate_sni_is_active", "j",
		"ssl_certificate_sni_type", "LE90D",
		"ssl_certificate_sni_force_https", "Y",
		"ssl_certificate_sni_hsts_max_age", "300",
		"php_version", "8.4",
		"php_deprecated", "N",
		"is_active", "Y",
		"in_progress", "FALSE",
	)
}

func TestSubdomains_ListMapsAllFields(t *testing.T) {
	c, _ := newFake(t, map[string]string{"get_subdomains": subdomainEntry("blog.example.com")})
	subs, err := c.Subdomains.List(context.Background())
	if err != nil || len(subs) != 1 {
		t.Fatalf("List: %v %v", subs, err)
	}
	s := subs[0]
	if s.FQDN != "blog.example.com" || s.Path != "https://example.org" || s.RedirectStatus != 301 ||
		s.PHPVersion != "8.4" || s.PHPDeprecated || !s.Active || s.InProgress {
		t.Fatalf("unexpected subdomain: %+v", s)
	}
	if !s.TLS.Active || !s.TLS.LetsEncrypt() || !s.TLS.ForceHTTPS || s.TLS.HSTSMaxAge != 300 {
		t.Fatalf("unexpected TLS state: %+v", s.TLS)
	}
}

func TestSubdomains_ListEmptyAndFault(t *testing.T) {
	ctx := context.Background()
	for _, answer := range []string{"", "!empty_list"} {
		c, _ := newFake(t, map[string]string{"get_subdomains": answer})
		subs, err := c.Subdomains.List(ctx)
		if err != nil || len(subs) != 0 {
			t.Fatalf("answer %q: %v %v", answer, subs, err)
		}
	}
	c, _ := newFake(t, map[string]string{"get_subdomains": "!kas_error"})
	if _, err := c.Subdomains.List(ctx); err == nil || !strings.Contains(err.Error(), "listing subdomains") {
		t.Fatalf("fault must be returned with context, got %v", err)
	}
}

func TestSubdomains_GetFiltersOnTheServer(t *testing.T) {
	ctx := context.Background()
	c, rec := newFake(t, map[string]string{"get_subdomains": subdomainEntry("Blog.Example.com")})

	sub, err := c.Subdomains.Get(ctx, "blog.example.com")
	if err != nil || sub.FQDN != "Blog.Example.com" {
		t.Fatalf("Get: %+v %v", sub, err)
	}
	wantParams(t, rec.last(t, "get_subdomains"), map[string]string{"subdomain_name": "blog.example.com"})

	// A server that ignores the filter must not return the wrong host.
	if _, err := c.Subdomains.Get(ctx, "other.example.com"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
	if _, err := c.Subdomains.Get(ctx, ""); err == nil {
		t.Fatal("Get without FQDN must fail")
	}

	c, _ = newFake(t, map[string]string{"get_subdomains": "!subdomain_doenst_exist"})
	if _, err := c.Subdomains.Get(ctx, "gone.example.com"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("not-found fault: expected ErrNotFound, got %v", err)
	}
	c, _ = newFake(t, map[string]string{"get_subdomains": "!kas_error"})
	if _, err := c.Subdomains.Get(ctx, "x.example.com"); err == nil || errors.Is(err, ErrNotFound) ||
		!strings.Contains(err.Error(), "reading subdomain x.example.com") {
		t.Fatalf("other faults must be returned with context, got %v", err)
	}
}

func TestSubdomains_CreateSendsNoDefaultSettings(t *testing.T) {
	c, rec := newFake(t, map[string]string{"add_subdomain": "shop.example.com"})
	if err := c.Subdomains.Create(context.Background(), "shop", "example.com", ""); err != nil {
		t.Fatalf("Create: %v", err)
	}
	got := rec.last(t, "add_subdomain")
	wantParams(t, got, map[string]string{"subdomain_name": "shop", "domain_name": "example.com"})
	wantAbsent(t, got, "subdomain_path", "redirect_status", "php_version", "is_active")
}

func TestSubdomains_CreateWithSettings(t *testing.T) {
	ctx := context.Background()
	c, rec := newFake(t, map[string]string{"add_subdomain": "TRUE"})

	err := c.Subdomains.CreateWithSettings(ctx, "go", "example.com", HostSettings{
		Path: "https://example.org/landing", RedirectStatus: new(302), PHPVersion: "8.4",
	})
	if err != nil {
		t.Fatalf("CreateWithSettings: %v", err)
	}
	wantParams(t, rec.last(t, "add_subdomain"), map[string]string{
		"subdomain_name": "go", "domain_name": "example.com",
		"subdomain_path": "https://example.org/landing", "redirect_status": "302", "php_version": "8.4",
	})

	before := rec.count("add_subdomain")
	for name, tc := range map[string]struct {
		sub, domain string
		hs          HostSettings
	}{
		"no name":          {"", "example.com", HostSettings{}},
		"no domain":        {"go", "", HostSettings{}},
		"active on create": {"go", "example.com", HostSettings{Active: new(false)}},
		"bad redirect":     {"go", "example.com", HostSettings{Path: "https://x", RedirectStatus: new(303)}},
	} {
		if err := c.Subdomains.CreateWithSettings(ctx, tc.sub, tc.domain, tc.hs); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
	if rec.count("add_subdomain") != before {
		t.Fatal("invalid input must not reach the API")
	}

	c, _ = newFake(t, map[string]string{"add_subdomain": "!subdomain_exist_as_subdomain"})
	err = c.Subdomains.CreateWithSettings(ctx, "go", "example.com", HostSettings{})
	var apiErr *APIError
	if !errors.As(err, &apiErr) || !strings.Contains(err.Error(), "creating subdomain go.example.com") {
		t.Fatalf("fault must be returned with context, got %v", err)
	}
}

func TestSubdomains_Update(t *testing.T) {
	ctx := context.Background()
	c, rec := newFake(t, map[string]string{"update_subdomain": "TRUE"})

	if err := c.Subdomains.Update(ctx, "blog.example.com", HostSettings{PHPVersion: "8.4", Active: new(false)}); err != nil {
		t.Fatalf("Update: %v", err)
	}
	got := rec.last(t, "update_subdomain")
	wantParams(t, got, map[string]string{"subdomain_name": "blog.example.com", "php_version": "8.4", "is_active": "N"})
	wantAbsent(t, got, "subdomain_path", "redirect_status")

	before := rec.count("update_subdomain")
	if err := c.Subdomains.Update(ctx, "", HostSettings{PHPVersion: "8.4"}); err == nil {
		t.Error("Update without FQDN must fail")
	}
	if err := c.Subdomains.Update(ctx, "blog.example.com", HostSettings{}); err == nil {
		t.Error("Update without settings must fail")
	}
	if err := c.Subdomains.Update(ctx, "blog.example.com", HostSettings{RedirectStatus: new(999)}); err == nil {
		t.Error("Update with a bad redirect status must fail")
	}
	if rec.count("update_subdomain") != before {
		t.Fatal("invalid input must not reach the API")
	}
}

func TestSubdomains_UpdatePathFaults(t *testing.T) {
	ctx := context.Background()

	c, _ := newFake(t, map[string]string{"update_subdomain": "!nothing_to_do"})
	if err := c.Subdomains.UpdatePath(ctx, "blog.example.com", "/same/"); err != nil {
		t.Fatalf("nothing_to_do must be success, got %v", err)
	}
	c, _ = newFake(t, map[string]string{"update_subdomain": "!subdomain_doenst_exist"})
	if err := c.Subdomains.UpdatePath(ctx, "gone.example.com", "/x/"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
	c, _ = newFake(t, map[string]string{"update_subdomain": "!in_progress"})
	err := c.Subdomains.UpdatePath(ctx, "blog.example.com", "/x/")
	var apiErr *APIError
	if !errors.As(err, &apiErr) || !strings.Contains(err.Error(), "updating subdomain blog.example.com") {
		t.Fatalf("fault must be returned with context, got %v", err)
	}
}

func TestSubdomains_UpdateFaults(t *testing.T) {
	ctx := context.Background()
	hs := HostSettings{PHPVersion: "8.4"}

	c, _ := newFake(t, map[string]string{"update_subdomain": "!nothing_to_do"})
	if err := c.Subdomains.Update(ctx, "blog.example.com", hs); err != nil {
		t.Fatalf("nothing_to_do must be success, got %v", err)
	}
	c, _ = newFake(t, map[string]string{"update_subdomain": "!subdomain_doenst_exist"})
	if err := c.Subdomains.Update(ctx, "gone.example.com", hs); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
	c, _ = newFake(t, map[string]string{"update_subdomain": "!in_progress"})
	err := c.Subdomains.Update(ctx, "blog.example.com", hs)
	var apiErr *APIError
	if !errors.As(err, &apiErr) || apiErr.Code != "in_progress" ||
		!strings.Contains(err.Error(), "updating subdomain blog.example.com") {
		t.Fatalf("fault must be returned with context, got %v", err)
	}
}

func TestSubdomains_UpdatePathSendsEmptyPath(t *testing.T) {
	c, rec := newFake(t, map[string]string{"update_subdomain": "TRUE"})
	if err := c.Subdomains.UpdatePath(context.Background(), "blog.example.com", ""); err != nil {
		t.Fatalf("UpdatePath: %v", err)
	}
	got := rec.last(t, "update_subdomain")
	if v, ok := got["subdomain_path"]; !ok || v != "" {
		t.Fatalf("the empty path must be sent, got %v", got)
	}
}

func TestSubdomains_DeleteFault(t *testing.T) {
	c, _ := newFake(t, map[string]string{"delete_subdomain": "!in_progress"})
	err := c.Subdomains.Delete(context.Background(), "blog.example.com")
	if err == nil || errors.Is(err, ErrNotFound) || !strings.Contains(err.Error(), "deleting subdomain blog.example.com") {
		t.Fatalf("fault must be returned with context, got %v", err)
	}
}

func TestWrapHostErr(t *testing.T) {
	if wrapHostErr("doing", "x", nil) != nil {
		t.Fatal("nil must stay nil")
	}
	if err := wrapHostErr("doing", "x", ErrNotFound); err != ErrNotFound {
		t.Fatalf("ErrNotFound must pass through unwrapped, got %v", err)
	}
	base := &APIError{Code: "in_progress"}
	err := wrapHostErr("updating host", "x.example.com", base)
	if !errors.Is(err, base) || err.Error() != "updating host x.example.com: kasapi: in_progress" {
		t.Fatalf("unexpected wrap: %v", err)
	}
}
