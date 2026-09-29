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
