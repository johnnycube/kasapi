// Copyright 2026 The kasapi Authors
// SPDX-License-Identifier: Apache-2.0

package kasapi

import (
	"context"
	"errors"
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
