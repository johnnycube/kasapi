// Copyright 2026 The kasapi Authors
// SPDX-License-Identifier: Apache-2.0

package kasapi

import (
	"context"
	"errors"
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
