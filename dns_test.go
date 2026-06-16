// Copyright 2026 The kasapi Authors
// SPDX-License-Identifier: Apache-2.0

package kasapi

import (
	"context"
	"errors"
	"testing"

	"github.com/johnnycube/kasapi/kasapitest"
)

func TestDNS_ListAndCreate(t *testing.T) {
	f := kasapitest.New(t, func(action string, params map[string]any) (string, string) {
		switch action {
		case "get_dns_settings":
			if params["zone_host"] != "example.com." {
				return "", "zone_not_found"
			}
			return `
 <item>
  <item><key>record_id</key><value>11</value></item>
  <item><key>record_name</key><value>www</value></item>
  <item><key>record_type</key><value>A</value></item>
  <item><key>record_data</key><value>203.0.113.10</value></item>
  <item><key>record_aux</key><value>0</value></item>
  <item><key>record_changeable</key><value>Y</value></item>
 </item>
 <item>
  <item><key>record_id</key><value>12</value></item>
  <item><key>record_name</key><value></value></item>
  <item><key>record_type</key><value>MX</value></item>
  <item><key>record_data</key><value>mail.example.com.</value></item>
  <item><key>record_aux</key><value>10</value></item>
  <item><key>record_changeable</key><value>Y</value></item>
 </item>`, ""
		case "add_dns_settings":
			return `13`, ""
		}
		return "", "unknown_action"
	})
	c := newTestClient(t, f)

	records, err := c.DNS.List(context.Background(), "example.com")
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(records) != 2 {
		t.Fatalf("expected 2 records, got %d", len(records))
	}
	if records[1].Type != "MX" || records[1].Aux != 10 || !records[1].Changeable {
		t.Fatalf("unexpected MX record: %+v", records[1])
	}

	id, err := c.DNS.Create(context.Background(), DNSRecord{
		Zone: "example.com", Name: "api", Type: "a", Data: "203.0.113.11",
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if id != "13" {
		t.Fatalf("expected id 13, got %q", id)
	}
}

func TestDNS_GetUpdateDelete(t *testing.T) {
	f := kasapitest.New(t, func(action string, params map[string]any) (string, string) {
		switch action {
		case "get_dns_settings":
			return `<item>` +
				kasapitest.MapItem("record_id", "11") +
				kasapitest.MapItem("record_name", "www") +
				kasapitest.MapItem("record_type", "A") +
				kasapitest.MapItem("record_data", "203.0.113.10") +
				kasapitest.MapItem("record_aux", "0") +
				kasapitest.MapItem("record_changeable", "Y") +
				`</item>`, ""
		case "update_dns_settings":
			if params["record_id"] != "11" || params["record_data"] != "203.0.113.20" {
				return "", "record_id_not_found"
			}
			return "TRUE", ""
		case "delete_dns_settings":
			if params["record_id"] != "11" {
				return "", "record_id_not_found"
			}
			return "TRUE", ""
		}
		return "", "unknown_action"
	})
	c := newTestClient(t, f)
	ctx := context.Background()

	rec, err := c.DNS.Get(ctx, "example.com", "11")
	if err != nil || rec.Name != "www" {
		t.Fatalf("Get: %v %+v", err, rec)
	}
	if _, err := c.DNS.Get(ctx, "example.com", "99"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}

	if err := c.DNS.Update(ctx, DNSRecord{ID: "11", Name: "www", Data: "203.0.113.20"}); err != nil {
		t.Fatalf("Update: %v", err)
	}
	if err := c.DNS.Update(ctx, DNSRecord{Name: "x"}); err == nil {
		t.Fatal("Update without id must fail")
	}

	if err := c.DNS.Delete(ctx, "11"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if err := c.DNS.Delete(ctx, ""); err == nil {
		t.Fatal("Delete without id must fail")
	}
	if err := c.DNS.Delete(ctx, "99"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound for unknown id, got %v", err)
	}
}
