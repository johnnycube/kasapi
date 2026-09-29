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

func dnsEntry(id, name, typ, data, aux string) string {
	return entry(
		"record_zone", "example.com",
		"record_name", name, "record_type", typ, "record_data", data, "record_aux", aux,
		"record_id", id, "record_changeable", "Y", "record_deleteable", "N",
	)
}

func TestNormalizeZone(t *testing.T) {
	for in, want := range map[string]string{
		"example.com": "example.com.", "example.com.": "example.com.",
		"  example.com ": "example.com.", "": "",
	} {
		if got := normalizeZone(in); got != want {
			t.Errorf("normalizeZone(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestDNS_ListMapsAllFields(t *testing.T) {
	c, rec := newFake(t, map[string]string{"get_dns_settings": dnsEntry("7", "mail", "MX", "mx.example.com.", "10")})
	records, err := c.DNS.List(context.Background(), "example.com")
	if err != nil || len(records) != 1 {
		t.Fatalf("List: %v %v", records, err)
	}
	want := DNSRecord{
		ID: "7", Zone: "example.com", Name: "mail", Type: "MX", Data: "mx.example.com.",
		Aux: 10, Changeable: true, Deletable: false,
	}
	if records[0] != want {
		t.Fatalf("got %+v, want %+v", records[0], want)
	}
	wantParams(t, rec.last(t, "get_dns_settings"), map[string]string{"zone_host": "example.com."})
	wantAbsent(t, rec.last(t, "get_dns_settings"), "record_id")
}

func TestDNS_ListEmptyAndFault(t *testing.T) {
	ctx := context.Background()
	for _, answer := range []string{"", "!empty_list"} {
		c, _ := newFake(t, map[string]string{"get_dns_settings": answer})
		records, err := c.DNS.List(ctx, "example.com")
		if err != nil || len(records) != 0 {
			t.Fatalf("answer %q: %v %v", answer, records, err)
		}
	}
	c, _ := newFake(t, map[string]string{"get_dns_settings": "!zone_not_found"})
	_, err := c.DNS.List(ctx, "example.com")
	var apiErr *APIError
	if !errors.As(err, &apiErr) || apiErr.Code != "zone_not_found" {
		t.Fatalf("a missing zone is a fault, not an empty list: %v", err)
	}
}

func TestDNS_GetFiltersOnTheServer(t *testing.T) {
	ctx := context.Background()
	c, rec := newFake(t, map[string]string{"get_dns_settings": dnsEntry("7", "www", "A", "203.0.113.1", "0")})

	r, err := c.DNS.Get(ctx, "example.com", "7")
	if err != nil || r.ID != "7" || r.Data != "203.0.113.1" {
		t.Fatalf("Get: %+v %v", r, err)
	}
	wantParams(t, rec.last(t, "get_dns_settings"), map[string]string{"zone_host": "example.com.", "record_id": "7"})

	// A server that ignores the filter must not return the wrong record.
	if _, err := c.DNS.Get(ctx, "example.com", "8"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
	if _, err := c.DNS.Get(ctx, "example.com", ""); err == nil {
		t.Fatal("Get without id must fail")
	}
	c, _ = newFake(t, map[string]string{"get_dns_settings": "!record_id_not_found"})
	if _, err := c.DNS.Get(ctx, "example.com", "9"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("not-found fault: expected ErrNotFound, got %v", err)
	}
	c, _ = newFake(t, map[string]string{"get_dns_settings": "!kas_error"})
	if _, err := c.DNS.Get(ctx, "example.com", "9"); err == nil || errors.Is(err, ErrNotFound) ||
		!strings.Contains(err.Error(), "reading DNS record 9") {
		t.Fatalf("other faults must be returned with context, got %v", err)
	}
}

func TestDNS_CreateReturnsID(t *testing.T) {
	c, rec := newFake(t, map[string]string{"add_dns_settings": "123456789"})
	id, err := c.DNS.Create(context.Background(), DNSRecord{
		Zone: "example.com", Name: "_acme-challenge", Type: "txt", Data: "token", Aux: 0,
	})
	if err != nil || id != "123456789" {
		t.Fatalf("Create: %q %v", id, err)
	}
	wantParams(t, rec.last(t, "add_dns_settings"), map[string]string{
		"zone_host": "example.com.", "record_type": "TXT", "record_name": "_acme-challenge",
		"record_data": "token", "record_aux": "0",
	})
	if rec.count("get_dns_settings") != 0 {
		t.Fatal("an id in the response needs no lookup")
	}
}

func TestDNS_CreateFallsBackToLookup(t *testing.T) {
	ctx := context.Background()
	rec := DNSRecord{Zone: "example.com", Name: "www", Type: "a", Data: "203.0.113.1"}

	// KAS answers TRUE: the id comes from re-reading the zone.
	c, _ := newFake(t, map[string]string{
		"add_dns_settings": "TRUE",
		"get_dns_settings": dnsEntry("1", "mail", "A", "203.0.113.1", "0") + dnsEntry("2", "www", "A", "203.0.113.1", "0"),
	})
	id, err := c.DNS.Create(ctx, rec)
	if err != nil || id != "2" {
		t.Fatalf("Create: %q %v", id, err)
	}

	// The record is not in the zone afterwards.
	c, _ = newFake(t, map[string]string{
		"add_dns_settings": "TRUE",
		"get_dns_settings": dnsEntry("1", "mail", "A", "203.0.113.1", "0"),
	})
	if _, err := c.DNS.Create(ctx, rec); err == nil || !strings.Contains(err.Error(), "not found in zone") {
		t.Fatalf("expected a lookup miss, got %v", err)
	}

	// The lookup itself fails.
	c, _ = newFake(t, map[string]string{"add_dns_settings": "TRUE", "get_dns_settings": "!kas_error"})
	if _, err := c.DNS.Create(ctx, rec); err == nil || !strings.Contains(err.Error(), "id lookup failed") {
		t.Fatalf("expected a lookup failure, got %v", err)
	}

	// The create fails.
	c, _ = newFake(t, map[string]string{"add_dns_settings": "!record_already_exists"})
	_, err = c.DNS.Create(ctx, rec)
	var apiErr *APIError
	if !errors.As(err, &apiErr) || apiErr.Code != "record_already_exists" {
		t.Fatalf("expected the fault, got %v", err)
	}
}

func TestDNS_UpdateAndDeleteFaults(t *testing.T) {
	ctx := context.Background()

	c, rec := newFake(t, map[string]string{"update_dns_settings": "TRUE"})
	if err := c.DNS.Update(ctx, DNSRecord{ID: "7", Name: "www", Data: "203.0.113.2", Aux: 5}); err != nil {
		t.Fatalf("Update: %v", err)
	}
	wantParams(t, rec.last(t, "update_dns_settings"), map[string]string{
		"record_id": "7", "record_name": "www", "record_data": "203.0.113.2", "record_aux": "5",
	})
	if err := c.DNS.Update(ctx, DNSRecord{Name: "www"}); err == nil {
		t.Fatal("Update without id must fail")
	}

	c, _ = newFake(t, map[string]string{"update_dns_settings": "!nothing_to_do"})
	if err := c.DNS.Update(ctx, DNSRecord{ID: "7"}); err != nil {
		t.Fatalf("nothing_to_do must be success, got %v", err)
	}
	c, _ = newFake(t, map[string]string{"update_dns_settings": "!record_syntax_incorrect"})
	if err := c.DNS.Update(ctx, DNSRecord{ID: "7"}); err == nil || !strings.Contains(err.Error(), "updating DNS record 7") {
		t.Fatalf("fault must be returned with context, got %v", err)
	}

	c, _ = newFake(t, map[string]string{"delete_dns_settings": "!record_id_not_found"})
	if err := c.DNS.Delete(ctx, "7"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
	if err := c.DNS.Delete(ctx, ""); err == nil {
		t.Fatal("Delete without id must fail")
	}
	c, _ = newFake(t, map[string]string{"delete_dns_settings": "!record_has_ssl_certificate"})
	if err := c.DNS.Delete(ctx, "7"); err == nil || errors.Is(err, ErrNotFound) ||
		!strings.Contains(err.Error(), "deleting DNS record 7") {
		t.Fatalf("fault must be returned with context, got %v", err)
	}
}
