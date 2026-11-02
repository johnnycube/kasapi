// Copyright 2026 The kasapi Authors
// SPDX-License-Identifier: Apache-2.0

package kasapi

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
)

// listEntry is a get_mailinglists entry as KAS sends it, password included.
func listEntry(name string, extra ...string) string {
	kv := []string{
		"mailinglist_name", name,
		"mailinglist_domain", "example.com",
		"mailinglist_password", "plaintext-password",
		"mailinglist_is_active", "Y",
		"in_progress", "FALSE",
	}
	return entry(append(kv, extra...)...)
}

func TestMailingList_ListAndGet(t *testing.T) {
	ctx := context.Background()
	c, rec := newFake(t, map[string]string{
		"get_mailinglists": listEntry("announce-example-com",
			"mailinglist_subscriber", "a@example.com\n\nb@example.com\n",
			"mailinglist_restrict_post", "owner@example.com",
			"mailinglist_config", "# Majordomo config") +
			listEntry("team-example-com", "mailinglist_is_active", "N", "in_progress", "TRUE"),
	})
	lists, err := c.MailingLists.List(ctx)
	if err != nil || len(lists) != 2 {
		t.Fatalf("List: %v %v", lists, err)
	}
	want := MailingList{
		Name: "announce-example-com", Domain: "example.com", Active: true,
		Subscribers: []string{"a@example.com", "b@example.com"}, RestrictPost: []string{"owner@example.com"},
		Config: "# Majordomo config",
	}
	if !reflect.DeepEqual(lists[0], want) {
		t.Fatalf("got %+v, want %+v", lists[0], want)
	}
	if lists[1].Active || !lists[1].InProgress {
		t.Fatalf("second list: %+v", lists[1])
	}

	l, err := c.MailingLists.Get(ctx, "team-example-com")
	if err != nil || l.Name != "team-example-com" {
		t.Fatalf("Get: %+v %v", l, err)
	}
	wantParams(t, rec.last(t, "get_mailinglists"), map[string]string{"mailinglist_name": "team-example-com"})
	v := reflect.ValueOf(*l)
	for i := range v.NumField() {
		if f := v.Field(i); f.Kind() == reflect.String && strings.Contains(f.String(), "plaintext-password") {
			t.Fatalf("field %s carries the list password", v.Type().Field(i).Name)
		}
	}
	if _, err := c.MailingLists.Get(ctx, "other-example-com"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
	if _, err := c.MailingLists.Get(ctx, ""); err == nil {
		t.Fatal("Get without name must fail")
	}
}

func TestMailingList_ListAndGetFaults(t *testing.T) {
	ctx := context.Background()
	for _, answer := range []string{"", "!empty_list"} {
		c, _ := newFake(t, map[string]string{"get_mailinglists": answer})
		if lists, err := c.MailingLists.List(ctx); err != nil || len(lists) != 0 {
			t.Fatalf("answer %q: %v %v", answer, lists, err)
		}
		if _, err := c.MailingLists.Get(ctx, "x-example-com"); !errors.Is(err, ErrNotFound) {
			t.Fatalf("answer %q: expected ErrNotFound, got %v", answer, err)
		}
	}
	c, _ := newFake(t, map[string]string{"get_mailinglists": "!kas_error"})
	if _, err := c.MailingLists.List(ctx); err == nil || !strings.Contains(err.Error(), "listing mailing lists") {
		t.Fatalf("List fault: %v", err)
	}
	if _, err := c.MailingLists.Get(ctx, "x"); err == nil || errors.Is(err, ErrNotFound) ||
		!strings.Contains(err.Error(), "reading mailing list x") {
		t.Fatalf("Get fault: %v", err)
	}
}

func TestMailingList_Create(t *testing.T) {
	ctx := context.Background()
	c, rec := newFake(t, map[string]string{"add_mailinglist": "announce-example-com"})
	name, err := c.MailingLists.Create(ctx, "announce", "example.com", "S3cure!")
	if err != nil || name != "announce-example-com" {
		t.Fatalf("Create: %q %v", name, err)
	}
	wantParams(t, rec.last(t, "add_mailinglist"), map[string]string{
		"mailinglist_name": "announce", "mailinglist_domain": "example.com", "mailinglist_password": "S3cure!",
	})

	before := rec.count("add_mailinglist")
	for _, args := range [][3]string{{"", "example.com", "p"}, {"a", "", "p"}, {"a b", "example.com", "p"}, {"a", "example.com", ""}} {
		if _, err := c.MailingLists.Create(ctx, args[0], args[1], args[2]); err == nil {
			t.Errorf("Create%v must fail", args)
		}
	}
	if rec.count("add_mailinglist") != before {
		t.Fatal("invalid input must not reach the API")
	}

	c, _ = newFake(t, map[string]string{"add_mailinglist": "TRUE"})
	if _, err := c.MailingLists.Create(ctx, "a", "example.com", "p"); err == nil || !strings.Contains(err.Error(), "returned no name") {
		t.Fatalf("a create without name must fail, got %v", err)
	}
	c, _ = newFake(t, map[string]string{"add_mailinglist": "!mailinglist_already_exists"})
	var apiErr *APIError
	if _, err := c.MailingLists.Create(ctx, "a", "example.com", "p"); !errors.As(err, &apiErr) ||
		!strings.Contains(err.Error(), "creating mailing list a@example.com") {
		t.Fatalf("fault must be returned with context, got %v", err)
	}
}

func TestMailingList_Update(t *testing.T) {
	ctx := context.Background()
	c, rec := newFake(t, map[string]string{"update_mailinglist": "TRUE"})
	err := c.MailingLists.Update(ctx, "announce-example-com", MailingListUpdate{
		Subscribers:  new([]string{"a@example.com", "b@example.com"}),
		RestrictPost: new([]string{}),
		Config:       new("# config"),
		Active:       new(false),
	})
	if err != nil {
		t.Fatalf("Update: %v", err)
	}
	wantParams(t, rec.last(t, "update_mailinglist"), map[string]string{
		"mailinglist_name": "announce-example-com", "subscriber": "a@example.com\nb@example.com",
		"restrict_post": "", "config": "# config", "is_active": "N",
	})

	if err := c.MailingLists.Update(ctx, "announce-example-com", MailingListUpdate{Active: new(true)}); err != nil {
		t.Fatalf("Update: %v", err)
	}
	got := rec.last(t, "update_mailinglist")
	wantParams(t, got, map[string]string{"is_active": "Y"})
	wantAbsent(t, got, "subscriber", "restrict_post", "config")

	before := rec.count("update_mailinglist")
	for name, u := range map[string]MailingListUpdate{
		"":                     {Active: new(true)},
		"no-change":            {},
		"bad-subscriber":       {Subscribers: new([]string{"not an address"})},
		"newline-subscriber":   {Subscribers: new([]string{"a@example.com\nb@example.com"})},
		"bad-restrict-post":    {RestrictPost: new([]string{"x"})},
		"newline-restrictpost": {RestrictPost: new([]string{"a@example.com\r"})},
	} {
		if err := c.MailingLists.Update(ctx, name, u); err == nil {
			t.Errorf("Update %q must fail", name)
		}
	}
	if rec.count("update_mailinglist") != before {
		t.Fatal("invalid input must not reach the API")
	}
}

func TestMailingList_UpdateAndDeleteFaults(t *testing.T) {
	ctx := context.Background()
	u := MailingListUpdate{Active: new(true)}
	c, rec := newFake(t, map[string]string{"update_mailinglist": "!nothing_to_do", "delete_mailinglist": "TRUE"})
	if err := c.MailingLists.Update(ctx, "l", u); err != nil {
		t.Errorf("nothing_to_do must be success, got %v", err)
	}
	if err := c.MailingLists.Delete(ctx, "l"); err != nil {
		t.Errorf("Delete: %v", err)
	}
	wantParams(t, rec.last(t, "delete_mailinglist"), map[string]string{"mailinglist_name": "l"})
	if err := c.MailingLists.Delete(ctx, ""); err == nil {
		t.Error("Delete without name must fail")
	}

	c, _ = newFake(t, map[string]string{"update_mailinglist": "!mailinglist_not_found", "delete_mailinglist": "!mailinglist_not_found"})
	if err := c.MailingLists.Update(ctx, "l", u); !errors.Is(err, ErrNotFound) {
		t.Errorf("Update: expected ErrNotFound, got %v", err)
	}
	if err := c.MailingLists.Delete(ctx, "l"); !errors.Is(err, ErrNotFound) {
		t.Errorf("Delete: expected ErrNotFound, got %v", err)
	}

	c, _ = newFake(t, map[string]string{"update_mailinglist": "!cannot_connect_to_majordomo", "delete_mailinglist": "!in_progress"})
	if err := c.MailingLists.Update(ctx, "l", u); err == nil || !strings.Contains(err.Error(), "updating mailing list l") {
		t.Errorf("Update fault: %v", err)
	}
	if err := c.MailingLists.Delete(ctx, "l"); err == nil || !strings.Contains(err.Error(), "deleting mailing list l") {
		t.Errorf("Delete fault: %v", err)
	}
}

func TestSplitLines(t *testing.T) {
	if got := splitLines(""); got != nil {
		t.Errorf("empty: %v", got)
	}
	if got := splitLines(" a \r\n\nb"); !reflect.DeepEqual(got, []string{"a", "b"}) {
		t.Errorf("got %v", got)
	}
}
