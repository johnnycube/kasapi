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

// ddnsEntry is a get_ddnsusers entry as KAS sends it, password included.
func ddnsEntry(login string, extra ...string) string {
	kv := []string{
		"dyndns_login", login,
		"dyndns_comment", "at home",
		"dyndns_label", "home",
		"dyndns_zone", "example.org",
		"dyndns_dual_stack", "Y",
		"dyndns_password", "plaintext-password",
		"dyndns_target_ip", "203.0.113.255",
		"dyndns_target_ipv4", "203.0.113.255",
		"dyndns_target_ipv6", "2001:db8::7334",
	}
	return entry(append(kv, extra...)...)
}

func TestDDNSUser_Host(t *testing.T) {
	if got := (DDNSUser{Zone: "example.org", Label: "home"}).Host(); got != "home.example.org" {
		t.Fatalf("Host(): %q", got)
	}
	if got := (DDNSUser{Zone: "example.org"}).Host(); got != "example.org" {
		t.Fatalf("Host() without label: %q", got)
	}
}

func TestDDNS_ListMapsAllFields(t *testing.T) {
	c, _ := newFake(t, map[string]string{
		"get_ddnsusers": ddnsEntry("dyn0000002") +
			// An older response shape: the address in dyndns_target_ip only.
			entry("dyndns_login", "dyn0000003", "dyndns_zone", "example.org", "dyndns_label", "lab",
				"dyndns_target_ip", "198.51.100.4", "dyndns_dual_stack", "N", "dyndns_comment", "lab"),
	})
	users, err := c.DDNS.List(context.Background())
	if err != nil || len(users) != 2 {
		t.Fatalf("List: %v %v", users, err)
	}
	want := DDNSUser{
		Login: "dyn0000002", Comment: "at home", Zone: "example.org", Label: "home",
		TargetIP: "203.0.113.255", TargetIPv6: "2001:db8::7334", DualStack: true,
	}
	if users[0] != want {
		t.Fatalf("got %+v, want %+v", users[0], want)
	}
	if users[1].TargetIP != "198.51.100.4" || users[1].TargetIPv6 != "" || users[1].DualStack {
		t.Fatalf("fallback shape: %+v", users[1])
	}
}

func TestDDNS_PasswordIsNotMapped(t *testing.T) {
	c, _ := newFake(t, map[string]string{"get_ddnsusers": ddnsEntry("dyn0000002")})
	u, err := c.DDNS.Get(context.Background(), "dyn0000002")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	v := reflect.ValueOf(*u)
	for i := range v.NumField() {
		if f := v.Field(i); f.Kind() == reflect.String && strings.Contains(f.String(), "plaintext-password") {
			t.Fatalf("field %s carries the DDNS password", v.Type().Field(i).Name)
		}
	}
}

func TestDDNS_ListEmptyAndFault(t *testing.T) {
	ctx := context.Background()
	// KAS answers an account without DDNS users with the fault empty_list.
	for _, answer := range []string{"!empty_list", ""} {
		c, _ := newFake(t, map[string]string{"get_ddnsusers": answer})
		if users, err := c.DDNS.List(ctx); err != nil || len(users) != 0 {
			t.Fatalf("answer %q: %v %v", answer, users, err)
		}
	}
	c, _ := newFake(t, map[string]string{"get_ddnsusers": "!settings_not_in_contract"})
	if _, err := c.DDNS.List(ctx); err == nil || !strings.Contains(err.Error(), "listing DDNS users") {
		t.Fatalf("fault must be returned with context, got %v", err)
	}
}

func TestDDNS_Get(t *testing.T) {
	ctx := context.Background()
	c, rec := newFake(t, map[string]string{"get_ddnsusers": ddnsEntry("dyn0000002")})

	u, err := c.DDNS.Get(ctx, "dyn0000002")
	if err != nil || u.Host() != "home.example.org" {
		t.Fatalf("Get: %+v %v", u, err)
	}
	// The filter parameter is ddns_login, unlike every other DDNS action.
	got := rec.last(t, "get_ddnsusers")
	wantParams(t, got, map[string]string{"ddns_login": "dyn0000002"})
	wantAbsent(t, got, "dyndns_login")

	if _, err := c.DDNS.Get(ctx, "dyn0000009"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
	if _, err := c.DDNS.Get(ctx, ""); err == nil {
		t.Fatal("Get without login must fail")
	}
	for _, fault := range []string{"!dyndns_login_not_found", "!empty_list"} {
		c, _ = newFake(t, map[string]string{"get_ddnsusers": fault})
		if _, err := c.DDNS.Get(ctx, "dyn0000009"); !errors.Is(err, ErrNotFound) {
			t.Fatalf("%s: expected ErrNotFound, got %v", fault, err)
		}
	}
	c, _ = newFake(t, map[string]string{"get_ddnsusers": "!kas_error"})
	if _, err := c.DDNS.Get(ctx, "dyn0000002"); err == nil || errors.Is(err, ErrNotFound) ||
		!strings.Contains(err.Error(), "reading DDNS user dyn0000002") {
		t.Fatalf("other faults must be returned with context, got %v", err)
	}
}

func TestDDNS_Create(t *testing.T) {
	ctx := context.Background()
	c, rec := newFake(t, map[string]string{"add_ddnsuser": "dyn0000001"})

	login, err := c.DDNS.Create(ctx, DDNSUser{
		Comment: "at home", Zone: "example.org.", Label: "home", TargetIP: "203.0.113.4", DualStack: true,
	}, "S3cure!pass")
	if err != nil || login != "dyn0000001" {
		t.Fatalf("Create: %q %v", login, err)
	}
	wantParams(t, rec.last(t, "add_ddnsuser"), map[string]string{
		"dyndns_comment": "at home", "dyndns_password": "S3cure!pass", "dyndns_zone": "example.org",
		"dyndns_label": "home", "dyndns_target_ip": "203.0.113.4", "dyndns_dual_stack": "Y",
	})

	// Without dual stack the parameter is left to the KAS default.
	if _, err := c.DDNS.Create(ctx, DDNSUser{Comment: "c", Zone: "example.org", Label: "lab", TargetIP: "203.0.113.5"}, "p"); err != nil {
		t.Fatalf("Create: %v", err)
	}
	wantAbsent(t, rec.last(t, "add_ddnsuser"), "dyndns_dual_stack", "dyndns_login")

	before := rec.count("add_ddnsuser")
	valid := DDNSUser{Comment: "c", Zone: "example.org", Label: "home", TargetIP: "203.0.113.4"}
	with := func(change func(*DDNSUser)) DDNSUser {
		u := valid
		change(&u)
		return u
	}
	for name, tc := range map[string]struct {
		u        DDNSUser
		password string
	}{
		"no password": {valid, ""},
		"no zone":     {with(func(u *DDNSUser) { u.Zone = "" }), "p"},
		"no label":    {with(func(u *DDNSUser) { u.Label = "" }), "p"},
		"no comment":  {with(func(u *DDNSUser) { u.Comment = "" }), "p"},
		"no address":  {with(func(u *DDNSUser) { u.TargetIP = "" }), "p"},
		"bad address": {with(func(u *DDNSUser) { u.TargetIP = "home.example.org" }), "p"},
		"IPv6":        {with(func(u *DDNSUser) { u.TargetIP = "2001:db8::1" }), "p"},
	} {
		if _, err := c.DDNS.Create(ctx, tc.u, tc.password); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
	if rec.count("add_ddnsuser") != before {
		t.Fatal("invalid input must not reach the API")
	}

	c, _ = newFake(t, map[string]string{"add_ddnsuser": "TRUE"})
	if _, err := c.DDNS.Create(ctx, valid, "p"); err == nil || !strings.Contains(err.Error(), "returned no login") {
		t.Fatalf("a create without login must fail, got %v", err)
	}
	c, _ = newFake(t, map[string]string{"add_ddnsuser": "!ddns_limit_reached"})
	if _, err := c.DDNS.Create(ctx, valid, "p"); err == nil ||
		!strings.Contains(err.Error(), "creating DDNS user for home.example.org") {
		t.Fatalf("fault must be returned with context, got %v", err)
	}
}

func TestDDNS_Update(t *testing.T) {
	ctx := context.Background()
	c, rec := newFake(t, map[string]string{"update_ddnsuser": "TRUE"})

	err := c.DDNS.Update(ctx, DDNSUser{
		Login: "dyn0000002", Comment: "moved", DualStack: false,
		Zone: "example.org", Label: "home", TargetIP: "203.0.113.9",
	})
	if err != nil {
		t.Fatalf("Update: %v", err)
	}
	got := rec.last(t, "update_ddnsuser")
	wantParams(t, got, map[string]string{
		"dyndns_login": "dyn0000002", "dyndns_comment": "moved", "dyndns_dual_stack": "N",
	})
	// Zone, label and address are not the API's to change here.
	wantAbsent(t, got, "dyndns_zone", "dyndns_label", "dyndns_target_ip", "dyndns_password")

	if err := c.DDNS.Update(ctx, DDNSUser{Comment: "x"}); err == nil {
		t.Error("Update without login must fail")
	}
	if err := c.DDNS.Update(ctx, DDNSUser{Login: "dyn0000002"}); err == nil {
		t.Error("Update without comment must fail")
	}

	if err := c.DDNS.UpdatePassword(ctx, "dyn0000002", "N3w!pass"); err != nil {
		t.Fatalf("UpdatePassword: %v", err)
	}
	got = rec.last(t, "update_ddnsuser")
	wantParams(t, got, map[string]string{"dyndns_login": "dyn0000002", "dyndns_password": "N3w!pass"})
	wantAbsent(t, got, "dyndns_comment", "dyndns_dual_stack")
	if err := c.DDNS.UpdatePassword(ctx, "", "p"); err == nil {
		t.Error("UpdatePassword without login must fail")
	}
	if err := c.DDNS.UpdatePassword(ctx, "dyn0000002", ""); err == nil {
		t.Error("UpdatePassword without password must fail")
	}
}

func TestDDNS_UpdateAndDeleteFaults(t *testing.T) {
	ctx := context.Background()
	u := DDNSUser{Login: "dyn0000002", Comment: "x"}

	c, rec := newFake(t, map[string]string{"update_ddnsuser": "!nothing_to_do", "delete_ddnsuser": "TRUE"})
	if err := c.DDNS.Update(ctx, u); err != nil {
		t.Errorf("Update: nothing_to_do must be success, got %v", err)
	}
	if err := c.DDNS.UpdatePassword(ctx, u.Login, "p"); err != nil {
		t.Errorf("UpdatePassword: nothing_to_do must be success, got %v", err)
	}
	if err := c.DDNS.Delete(ctx, u.Login); err != nil {
		t.Errorf("Delete: %v", err)
	}
	wantParams(t, rec.last(t, "delete_ddnsuser"), map[string]string{"dyndns_login": "dyn0000002"})
	if err := c.DDNS.Delete(ctx, ""); err == nil {
		t.Error("Delete without login must fail")
	}

	c, _ = newFake(t, map[string]string{"update_ddnsuser": "!dyndns_login_not_found", "delete_ddnsuser": "!dyndns_login_not_found"})
	for name, err := range map[string]error{
		"Update": c.DDNS.Update(ctx, u), "UpdatePassword": c.DDNS.UpdatePassword(ctx, u.Login, "p"),
		"Delete": c.DDNS.Delete(ctx, u.Login),
	} {
		if !errors.Is(err, ErrNotFound) {
			t.Errorf("%s: expected ErrNotFound, got %v", name, err)
		}
	}

	c, _ = newFake(t, map[string]string{"update_ddnsuser": "!ddns_service_temporarily_not_available", "delete_ddnsuser": "!kas_error"})
	for name, tc := range map[string]struct {
		err  error
		want string
	}{
		"Update":         {c.DDNS.Update(ctx, u), "updating DDNS user dyn0000002"},
		"UpdatePassword": {c.DDNS.UpdatePassword(ctx, u.Login, "p"), "updating password of DDNS user dyn0000002"},
		"Delete":         {c.DDNS.Delete(ctx, u.Login), "deleting DDNS user dyn0000002"},
	} {
		var apiErr *APIError
		if !errors.As(tc.err, &apiErr) || !strings.Contains(tc.err.Error(), tc.want) {
			t.Errorf("%s: fault must be returned with context, got %v", name, tc.err)
		}
	}
}
