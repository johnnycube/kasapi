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

// sambaEntry is a get_sambausers entry as KAS sends it, password included.
func sambaEntry(login string, extra ...string) string {
	kv := []string{
		"samba_login", login, "samba_password", "plaintext-password",
		"samba_path", "/example.com/share/", "samba_comment", "Shared documents",
		"in_progress", "FALSE",
	}
	return entry(append(kv, extra...)...)
}

func TestSamba_ListAndGet(t *testing.T) {
	ctx := context.Background()
	c, rec := newFake(t, map[string]string{
		"get_sambausers": sambaEntry("s0000001") + sambaEntry("s0000002", "in_progress", "TRUE"),
	})
	users, err := c.Samba.List(ctx)
	if err != nil || len(users) != 2 {
		t.Fatalf("List: %v %v", users, err)
	}
	if want := (SambaUser{Login: "s0000001", Path: "/example.com/share/", Comment: "Shared documents"}); users[0] != want {
		t.Fatalf("got %+v, want %+v", users[0], want)
	}
	if !users[1].InProgress {
		t.Fatalf("in_progress: %+v", users[1])
	}

	u, err := c.Samba.Get(ctx, "s0000002")
	if err != nil || u.Login != "s0000002" {
		t.Fatalf("Get: %+v %v", u, err)
	}
	wantParams(t, rec.last(t, "get_sambausers"), map[string]string{"samba_login": "s0000002"})
	v := reflect.ValueOf(*u)
	for i := range v.NumField() {
		if f := v.Field(i); f.Kind() == reflect.String && strings.Contains(f.String(), "plaintext-password") {
			t.Fatalf("field %s carries the password", v.Type().Field(i).Name)
		}
	}
	if _, err := c.Samba.Get(ctx, "s0000009"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
	if _, err := c.Samba.Get(ctx, ""); err == nil {
		t.Fatal("Get without login must fail")
	}
}

func TestSamba_ListAndGetFaults(t *testing.T) {
	ctx := context.Background()
	c, _ := newFake(t, map[string]string{"get_sambausers": "!samba_login_not_found"})
	if _, err := c.Samba.Get(ctx, "s1"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
	c, _ = newFake(t, map[string]string{"get_sambausers": "!kas_error"})
	if _, err := c.Samba.List(ctx); err == nil || !strings.Contains(err.Error(), "listing network drive users") {
		t.Fatalf("List fault: %v", err)
	}
	if _, err := c.Samba.Get(ctx, "s1"); err == nil || errors.Is(err, ErrNotFound) ||
		!strings.Contains(err.Error(), "reading network drive user s1") {
		t.Fatalf("Get fault: %v", err)
	}
}

func TestSamba_Create(t *testing.T) {
	ctx := context.Background()
	c, rec := newFake(t, map[string]string{"add_sambauser": "s0000003"})
	login, err := c.Samba.Create(ctx, SambaUser{Path: "/share/", Comment: "docs"}, "S3cure!")
	if err != nil || login != "s0000003" {
		t.Fatalf("Create: %q %v", login, err)
	}
	got := rec.last(t, "add_sambauser")
	wantParams(t, got, map[string]string{"samba_path": "/share/", "samba_comment": "docs", "samba_password": "S3cure!"})
	wantAbsent(t, got, "samba_login", "samba_new_password")

	for name, tc := range map[string]struct {
		u  SambaUser
		pw string
	}{
		"no path":     {SambaUser{Comment: "x"}, "p"},
		"no comment":  {SambaUser{Path: "/x/"}, "p"},
		"no password": {SambaUser{Path: "/x/", Comment: "x"}, ""},
	} {
		if _, err := c.Samba.Create(ctx, tc.u, tc.pw); err == nil {
			t.Errorf("Create %s must fail", name)
		}
	}
	if rec.count("add_sambauser") != 1 {
		t.Fatal("invalid input must not reach the API")
	}

	c, _ = newFake(t, map[string]string{"add_sambauser": "TRUE"})
	if _, err := c.Samba.Create(ctx, SambaUser{Path: "/x/", Comment: "x"}, "p"); err == nil || !strings.Contains(err.Error(), "returned no login") {
		t.Fatalf("a create without login must fail, got %v", err)
	}
	c, _ = newFake(t, map[string]string{"add_sambauser": "!max_sambauser_reached"})
	if _, err := c.Samba.Create(ctx, SambaUser{Path: "/x/", Comment: "x"}, "p"); err == nil ||
		!strings.Contains(err.Error(), `creating network drive user "x"`) {
		t.Fatalf("fault must be returned with context, got %v", err)
	}
}

func TestSamba_UpdateAndDelete(t *testing.T) {
	ctx := context.Background()
	c, rec := newFake(t, map[string]string{"update_sambauser": "TRUE", "delete_sambauser": "TRUE"})
	u := SambaUser{Login: "s1", Path: "/share/", Comment: "docs"}
	if err := c.Samba.Update(ctx, u); err != nil {
		t.Fatalf("Update: %v", err)
	}
	got := rec.last(t, "update_sambauser")
	wantParams(t, got, map[string]string{"samba_login": "s1", "samba_path": "/share/", "samba_comment": "docs"})
	wantAbsent(t, got, "samba_new_password", "samba_password")
	if err := c.Samba.UpdatePassword(ctx, "s1", "N3w!"); err != nil {
		t.Fatalf("UpdatePassword: %v", err)
	}
	got = rec.last(t, "update_sambauser")
	wantParams(t, got, map[string]string{"samba_login": "s1", "samba_new_password": "N3w!"})
	wantAbsent(t, got, "samba_path", "samba_comment")
	if err := c.Samba.Delete(ctx, "s1"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	wantParams(t, rec.last(t, "delete_sambauser"), map[string]string{"samba_login": "s1"})

	for name, err := range map[string]error{
		"Update without login":           c.Samba.Update(ctx, SambaUser{Path: "/x/", Comment: "x"}),
		"Update without path":            c.Samba.Update(ctx, SambaUser{Login: "s1", Comment: "x"}),
		"UpdatePassword without login":   c.Samba.UpdatePassword(ctx, "", "p"),
		"UpdatePassword without secret":  c.Samba.UpdatePassword(ctx, "s1", ""),
		"Delete without login":           c.Samba.Delete(ctx, ""),
		"Update without comment":         c.Samba.Update(ctx, SambaUser{Login: "s1", Path: "/x/"}),
		"UpdatePassword with empty both": c.Samba.UpdatePassword(ctx, "", ""),
	} {
		if err == nil {
			t.Errorf("%s must fail", name)
		}
	}
}

func TestSamba_UpdateAndDeleteFaults(t *testing.T) {
	ctx := context.Background()
	u := SambaUser{Login: "s1", Path: "/x/", Comment: "x"}
	c, _ := newFake(t, map[string]string{"update_sambauser": "!nothing_to_do"})
	if err := c.Samba.Update(ctx, u); err != nil {
		t.Errorf("nothing_to_do must be success, got %v", err)
	}
	c, _ = newFake(t, map[string]string{"update_sambauser": "!samba_login_not_found", "delete_sambauser": "!samba_login_not_found"})
	for name, err := range map[string]error{
		"Update": c.Samba.Update(ctx, u), "UpdatePassword": c.Samba.UpdatePassword(ctx, "s1", "p"),
		"Delete": c.Samba.Delete(ctx, "s1"),
	} {
		if !errors.Is(err, ErrNotFound) {
			t.Errorf("%s: expected ErrNotFound, got %v", name, err)
		}
	}
	c, _ = newFake(t, map[string]string{"update_sambauser": "!in_progress", "delete_sambauser": "!in_progress"})
	for name, tc := range map[string]struct {
		err  error
		want string
	}{
		"Update":         {c.Samba.Update(ctx, u), "updating network drive user s1"},
		"UpdatePassword": {c.Samba.UpdatePassword(ctx, "s1", "p"), "updating password of network drive user s1"},
		"Delete":         {c.Samba.Delete(ctx, "s1"), "deleting network drive user s1"},
	} {
		if tc.err == nil || !strings.Contains(tc.err.Error(), tc.want) {
			t.Errorf("%s: fault must be returned with context, got %v", name, tc.err)
		}
	}
}
