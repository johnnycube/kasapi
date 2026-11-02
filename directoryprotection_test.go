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

// dirEntry is a get_directoryprotection entry as KAS sends it, password included.
func dirEntry(path, user string) string {
	return entry(
		"directory_user", user, "directory_path", path, "directory_authname", "Admin area",
		"directory_password", "plaintext-password", "in_progress", "FALSE",
	)
}

func TestDirectoryProtection_ListAndGet(t *testing.T) {
	ctx := context.Background()
	c, rec := newFake(t, map[string]string{
		"get_directoryprotection": dirEntry("/admin/", "alice") + dirEntry("/admin/", "bob"),
	})
	all, err := c.DirectoryProtection.List(ctx)
	if err != nil || len(all) != 2 {
		t.Fatalf("List: %v %v", all, err)
	}
	if want := (DirectoryProtection{Path: "/admin/", User: "alice", AuthName: "Admin area"}); all[0] != want {
		t.Fatalf("got %+v, want %+v", all[0], want)
	}
	wantAbsent(t, rec.last(t, "get_directoryprotection"), "directory_path")

	// The trailing slash does not matter.
	p, err := c.DirectoryProtection.Get(ctx, "/admin", "bob")
	if err != nil || p.User != "bob" {
		t.Fatalf("Get: %+v %v", p, err)
	}
	wantParams(t, rec.last(t, "get_directoryprotection"), map[string]string{"directory_path": "/admin"})
	v := reflect.ValueOf(*p)
	for i := range v.NumField() {
		if f := v.Field(i); f.Kind() == reflect.String && strings.Contains(f.String(), "plaintext-password") {
			t.Fatalf("field %s carries the password", v.Type().Field(i).Name)
		}
	}
	if _, err := c.DirectoryProtection.Get(ctx, "/admin/", "carol"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
	for _, args := range [][2]string{{"", "a"}, {"/x/", ""}, {"/x/", "a:b"}} {
		if _, err := c.DirectoryProtection.Get(ctx, args[0], args[1]); err == nil {
			t.Errorf("Get%v must fail", args)
		}
	}
}

func TestDirectoryProtection_ListAndGetFaults(t *testing.T) {
	ctx := context.Background()
	c, _ := newFake(t, map[string]string{"get_directoryprotection": "!empty_list"})
	if all, err := c.DirectoryProtection.List(ctx); err != nil || len(all) != 0 {
		t.Fatalf("empty list: %v %v", all, err)
	}
	if _, err := c.DirectoryProtection.Get(ctx, "/x/", "a"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
	c, _ = newFake(t, map[string]string{"get_directoryprotection": "!kas_error"})
	if _, err := c.DirectoryProtection.List(ctx); err == nil || !strings.Contains(err.Error(), "listing directory protections") {
		t.Fatalf("List fault: %v", err)
	}
	if _, err := c.DirectoryProtection.Get(ctx, "/x/", "a"); err == nil || errors.Is(err, ErrNotFound) ||
		!strings.Contains(err.Error(), "reading directory protection /x/") {
		t.Fatalf("Get fault: %v", err)
	}
}

func TestDirectoryProtection_CreateAndUpdate(t *testing.T) {
	ctx := context.Background()
	c, rec := newFake(t, map[string]string{"add_directoryprotection": "TRUE", "update_directoryprotection": "TRUE"})
	p := DirectoryProtection{Path: "/admin/", User: "alice", AuthName: "Admin area"}
	want := map[string]string{
		"directory_path": "/admin/", "directory_user": "alice",
		"directory_password": "S3cure!", "directory_authname": "Admin area",
	}
	if err := c.DirectoryProtection.Create(ctx, p, "S3cure!"); err != nil {
		t.Fatalf("Create: %v", err)
	}
	wantParams(t, rec.last(t, "add_directoryprotection"), want)
	if err := c.DirectoryProtection.Update(ctx, p, "S3cure!"); err != nil {
		t.Fatalf("Update: %v", err)
	}
	wantParams(t, rec.last(t, "update_directoryprotection"), want)

	for name, tc := range map[string]struct {
		p  DirectoryProtection
		pw string
	}{
		"no path":     {DirectoryProtection{User: "a", AuthName: "x"}, "p"},
		"no user":     {DirectoryProtection{Path: "/a/", AuthName: "x"}, "p"},
		"colon":       {DirectoryProtection{Path: "/a/", User: "a:b", AuthName: "x"}, "p"},
		"no password": {DirectoryProtection{Path: "/a/", User: "a", AuthName: "x"}, ""},
		"no authname": {DirectoryProtection{Path: "/a/", User: "a"}, "p"},
	} {
		if err := c.DirectoryProtection.Create(ctx, tc.p, tc.pw); err == nil {
			t.Errorf("Create %s must fail", name)
		}
		if err := c.DirectoryProtection.Update(ctx, tc.p, tc.pw); err == nil {
			t.Errorf("Update %s must fail", name)
		}
	}
	if rec.count("add_directoryprotection") != 1 || rec.count("update_directoryprotection") != 1 {
		t.Fatal("invalid input must not reach the API")
	}

	c, _ = newFake(t, map[string]string{"add_directoryprotection": "!duplicate_directory_user", "update_directoryprotection": "!in_progress"})
	if err := c.DirectoryProtection.Create(ctx, p, "p"); err == nil ||
		!strings.Contains(err.Error(), "creating directory protection /admin/ for alice") {
		t.Errorf("Create fault: %v", err)
	}
	if err := c.DirectoryProtection.Update(ctx, p, "p"); err == nil ||
		!strings.Contains(err.Error(), "updating directory protection /admin/ for alice") {
		t.Errorf("Update fault: %v", err)
	}
	c, _ = newFake(t, map[string]string{"update_directoryprotection": "!nothing_to_do"})
	if err := c.DirectoryProtection.Update(ctx, p, "p"); err != nil {
		t.Errorf("nothing_to_do must be success, got %v", err)
	}
}

func TestDirectoryProtection_Delete(t *testing.T) {
	ctx := context.Background()
	c, rec := newFake(t, map[string]string{"delete_directoryprotection": "TRUE"})
	if err := c.DirectoryProtection.Delete(ctx, "/admin/", "alice"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	got := rec.last(t, "delete_directoryprotection")
	wantParams(t, got, map[string]string{"directory_path": "/admin/", "directory_user": "alice"})
	wantAbsent(t, got, "directory_password")
	if err := c.DirectoryProtection.Delete(ctx, "", "alice"); err == nil {
		t.Error("Delete without path must fail")
	}
	// KAS documents no not-found fault for directory protections, so an
	// unknown code is returned as it is rather than guessed to be one.
	c, _ = newFake(t, map[string]string{"delete_directoryprotection": "!directory_not_found"})
	if err := c.DirectoryProtection.Delete(ctx, "/admin/", "alice"); err == nil || errors.Is(err, ErrNotFound) {
		t.Errorf("an undocumented fault must surface, got %v", err)
	}
	c, _ = newFake(t, map[string]string{"delete_directoryprotection": "!in_progress"})
	if err := c.DirectoryProtection.Delete(ctx, "/admin/", "alice"); err == nil ||
		!strings.Contains(err.Error(), "deleting directory protection /admin/ for alice") {
		t.Errorf("Delete fault: %v", err)
	}
}
