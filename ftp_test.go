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

// ftpEntry is a get_ftpusers entry as KAS sends it, passwords included.
func ftpEntry(login string, extra ...string) string {
	kv := []string{
		"ftp_login", login,
		"ftp_password", "plaintext-password",
		"ftp_passwort", "plaintext-password",
		"ftp_path", "/logs/",
		"ftp_comment", "log reader",
		"ftp_is_main_user", "N",
		"ftp_permission_list", "Y",
		"ftp_permission_write", "N",
		"ftp_permission_read", "Y",
		"ftp_virus_clamav", "Y",
		"in_progress", "FALSE",
	}
	return entry(append(kv, extra...)...)
}

func TestFTP_ListMapsAllFields(t *testing.T) {
	c, _ := newFake(t, map[string]string{
		"get_ftpusers": ftpEntry("w0123456", "ftp_is_main_user", "Y", "ftp_permission_write", "Y", "ftp_path", "/") +
			ftpEntry("f0000001", "in_progress", "TRUE"),
	})
	users, err := c.FTP.List(context.Background())
	if err != nil || len(users) != 2 {
		t.Fatalf("List: %v %v", users, err)
	}
	want := FTPUser{
		Login: "f0000001", Path: "/logs/", Comment: "log reader",
		Read: true, Write: false, List: true, VirusScan: true, InProgress: true,
	}
	if users[1] != want {
		t.Fatalf("got %+v, want %+v", users[1], want)
	}
	if !users[0].MainUser || !users[0].Write || users[0].Path != "/" {
		t.Fatalf("main user: %+v", users[0])
	}
}

func TestFTP_PasswordIsNotMapped(t *testing.T) {
	c, _ := newFake(t, map[string]string{"get_ftpusers": ftpEntry("f0000001")})
	u, err := c.FTP.Get(context.Background(), "f0000001")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	v := reflect.ValueOf(*u)
	for i := range v.NumField() {
		if f := v.Field(i); f.Kind() == reflect.String && strings.Contains(f.String(), "plaintext-password") {
			t.Fatalf("field %s carries the FTP password", v.Type().Field(i).Name)
		}
	}
}

func TestFTP_ListEmptyAndFault(t *testing.T) {
	ctx := context.Background()
	for _, answer := range []string{"", "!empty_list"} {
		c, _ := newFake(t, map[string]string{"get_ftpusers": answer})
		if users, err := c.FTP.List(ctx); err != nil || len(users) != 0 {
			t.Fatalf("answer %q: %v %v", answer, users, err)
		}
	}
	c, _ := newFake(t, map[string]string{"get_ftpusers": "!kas_error"})
	if _, err := c.FTP.List(ctx); err == nil || !strings.Contains(err.Error(), "listing FTP users") {
		t.Fatalf("fault must be returned with context, got %v", err)
	}
}

func TestFTP_Get(t *testing.T) {
	ctx := context.Background()
	c, rec := newFake(t, map[string]string{"get_ftpusers": ftpEntry("f0000001")})

	u, err := c.FTP.Get(ctx, "f0000001")
	if err != nil || u.Login != "f0000001" {
		t.Fatalf("Get: %+v %v", u, err)
	}
	wantParams(t, rec.last(t, "get_ftpusers"), map[string]string{"ftp_login": "f0000001"})

	if _, err := c.FTP.Get(ctx, "f0000002"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
	if _, err := c.FTP.Get(ctx, ""); err == nil {
		t.Fatal("Get without login must fail")
	}
	c, _ = newFake(t, map[string]string{"get_ftpusers": "!ftp_login_not_found"})
	if _, err := c.FTP.Get(ctx, "f0000009"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("not-found fault: expected ErrNotFound, got %v", err)
	}
	c, _ = newFake(t, map[string]string{"get_ftpusers": "!kas_error"})
	if _, err := c.FTP.Get(ctx, "f0000001"); err == nil || errors.Is(err, ErrNotFound) ||
		!strings.Contains(err.Error(), "reading FTP user f0000001") {
		t.Fatalf("other faults must be returned with context, got %v", err)
	}
}

func TestFTP_Create(t *testing.T) {
	ctx := context.Background()
	c, rec := newFake(t, map[string]string{"add_ftpuser": "f0000004"})

	login, err := c.FTP.Create(ctx, FTPUser{Path: "/logs/", Comment: "log reader", Read: true, List: true}, "S3cure!pass")
	if err != nil || login != "f0000004" {
		t.Fatalf("Create: %q %v", login, err)
	}
	wantParams(t, rec.last(t, "add_ftpuser"), map[string]string{
		"ftp_password": "S3cure!pass", "ftp_path": "/logs/", "ftp_comment": "log reader",
		"ftp_permission_read": "Y", "ftp_permission_write": "N", "ftp_permission_list": "Y",
		"ftp_virus_clamav": "N",
	})

	// The zero value grants nothing and leaves the path to KAS.
	if _, err := c.FTP.Create(ctx, FTPUser{Comment: "locked"}, "p"); err != nil {
		t.Fatalf("Create: %v", err)
	}
	got := rec.last(t, "add_ftpuser")
	wantParams(t, got, map[string]string{
		"ftp_permission_read": "N", "ftp_permission_write": "N", "ftp_permission_list": "N",
	})
	wantAbsent(t, got, "ftp_path", "ftp_login", "ftp_new_password")

	before := rec.count("add_ftpuser")
	if _, err := c.FTP.Create(ctx, FTPUser{Comment: "x"}, ""); err == nil {
		t.Error("Create without password must fail")
	}
	if _, err := c.FTP.Create(ctx, FTPUser{}, "p"); err == nil {
		t.Error("Create without comment must fail")
	}
	if rec.count("add_ftpuser") != before {
		t.Fatal("invalid input must not reach the API")
	}

	c, _ = newFake(t, map[string]string{"add_ftpuser": "TRUE"})
	if _, err := c.FTP.Create(ctx, FTPUser{Comment: "x"}, "p"); err == nil || !strings.Contains(err.Error(), "returned no login") {
		t.Fatalf("a create without login must fail, got %v", err)
	}
	c, _ = newFake(t, map[string]string{"add_ftpuser": "!max_ftpuser_reached"})
	_, err = c.FTP.Create(ctx, FTPUser{Comment: "x"}, "p")
	var apiErr *APIError
	if !errors.As(err, &apiErr) || !strings.Contains(err.Error(), `creating FTP user "x"`) {
		t.Fatalf("fault must be returned with context, got %v", err)
	}
}

func TestFTP_Update(t *testing.T) {
	ctx := context.Background()
	c, rec := newFake(t, map[string]string{"update_ftpuser": "TRUE"})

	err := c.FTP.Update(ctx, FTPUser{Login: "f0000001", Path: "/web/", Comment: "deploy", Read: true, Write: true, List: true, VirusScan: true})
	if err != nil {
		t.Fatalf("Update: %v", err)
	}
	got := rec.last(t, "update_ftpuser")
	wantParams(t, got, map[string]string{
		"ftp_login": "f0000001", "ftp_path": "/web/", "ftp_comment": "deploy",
		"ftp_permission_read": "Y", "ftp_permission_write": "Y", "ftp_permission_list": "Y",
		"ftp_virus_clamav": "Y",
	})
	wantAbsent(t, got, "ftp_new_password", "ftp_password")

	if err := c.FTP.Update(ctx, FTPUser{Comment: "x"}); err == nil {
		t.Error("Update without login must fail")
	}

	if err := c.FTP.UpdatePassword(ctx, "f0000001", "N3w!pass"); err != nil {
		t.Fatalf("UpdatePassword: %v", err)
	}
	got = rec.last(t, "update_ftpuser")
	wantParams(t, got, map[string]string{"ftp_login": "f0000001", "ftp_new_password": "N3w!pass"})
	wantAbsent(t, got, "ftp_permission_read", "ftp_comment", "ftp_path")
	if err := c.FTP.UpdatePassword(ctx, "", "p"); err == nil {
		t.Error("UpdatePassword without login must fail")
	}
	if err := c.FTP.UpdatePassword(ctx, "f0000001", ""); err == nil {
		t.Error("UpdatePassword without password must fail")
	}
}

func TestFTP_UpdateAndDeleteFaults(t *testing.T) {
	ctx := context.Background()
	u := FTPUser{Login: "f0000001", Comment: "x"}

	c, _ := newFake(t, map[string]string{"update_ftpuser": "!nothing_to_do", "delete_ftpuser": "TRUE"})
	if err := c.FTP.Update(ctx, u); err != nil {
		t.Errorf("Update: nothing_to_do must be success, got %v", err)
	}
	if err := c.FTP.UpdatePassword(ctx, u.Login, "p"); err != nil {
		t.Errorf("UpdatePassword: nothing_to_do must be success, got %v", err)
	}
	if err := c.FTP.Delete(ctx, u.Login); err != nil {
		t.Errorf("Delete: %v", err)
	}
	if err := c.FTP.Delete(ctx, ""); err == nil {
		t.Error("Delete without login must fail")
	}

	c, _ = newFake(t, map[string]string{"update_ftpuser": "!ftp_login_not_found", "delete_ftpuser": "!ftp_login_not_found"})
	for name, err := range map[string]error{
		"Update": c.FTP.Update(ctx, u), "UpdatePassword": c.FTP.UpdatePassword(ctx, u.Login, "p"),
		"Delete": c.FTP.Delete(ctx, u.Login),
	} {
		if !errors.Is(err, ErrNotFound) {
			t.Errorf("%s: expected ErrNotFound, got %v", name, err)
		}
	}

	c, _ = newFake(t, map[string]string{"update_ftpuser": "!in_progress", "delete_ftpuser": "!ftp_login_belongs_to_account"})
	for name, tc := range map[string]struct {
		err  error
		want string
	}{
		"Update":         {c.FTP.Update(ctx, u), "updating FTP user f0000001"},
		"UpdatePassword": {c.FTP.UpdatePassword(ctx, u.Login, "p"), "updating password of FTP user f0000001"},
		"Delete":         {c.FTP.Delete(ctx, u.Login), "deleting FTP user f0000001"},
	} {
		var apiErr *APIError
		if !errors.As(tc.err, &apiErr) || !strings.Contains(tc.err.Error(), tc.want) {
			t.Errorf("%s: fault must be returned with context, got %v", name, tc.err)
		}
	}
}
