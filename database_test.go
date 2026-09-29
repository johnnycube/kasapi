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

// databaseEntry is a get_databases entry as KAS sends it, password included.
func databaseEntry(login string, extra ...string) string {
	kv := []string{
		"database_name", login,
		"database_login", login,
		"database_password", "plaintext-password",
		"database_comment", "shop",
		"database_allowed_hosts", "localhost, 192.168.100.10, 192.168.100.0/24",
		"used_database_space", "1024",
		"in_progress", "FALSE",
	}
	return entry(append(kv, extra...)...)
}

func TestDatabases_ListMapsAllFields(t *testing.T) {
	c, _ := newFake(t, map[string]string{
		"get_databases": databaseEntry("d0123460") + databaseEntry("d0123461", "database_allowed_hosts", "", "in_progress", "TRUE"),
	})
	dbs, err := c.Databases.List(context.Background())
	if err != nil || len(dbs) != 2 {
		t.Fatalf("List: %v %v", dbs, err)
	}
	want := Database{
		Name: "d0123460", Login: "d0123460", Comment: "shop",
		AllowedHosts: []string{"localhost", "192.168.100.10", "192.168.100.0/24"}, UsedSpace: 1024,
	}
	if !reflect.DeepEqual(dbs[0], want) {
		t.Fatalf("got %+v, want %+v", dbs[0], want)
	}
	if dbs[1].AllowedHosts != nil || !dbs[1].InProgress {
		t.Fatalf("second database: %+v", dbs[1])
	}
}

func TestDatabases_PasswordIsNotMapped(t *testing.T) {
	c, _ := newFake(t, map[string]string{"get_databases": databaseEntry("d0123460")})
	db, err := c.Databases.Get(context.Background(), "d0123460")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	v := reflect.ValueOf(*db)
	for i := range v.NumField() {
		if f := v.Field(i); f.Kind() == reflect.String && strings.Contains(f.String(), "plaintext-password") {
			t.Fatalf("field %s carries the database password", v.Type().Field(i).Name)
		}
	}
}

func TestDatabases_ListEmptyAndFault(t *testing.T) {
	ctx := context.Background()
	for _, answer := range []string{"", "!empty_list"} {
		c, _ := newFake(t, map[string]string{"get_databases": answer})
		if dbs, err := c.Databases.List(ctx); err != nil || len(dbs) != 0 {
			t.Fatalf("answer %q: %v %v", answer, dbs, err)
		}
	}
	c, _ := newFake(t, map[string]string{"get_databases": "!no_mysql_on_this_server"})
	if _, err := c.Databases.List(ctx); err == nil || !strings.Contains(err.Error(), "listing databases") {
		t.Fatalf("fault must be returned with context, got %v", err)
	}
}

func TestDatabases_Get(t *testing.T) {
	ctx := context.Background()
	c, rec := newFake(t, map[string]string{"get_databases": databaseEntry("d0123460")})

	db, err := c.Databases.Get(ctx, "d0123460")
	if err != nil || db.Login != "d0123460" {
		t.Fatalf("Get: %+v %v", db, err)
	}
	wantParams(t, rec.last(t, "get_databases"), map[string]string{"database_login": "d0123460"})

	if _, err := c.Databases.Get(ctx, "d0000000"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
	if _, err := c.Databases.Get(ctx, ""); err == nil {
		t.Fatal("Get without login must fail")
	}
	c, _ = newFake(t, map[string]string{"get_databases": "!database_login_not_found"})
	if _, err := c.Databases.Get(ctx, "d0000000"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("not-found fault: expected ErrNotFound, got %v", err)
	}
	c, _ = newFake(t, map[string]string{"get_databases": "!kas_error"})
	if _, err := c.Databases.Get(ctx, "d0123460"); err == nil || errors.Is(err, ErrNotFound) ||
		!strings.Contains(err.Error(), "reading database d0123460") {
		t.Fatalf("other faults must be returned with context, got %v", err)
	}
}

func TestDatabases_Create(t *testing.T) {
	ctx := context.Background()
	c, rec := newFake(t, map[string]string{"add_database": "d0123460"})

	login, err := c.Databases.Create(ctx, Database{Comment: "shop", AllowedHosts: []string{"203.0.113.7", "203.0.113.0/24"}}, "S3cure!pass")
	if err != nil || login != "d0123460" {
		t.Fatalf("Create: %q %v", login, err)
	}
	wantParams(t, rec.last(t, "add_database"), map[string]string{
		"database_password": "S3cure!pass", "database_comment": "shop",
		"database_allowed_hosts": "203.0.113.7,203.0.113.0/24",
	})

	// Without allowed hosts the parameter is not sent.
	if _, err := c.Databases.Create(ctx, Database{Comment: "internal"}, "p"); err != nil {
		t.Fatalf("Create: %v", err)
	}
	wantAbsent(t, rec.last(t, "add_database"), "database_allowed_hosts", "database_login")

	before := rec.count("add_database")
	if _, err := c.Databases.Create(ctx, Database{Comment: "x"}, ""); err == nil {
		t.Error("Create without password must fail")
	}
	if _, err := c.Databases.Create(ctx, Database{}, "p"); err == nil {
		t.Error("Create without comment must fail")
	}
	if rec.count("add_database") != before {
		t.Fatal("invalid input must not reach the API")
	}

	c, _ = newFake(t, map[string]string{"add_database": "TRUE"})
	if _, err := c.Databases.Create(ctx, Database{Comment: "x"}, "p"); err == nil || !strings.Contains(err.Error(), "returned no login") {
		t.Fatalf("a create without login must fail, got %v", err)
	}
	c, _ = newFake(t, map[string]string{"add_database": "!max_database_reached"})
	if _, err := c.Databases.Create(ctx, Database{Comment: "x"}, "p"); err == nil ||
		!strings.Contains(err.Error(), `creating database "x"`) {
		t.Fatalf("fault must be returned with context, got %v", err)
	}
}

func TestDatabases_Update(t *testing.T) {
	ctx := context.Background()
	c, rec := newFake(t, map[string]string{"update_database": "TRUE"})

	if err := c.Databases.Update(ctx, Database{Login: "d0123460", Comment: "shop v2", AllowedHosts: []string{"203.0.113.7"}}); err != nil {
		t.Fatalf("Update: %v", err)
	}
	got := rec.last(t, "update_database")
	wantParams(t, got, map[string]string{
		"database_login": "d0123460", "database_comment": "shop v2", "database_allowed_hosts": "203.0.113.7",
	})
	wantAbsent(t, got, "database_new_password")

	// No allowed hosts is sent as the empty value, which closes access.
	if err := c.Databases.Update(ctx, Database{Login: "d0123460", Comment: "shop"}); err != nil {
		t.Fatalf("Update: %v", err)
	}
	if v, ok := rec.last(t, "update_database")["database_allowed_hosts"]; !ok || v != "" {
		t.Fatalf("closing access must send the empty value, got %v", rec.last(t, "update_database"))
	}

	before := rec.count("update_database")
	if err := c.Databases.Update(ctx, Database{Comment: "x"}); err == nil {
		t.Error("Update without login must fail")
	}
	if err := c.Databases.Update(ctx, Database{Login: "d0123460", Comment: "  "}); err == nil {
		t.Error("Update without comment must fail")
	}
	if rec.count("update_database") != before {
		t.Fatal("invalid input must not reach the API")
	}

	if err := c.Databases.UpdatePassword(ctx, "d0123460", "N3w!pass"); err != nil {
		t.Fatalf("UpdatePassword: %v", err)
	}
	got = rec.last(t, "update_database")
	wantParams(t, got, map[string]string{"database_login": "d0123460", "database_new_password": "N3w!pass"})
	wantAbsent(t, got, "database_comment", "database_allowed_hosts")
	if err := c.Databases.UpdatePassword(ctx, "", "p"); err == nil {
		t.Error("UpdatePassword without login must fail")
	}
	if err := c.Databases.UpdatePassword(ctx, "d0123460", ""); err == nil {
		t.Error("UpdatePassword without password must fail")
	}
}

func TestDatabases_UpdateAndDeleteFaults(t *testing.T) {
	ctx := context.Background()
	db := Database{Login: "d0123460", Comment: "x"}

	c, rec := newFake(t, map[string]string{"update_database": "!nothing_to_do", "delete_database": "TRUE"})
	if err := c.Databases.Update(ctx, db); err != nil {
		t.Errorf("Update: nothing_to_do must be success, got %v", err)
	}
	if err := c.Databases.UpdatePassword(ctx, db.Login, "p"); err != nil {
		t.Errorf("UpdatePassword: nothing_to_do must be success, got %v", err)
	}
	if err := c.Databases.Delete(ctx, db.Login); err != nil {
		t.Errorf("Delete: %v", err)
	}
	wantParams(t, rec.last(t, "delete_database"), map[string]string{"database_login": "d0123460"})
	if err := c.Databases.Delete(ctx, ""); err == nil {
		t.Error("Delete without login must fail")
	}

	c, _ = newFake(t, map[string]string{"update_database": "!database_login_not_found", "delete_database": "!database_login_not_found"})
	for name, err := range map[string]error{
		"Update": c.Databases.Update(ctx, db), "UpdatePassword": c.Databases.UpdatePassword(ctx, db.Login, "p"),
		"Delete": c.Databases.Delete(ctx, db.Login),
	} {
		if !errors.Is(err, ErrNotFound) {
			t.Errorf("%s: expected ErrNotFound, got %v", name, err)
		}
	}

	c, _ = newFake(t, map[string]string{"update_database": "!password_syntax_incorrect", "delete_database": "!in_progress"})
	for name, tc := range map[string]struct {
		err  error
		want string
	}{
		"Update":         {c.Databases.Update(ctx, db), "updating database d0123460"},
		"UpdatePassword": {c.Databases.UpdatePassword(ctx, db.Login, "p"), "updating password of database d0123460"},
		"Delete":         {c.Databases.Delete(ctx, db.Login), "deleting database d0123460"},
	} {
		var apiErr *APIError
		if !errors.As(tc.err, &apiErr) || !strings.Contains(tc.err.Error(), tc.want) {
			t.Errorf("%s: fault must be returned with context, got %v", name, tc.err)
		}
	}
}
