// Copyright 2026 The kasapi Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCLI_GetListsAndDrives(t *testing.T) {
	setupFake(t, map[string]string{
		"get_mailinglists": entry("mailinglist_name", "announce-example-com", "mailinglist_domain", "example.com",
			"mailinglist_password", "PLAINTEXT-PASSWORD", "mailinglist_is_active", "Y",
			"mailinglist_subscriber", "a@example.com\nb@example.com", "mailinglist_config", "# cfg"),
		"get_directoryprotection": entry("directory_user", "alice", "directory_path", "/admin/",
			"directory_authname", "Admin area", "directory_password", "PLAINTEXT-PASSWORD"),
		"get_sambausers": entry("samba_login", "s0000001", "samba_password", "PLAINTEXT-PASSWORD",
			"samba_path", "/share/", "samba_comment", "docs"),
	})
	for res, tc := range map[string]struct {
		name string
		want []string
	}{
		"ml":  {"mailinglist/announce-example-com", []string{"announce-example-com", "example.com", "SUBSCRIBERS"}},
		"dp":  {"directoryprotection//admin/:alice", []string{"/admin/", "alice", "Admin area"}},
		"smb": {"sambauser/s0000001", []string{"s0000001", "/share/", "docs"}},
	} {
		if out := capture(t, "get", res, "-o", "name"); strings.TrimSpace(out) != tc.name {
			t.Errorf("%s name output: %q", res, out)
		}
		out := capture(t, "get", res, "-o", "wide")
		for _, want := range tc.want {
			if !strings.Contains(out, want) {
				t.Errorf("%s wide lacks %q:\n%s", res, want, out)
			}
		}
		for _, format := range []string{"wide", "json", "yaml"} {
			if out := capture(t, "get", res, "-o", format); strings.Contains(out, "PLAINTEXT-PASSWORD") {
				t.Fatalf("%s -o %s prints a password:\n%s", res, format, out)
			}
		}
	}

	// The list shows no subscribers; one list read by name does.
	var items []map[string]any
	if err := json.Unmarshal([]byte(capture(t, "get", "ml", "-o", "json")), &items); err != nil || items[0]["subscribers"] != nil {
		t.Fatalf("list json: %v %v", items, err)
	}
	out := capture(t, "get", "ml", "announce-example-com", "-o", "json")
	if err := json.Unmarshal([]byte(out), &items); err != nil || len(items) != 1 {
		t.Fatalf("named json: %v\n%s", err, out)
	}
	if subs, _ := items[0]["subscribers"].([]any); len(subs) != 2 || items[0]["config"] != "# cfg" {
		t.Fatalf("named list lacks details: %v", items[0])
	}
	if out := capture(t, "get", "ml", "announce-example-com", "-o", "wide"); !strings.Contains(out, " 2") {
		t.Fatalf("wide output lacks the subscriber count:\n%s", out)
	}
	wantErr(t, "not found", "get", "ml", "other-example-com")
}

func TestCLI_CreateMailingList(t *testing.T) {
	rec := setupFake(t, map[string]string{"add_mailinglist": "announce-example-com"})
	setStdin(t, "S3cure!\n")
	out := capture(t, "create", "mailinglist", "--address", "announce@example.com", "--password-stdin")
	if strings.TrimSpace(out) != "mailinglist/announce-example-com created" {
		t.Fatalf("output: %q", out)
	}
	wantParams(t, rec.last(t, "add_mailinglist"), map[string]string{
		"mailinglist_name": "announce", "mailinglist_domain": "example.com", "mailinglist_password": "S3cure!",
	})
	wantErr(t, "--address", "create", "ml", "--password-stdin")
	setStdin(t, "")
	wantErr(t, "reading input", "create", "ml", "--address", "a@example.com", "--password-stdin")
}

func TestCLI_UpdateMailingList(t *testing.T) {
	rec := setupFake(t, map[string]string{"update_mailinglist": "TRUE"})
	config := filepath.Join(t.TempDir(), "majordomo.cf")
	if err := os.WriteFile(config, []byte("# new config"), 0o600); err != nil {
		t.Fatal(err)
	}
	out := capture(t, "update", "ml", "announce-example-com",
		"--subscriber", "a@example.com,b@example.com", "--restrict-post", "", "--active=false", "--config", config)
	if strings.TrimSpace(out) != "mailinglist/announce-example-com updated" {
		t.Fatalf("output: %q", out)
	}
	wantParams(t, rec.last(t, "update_mailinglist"), map[string]string{
		"mailinglist_name": "announce-example-com", "subscriber": "a@example.com\nb@example.com",
		"restrict_post": "", "is_active": "N", "config": "# new config",
	})
	capture(t, "update", "ml", "announce-example-com", "--active")
	got := rec.last(t, "update_mailinglist")
	wantParams(t, got, map[string]string{"is_active": "Y"})
	wantAbsent(t, got, "subscriber", "restrict_post", "config")

	before := rec.count("update_mailinglist")
	wantErr(t, "nothing to update", "update", "ml", "announce-example-com")
	wantErr(t, "--config", "update", "ml", "announce-example-com", "--config", filepath.Join(t.TempDir(), "missing"))
	wantErr(t, "invalid subscriber", "update", "ml", "announce-example-com", "--subscriber", "nope")
	if rec.count("update_mailinglist") != before {
		t.Fatal("invalid input must not reach the API")
	}
}

func TestCLI_DirectoryProtection(t *testing.T) {
	rec := setupFake(t, map[string]string{
		"add_directoryprotection": "TRUE", "update_directoryprotection": "TRUE", "delete_directoryprotection": "TRUE",
		"get_directoryprotection": entry("directory_user", "alice", "directory_path", "/admin/", "directory_authname", "Admin area"),
	})
	setStdin(t, "S3cure!\n")
	out := capture(t, "create", "dp", "--path", "/admin/", "--user", "alice", "--auth-name", "Admin area", "--password-stdin")
	if strings.TrimSpace(out) != "directoryprotection//admin/:alice created" {
		t.Fatalf("create output: %q", out)
	}
	wantParams(t, rec.last(t, "add_directoryprotection"), map[string]string{
		"directory_path": "/admin/", "directory_user": "alice", "directory_authname": "Admin area", "directory_password": "S3cure!",
	})
	wantErr(t, "--path, --user and --auth-name are required", "create", "dp", "--path", "/admin/", "--password-stdin")

	// Update keeps the realm unless --auth-name is given, and always sets the password.
	setStdin(t, "N3w!\n")
	out = capture(t, "update", "dp", "/admin/:alice", "--password-stdin")
	if strings.TrimSpace(out) != "directoryprotection//admin/:alice updated" {
		t.Fatalf("update output: %q", out)
	}
	wantParams(t, rec.last(t, "update_directoryprotection"), map[string]string{
		"directory_path": "/admin/", "directory_user": "alice", "directory_authname": "Admin area", "directory_password": "N3w!",
	})
	setStdin(t, "N3w!\n")
	capture(t, "update", "dp", "/admin/:alice", "--auth-name", "Staff", "--password-stdin")
	wantParams(t, rec.last(t, "update_directoryprotection"), map[string]string{"directory_authname": "Staff"})
	setStdin(t, "N3w!\n")
	wantErr(t, "not found", "update", "dp", "/admin/:bob", "--password-stdin")
	wantErr(t, "expected <path>:<user>", "update", "dp", "/admin/", "--password-stdin")
	setStdin(t, "")
	wantErr(t, "reading input", "update", "dp", "/admin/:alice", "--password-stdin")

	out = capture(t, "delete", "dp", "/admin/:alice")
	if strings.TrimSpace(out) != "directoryprotection//admin/:alice deleted" {
		t.Fatalf("delete output: %q", out)
	}
	wantParams(t, rec.last(t, "delete_directoryprotection"), map[string]string{"directory_path": "/admin/", "directory_user": "alice"})
	wantErr(t, "expected <path>:<user>", "delete", "dp", "alice:")
}

func TestSplitDirectoryID(t *testing.T) {
	for id, want := range map[string][2]string{
		"/admin/:alice":   {"/admin/", "alice"},
		"/a:b/c/:carol":   {"/a:b/c/", "carol"},
		"/example.com/:x": {"/example.com/", "x"},
	} {
		path, user, err := splitDirectoryID(id)
		if err != nil || path != want[0] || user != want[1] {
			t.Errorf("splitDirectoryID(%q) = %q, %q, %v", id, path, user, err)
		}
	}
	for _, id := range []string{"", "alice", ":alice", "/admin/:"} {
		if _, _, err := splitDirectoryID(id); err == nil {
			t.Errorf("splitDirectoryID(%q) must fail", id)
		}
	}
}

func TestCLI_SambaUser(t *testing.T) {
	rec := setupFake(t, map[string]string{
		"add_sambauser": "s0000003", "update_sambauser": "TRUE", "delete_sambauser": "TRUE",
		"get_sambausers": entry("samba_login", "s0000003", "samba_path", "/share/", "samba_comment", "docs"),
	})
	setStdin(t, "S3cure!\n")
	out := capture(t, "create", "smb", "--path", "/share/", "--comment", "docs", "--password-stdin")
	if strings.TrimSpace(out) != "sambauser/s0000003 created" {
		t.Fatalf("create output: %q", out)
	}
	wantParams(t, rec.last(t, "add_sambauser"), map[string]string{"samba_path": "/share/", "samba_comment": "docs", "samba_password": "S3cure!"})
	wantErr(t, "--path and --comment are required", "create", "smb", "--path", "/share/", "--password-stdin")

	out = capture(t, "update", "smb", "s0000003", "--comment", "documents")
	if strings.TrimSpace(out) != "sambauser/s0000003 updated" {
		t.Fatalf("update output: %q", out)
	}
	got := rec.last(t, "update_sambauser")
	wantParams(t, got, map[string]string{"samba_login": "s0000003", "samba_path": "/share/", "samba_comment": "documents"})
	wantAbsent(t, got, "samba_new_password")
	capture(t, "update", "smb", "s0000003", "--path", "/media/")
	wantParams(t, rec.last(t, "update_sambauser"), map[string]string{"samba_path": "/media/", "samba_comment": "docs"})

	setStdin(t, "N3w!\n")
	capture(t, "update", "smb", "s0000003", "--password-stdin")
	got = rec.last(t, "update_sambauser")
	wantParams(t, got, map[string]string{"samba_login": "s0000003", "samba_new_password": "N3w!"})
	wantAbsent(t, got, "samba_path")
	wantErr(t, "not found", "update", "smb", "s0000009", "--comment", "x")

	if out := capture(t, "delete", "smb", "s0000003"); strings.TrimSpace(out) != "sambauser/s0000003 deleted" {
		t.Fatalf("delete output: %q", out)
	}
	wantParams(t, rec.last(t, "delete_sambauser"), map[string]string{"samba_login": "s0000003"})
	setStdin(t, "")
	wantErr(t, "reading input", "create", "smb", "--path", "/share/", "--comment", "docs", "--password-stdin")
}

func TestCLI_ListWriteFaults(t *testing.T) {
	setupFake(t, map[string]string{
		"add_mailinglist": "!mailinglist_already_exists", "add_directoryprotection": "!duplicate_directory_user",
		"add_sambauser": "!max_sambauser_reached", "update_directoryprotection": "!in_progress",
		"get_directoryprotection": entry("directory_user", "alice", "directory_path", "/admin/", "directory_authname", "x"),
	})
	for want, args := range map[string][]string{
		"mailinglist_already_exists": {"create", "ml", "--address", "a@example.com", "--password-stdin"},
		"duplicate_directory_user":   {"create", "dp", "--path", "/admin/", "--user", "alice", "--auth-name", "x", "--password-stdin"},
		"max_sambauser_reached":      {"create", "smb", "--path", "/a/", "--comment", "x", "--password-stdin"},
		"in_progress":                {"update", "dp", "/admin/:alice", "--password-stdin"},
	} {
		setStdin(t, "p\n")
		wantErr(t, want, args...)
	}
	setStdin(t, "")
	wantErr(t, "reading input", "create", "dp", "--path", "/admin/", "--user", "alice", "--auth-name", "x", "--password-stdin")
}
