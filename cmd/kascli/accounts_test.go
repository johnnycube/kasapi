// Copyright 2026 The kasapi Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"

	kasapi "github.com/johnnycube/kasapi"
	"github.com/johnnycube/kasapi/kasapitest"
)

func accountEntry(login string) string {
	return entry(
		"account_login", login, "account_password", "PLAINTEXT-PASSWORD", "account_comment", "shop",
		"account_contact_mail", "ops@example.org", "max_webspace", "8192", "max_mail_list", "3",
		"logging", "kurz", "logage", "7", "dns_settings", "Y", "ssh_access", "N", "account_2fa", "Y",
	)
}

func settingsXML() string {
	fp := kasapitest.MapItem("SHA256:", "AbCd")
	return kasapitest.MapItem("settings",
		kasapitest.MapItem("account_login", "w0123456")+
			kasapitest.MapItem("account_comment", "Administrator")+
			kasapitest.MapItem("account_password", "PLAINTEXT-PASSWORD")+
			kasapitest.MapItem("server", "d012345")+
			kasapitest.MapItem("logging", "voll")+
			kasapitest.MapItem("logage", "190")+
			kasapitest.MapItem("ssh_access", "Y")+
			kasapitest.MapItem("ssh_keys", "ssh-ed25519 AAAA one")+
			kasapitest.MapItem("ssh_fingerprints", kasapitest.MapItem("ED25519", fp)))
}

func resourceXML(key, max, used, free string) string {
	return kasapitest.MapItem(key, kasapitest.MapItem("max", max)+kasapitest.MapItem("used", used)+
		kasapitest.MapItem("free", free)+kasapitest.MapItem("created", "1")+
		kasapitest.MapItem("reserved", "2")+kasapitest.MapItem("exceeded", "false"))
}

func TestCLI_GetAccountResources(t *testing.T) {
	setupFake(t, map[string]string{
		"get_accounts":        accountEntry("w0000001"),
		"get_accountsettings": settingsXML(),
		"get_accountresources": resourceXML("max_domain", "-1", "5", "-1") +
			resourceXML("max_subdomain", "500", "15", "485"),
		"get_server_information": entry("service", "php", "interface", "cgi-fcgi", "file_extension", "php82", "version", "8.2.9") +
			entry("service", "os", "distribution", "ubuntu", "version", "22"),
		"get_space": entry("account_login", "w0123456", "used_webspace", "11947780", "max_webspace", "36454400",
			"used_htdocs_space", "4843107", "last_calculation", "1777688517"),
		"get_space_usage": entry("directory", "/example.com/", "bytes", "4096", "count", "1", "has_sub_dirs", "Y"),
		"get_traffic": kasapitest.MapItem("0", kasapitest.MapItem("account_login", "w0123456")+
			kasapitest.MapItem("year", "2026")+kasapitest.MapItem("month", "05")+
			kasapitest.MapItem("http_traffic", "4104052")+kasapitest.MapItem("http_hits", "216")) +
			kasapitest.MapItem("01", kasapitest.MapItem("account_login", "w0123456")+
				kasapitest.MapItem("year", "2026")+kasapitest.MapItem("month", "05")+kasapitest.MapItem("day", "01")),
	})
	for res, tc := range map[string]struct {
		names []string
		wide  []string
	}{
		"acc":              {[]string{"account/w0000001"}, []string{"WEBSPACE-MB", "8192", "kurz", "shop"}},
		"accountsettings":  {[]string{"accountsettings/w0123456"}, []string{"d012345", "LOG-AGE", "190"}},
		"accountresources": {[]string{"accountresource/domain", "accountresource/subdomain"}, []string{"unlimited", "485", "RESERVED"}},
		"serverinfo":       {[]string{"serverinfo/php-8.2.9", "serverinfo/os-22"}, []string{"php82", "ubuntu"}},
		"space":            {[]string{"space/w0123456"}, []string{"USED-KB", "11947780", "36454400", "4843107", "2026-05-02T"}},
		"spaceusage":       {[]string{"spaceusage//example.com/"}, []string{"4096", "SUBDIRS"}},
		"traffic":          {[]string{"traffic/w0123456/2026-05", "traffic/w0123456/2026-05-01"}, []string{"2026-05-01", "4104052", "216"}},
	} {
		out := capture(t, "get", res, "-o", "name")
		if strings.TrimSpace(out) != strings.Join(tc.names, "\n") {
			t.Errorf("%s name output: %q", res, out)
		}
		out = capture(t, "get", res, "-o", "wide")
		for _, want := range tc.wide {
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

	var items []map[string]any
	if err := json.Unmarshal([]byte(capture(t, "get", "acc", "-o", "json")), &items); err != nil {
		t.Fatalf("accounts json: %v", err)
	}
	if limits, _ := items[0]["limits"].(map[string]any); limits["mailinglist"] != float64(3) || limits["webspace"] != float64(8192) {
		t.Fatalf("limits: %v", items[0]["limits"])
	}
	if err := json.Unmarshal([]byte(capture(t, "get", "accountsettings", "-o", "json")), &items); err != nil {
		t.Fatalf("settings json: %v", err)
	}
	if keys, _ := items[0]["sshHostKeys"].([]any); len(keys) != 1 {
		t.Fatalf("host keys: %v", items[0])
	}
}

func TestCLI_GetStatisticsFlags(t *testing.T) {
	rec := setupFake(t, map[string]string{"get_space": "", "get_space_usage": "", "get_traffic": ""})
	capture(t, "get", "space", "--subaccounts")
	wantParams(t, rec.last(t, "get_space"), map[string]string{"show_subaccounts": "Y"})
	capture(t, "get", "spaceusage", "/example.com/")
	wantParams(t, rec.last(t, "get_space_usage"), map[string]string{"directory": "/example.com/"})
	capture(t, "get", "traffic", "--year", "2025", "--month", "12")
	wantParams(t, rec.last(t, "get_traffic"), map[string]string{"year": "2025", "month": "12"})
	wantErr(t, "invalid traffic period", "get", "traffic", "--month", "13")

	before := rec.total()
	wantErr(t, "cannot delete", "delete", "space", "x")
	if rec.total() != before {
		t.Fatal("a refused delete must not reach the API")
	}
}

func TestCLI_GetAccountFaults(t *testing.T) {
	setupFake(t, map[string]string{})
	for _, res := range []string{"acc", "accountsettings", "accountresources", "serverinfo", "space", "spaceusage", "traffic"} {
		wantErr(t, "unknown_action", "get", res)
	}
}

func TestCLI_CreateAccount(t *testing.T) {
	rec := setupFake(t, map[string]string{"add_account": "w0000005"})
	setStdin(t, "kas-pw\nftp-pw\n")
	out := capture(t, "create", "account", "--subdomain", "forum.example.de", "--path", "/forum/",
		"--limit", "subdomain=1,webspace=8192", "--comment", "forum", "--logging", "kurz", "--log-age", "7",
		"--dns-settings", "--software-install=false", "--password-stdin")
	if strings.TrimSpace(out) != "account/w0000005 created" {
		t.Fatalf("output: %q", out)
	}
	got := rec.last(t, "add_account")
	wantParams(t, got, map[string]string{
		"account_kas_password": "kas-pw", "account_ftp_password": "ftp-pw",
		"hostname_art": "subdomain", "hostname_part1": "forum", "hostname_part2": "example.de",
		"hostname_path": "/forum/", "max_subdomain": "1", "max_webspace": "8192",
		"account_comment": "forum", "logging": "kurz", "logage": "7",
		"dns_settings": "Y", "inst_software": "N",
	})
	wantAbsent(t, got, "inst_htaccess", "kas_access_forbidden", "show_password", "statistic", "account_contact_mail")

	setStdin(t, "kas-pw\nftp-pw\n")
	capture(t, "create", "account", "--domain", "example.co.uk", "--password-stdin")
	wantParams(t, rec.last(t, "add_account"), map[string]string{
		"hostname_art": "domain", "hostname_part1": "example", "hostname_part2": "co.uk",
	})
	setStdin(t, "kas-pw\nftp-pw\n")
	capture(t, "create", "account", "--password-stdin")
	got = rec.last(t, "add_account")
	wantParams(t, got, map[string]string{"hostname_art": ""})
	wantAbsent(t, got, "hostname_part1")

	before := rec.count("add_account")
	wantErr(t, "exclude each other", "create", "account", "--domain", "a.de", "--subdomain", "b.a.de")
	wantErr(t, "--path needs", "create", "account", "--path", "/x/")
	wantErr(t, "invalid host", "create", "account", "--domain", "example")
	wantErr(t, `unknown resource "pods"`, "create", "account", "--limit", "pods=3")
	setStdin(t, "kas-pw\n")
	wantErr(t, "reading input", "create", "account", "--password-stdin")
	setStdin(t, "")
	wantErr(t, "reading input", "create", "account", "--password-stdin")
	setStdin(t, "kas-pw\nftp-pw\n")
	wantErr(t, "access log mode", "create", "account", "--logging", "full", "--password-stdin")
	if rec.count("add_account") != before {
		t.Fatal("invalid input must not reach the API")
	}

	t.Setenv("KASCONFIG", filepath.Join(t.TempDir(), "config"))
	setStdin(t, "kas-pw\nftp-pw\n")
	wantErr(t, "no credentials", "create", "account", "--password-stdin")
}

func TestCLI_UpdateAccount(t *testing.T) {
	rec := setupFake(t, map[string]string{
		"update_account": "TRUE", "update_superusersettings": "TRUE", "delete_account": "TRUE",
	})
	out := capture(t, "update", "acc", "w0000001", "--limit", "mailinglist=5", "--directory-protection=false",
		"--kas-access-forbidden", "--show-password", "--statistics", "de", "--contact-mail", "ops@example.org")
	if strings.TrimSpace(out) != "account/w0000001 updated" {
		t.Fatalf("output: %q", out)
	}
	got := rec.last(t, "update_account")
	wantParams(t, got, map[string]string{
		"account_login": "w0000001", "max_mailinglist": "5", "inst_htaccess": "N",
		"kas_access_forbidden": "Y", "show_password": "Y", "statistic": "de",
		"account_contact_mail": "ops@example.org",
	})
	wantAbsent(t, got, "account_kas_password", "dns_settings", "logging")
	if rec.count("update_superusersettings") != 0 {
		t.Fatal("SSH settings must not be sent without SSH flags")
	}

	// SSH flags alone are one update_superusersettings request.
	updates := rec.count("update_account")
	capture(t, "update", "acc", "w0000001", "--ssh-access", "--ssh-key", "ssh-ed25519 AAAA one", "--ssh-key", "ssh-rsa BBBB two")
	if rec.count("update_account") != updates {
		t.Fatal("SSH flags must not send update_account")
	}
	wantParams(t, rec.last(t, "update_superusersettings"), map[string]string{
		"account_login": "w0000001", "ssh_access": "Y", "ssh_keys": "ssh-ed25519 AAAA one\nssh-rsa BBBB two",
	})
	capture(t, "update", "acc", "w0000001", "--ssh-key", "")
	got = rec.last(t, "update_superusersettings")
	wantParams(t, got, map[string]string{"ssh_keys": ""})
	wantAbsent(t, got, "ssh_access")

	setStdin(t, "N3w!\n")
	capture(t, "update", "acc", "w0000001", "--password-stdin")
	got = rec.last(t, "update_account")
	wantParams(t, got, map[string]string{"account_login": "w0000001", "account_kas_password": "N3w!"})
	wantAbsent(t, got, "inst_htaccess")

	wantErr(t, "nothing to update", "update", "acc", "w0000001")
	wantErr(t, "unknown resource", "update", "acc", "w0000001", "--limit", "x=1")
	setStdin(t, "")
	wantErr(t, "reading input", "update", "acc", "w0000001", "--password-stdin")

	if out := capture(t, "delete", "acc", "w0000001"); strings.TrimSpace(out) != "account/w0000001 deleted" {
		t.Fatalf("delete output: %q", out)
	}
	wantParams(t, rec.last(t, "delete_account"), map[string]string{"account_login": "w0000001"})

	setupFake(t, map[string]string{"update_account": "!account_login_not_found"})
	wantErr(t, "not found", "update", "acc", "w0000009", "--comment", "x")
}

func TestCLI_UpdateAccountSettings(t *testing.T) {
	rec := setupFake(t, map[string]string{"update_accountsettings": "TRUE"})
	out := capture(t, "update", "accountsettings", "--log-age", "30", "--logging", "ohneip", "--comment", "Admin")
	if strings.TrimSpace(out) != "accountsettings updated" {
		t.Fatalf("output: %q", out)
	}
	got := rec.last(t, "update_accountsettings")
	wantParams(t, got, map[string]string{"logage": "30", "logging": "ohneip", "account_comment": "Admin"})
	wantAbsent(t, got, "account_password")

	setStdin(t, "N3w!\n")
	capture(t, "update", "accountsettings", "--password-stdin")
	got = rec.last(t, "update_accountsettings")
	wantParams(t, got, map[string]string{"account_password": "N3w!"})
	wantAbsent(t, got, "logage")

	wantErr(t, "nothing to update", "update", "accountsettings")
	wantErr(t, "log age", "update", "accountsettings", "--log-age", "0")
	wantErr(t, "unknown command", "update", "accountsettings", "w0123456", "--comment", "x")
	setStdin(t, "")
	wantErr(t, "reading input", "update", "accountsettings", "--password-stdin")
}

func TestAccountHelpers(t *testing.T) {
	if got := countWord(-1); got != "unlimited" {
		t.Errorf("countWord(-1) = %q", got)
	}
	if got := timeWord(time.Time{}); got != "" {
		t.Errorf("timeWord(zero) = %q", got)
	}
	if got := limitName(kasapi.LimitCronjobs); got != "cronjobs" {
		t.Errorf("limitName = %q", got)
	}
	if got := trafficPeriod(kasapi.Traffic{Year: 2026, Month: 5}); got != "2026-05" {
		t.Errorf("trafficPeriod = %q", got)
	}
	host, err := accountHost("", "", "")
	if err != nil || host != (kasapi.AccountHost{}) {
		t.Errorf("accountHost without host: %+v %v", host, err)
	}
}
