// Copyright 2026 The kasapi Authors
// SPDX-License-Identifier: Apache-2.0

package kasapi

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/johnnycube/kasapi/kasapitest"
)

// accountEntry is a get_accounts entry as KAS sends it, password included.
func accountEntry(login string, extra ...string) string {
	kv := []string{
		"account_login", login, "account_password", "plaintext-password",
		"max_account", "10", "max_domain", "4", "max_subdomain", "10", "max_webspace", "35600",
		"max_mail_account", "35", "max_mail_forward", "35", "max_mail_list", "10",
		"max_databases", "10", "max_ftpuser", "10", "max_sambauser", "0", "max_cronjobs", "10",
		"max_wbk", "0", "inst_htaccess", "Y", "inst_fpse", "N", "inst_software", "Y",
		"kas_access_forbidden", "N", "logging", "voll", "statistic", "de", "logage", "999",
		"show_password", "N", "dns_settings", "Y", "ssh_access", "Y", "account_2fa", "Y",
		"account_comment", "shop", "account_contact_mail", "ops@example.org", "in_progress", "FALSE",
	}
	return entry(append(kv, extra...)...)
}

func TestAccounts_ListAndGet(t *testing.T) {
	ctx := context.Background()
	c, rec := newFake(t, map[string]string{"get_accounts": accountEntry("w0000001") + accountEntry("w0000002")})
	accounts, err := c.Accounts.List(ctx)
	if err != nil || len(accounts) != 2 {
		t.Fatalf("List: %v %v", accounts, err)
	}
	want := Subaccount{
		Login: "w0000001", Comment: "shop", ContactMail: "ops@example.org",
		Limits: map[AccountLimit]int{
			LimitSubaccounts: 10, LimitDomains: 4, LimitSubdomains: 10, LimitWebspace: 35600,
			LimitMailAccounts: 35, LimitMailForwards: 35, LimitMailingLists: 10, LimitDatabases: 10,
			LimitFTPUsers: 10, LimitSambaUsers: 0, LimitCronjobs: 10, LimitWBKs: 0,
		},
		DirectoryProtection: true, SoftwareInstall: true, DNSSettings: true, SSHAccess: true,
		Logging: LogFull, LogAge: 999, Statistics: "de", TwoFactor: true,
	}
	if !reflect.DeepEqual(accounts[0], want) {
		t.Fatalf("got %+v\nwant %+v", accounts[0], want)
	}

	a, err := c.Accounts.Get(ctx, "w0000002")
	if err != nil || a.Login != "w0000002" {
		t.Fatalf("Get: %+v %v", a, err)
	}
	wantParams(t, rec.last(t, "get_accounts"), map[string]string{"account_login": "w0000002"})
	v := reflect.ValueOf(*a)
	for i := range v.NumField() {
		if f := v.Field(i); f.Kind() == reflect.String && strings.Contains(f.String(), "plaintext-password") {
			t.Fatalf("field %s carries the password", v.Type().Field(i).Name)
		}
	}
	if _, err := c.Accounts.Get(ctx, "w0000009"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
	if _, err := c.Accounts.Get(ctx, ""); err == nil {
		t.Fatal("Get without login must fail")
	}

	c, _ = newFake(t, map[string]string{"get_accounts": "!kas_error"})
	if _, err := c.Accounts.List(ctx); err == nil || !strings.Contains(err.Error(), "listing accounts") {
		t.Fatalf("List fault: %v", err)
	}
	if _, err := c.Accounts.Get(ctx, "w1"); err == nil || errors.Is(err, ErrNotFound) ||
		!strings.Contains(err.Error(), "reading account w1") {
		t.Fatalf("Get fault: %v", err)
	}
	c, _ = newFake(t, map[string]string{"get_accounts": "!account_login_not_found"})
	if _, err := c.Accounts.Get(ctx, "w1"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
}

func TestAccounts_Create(t *testing.T) {
	ctx := context.Background()
	c, rec := newFake(t, map[string]string{"add_account": "w0000005"})
	ch := AccountChange{
		AccountOptions: AccountOptions{
			Comment: new("demo"), ContactMail: new("ops@example.org"), Logging: new(LogShort),
			LogAge: new(7), Statistics: new("0"), ShowPassword: new(false),
		},
		Limits:              map[AccountLimit]int{LimitSubdomains: 1, LimitWebspace: 8192},
		DirectoryProtection: new(true), SoftwareInstall: new(false), DNSSettings: new(true),
		KASAccessForbidden: new(false),
	}
	login, err := c.Accounts.Create(ctx, AccountHost{Kind: "subdomain", Label: "share", Parent: "example.com", Path: "/share/"}, ch, "kas-pw", "ftp-pw")
	if err != nil || login != "w0000005" {
		t.Fatalf("Create: %q %v", login, err)
	}
	got := rec.last(t, "add_account")
	wantParams(t, got, map[string]string{
		"account_kas_password": "kas-pw", "account_ftp_password": "ftp-pw",
		"hostname_art": "subdomain", "hostname_part1": "share", "hostname_part2": "example.com",
		"hostname_path": "/share/", "max_subdomain": "1", "max_webspace": "8192",
		"account_comment": "demo", "account_contact_mail": "ops@example.org", "logging": "kurz",
		"logage": "7", "statistic": "0", "show_password": "N", "inst_htaccess": "Y",
		"inst_software": "N", "dns_settings": "Y", "kas_access_forbidden": "N",
	})
	wantAbsent(t, got, "max_domain", "account_login")

	if _, err := c.Accounts.Create(ctx, AccountHost{}, AccountChange{}, "k", "f"); err != nil {
		t.Fatalf("Create without host: %v", err)
	}
	got = rec.last(t, "add_account")
	wantParams(t, got, map[string]string{"hostname_art": ""})
	wantAbsent(t, got, "hostname_part1", "hostname_part2", "hostname_path", "logging")

	before := rec.count("add_account")
	for name, tc := range map[string]struct {
		host AccountHost
		ch   AccountChange
		kas  string
	}{
		"no password":     {AccountHost{}, AccountChange{}, ""},
		"bad kind":        {AccountHost{Kind: "wildcard", Label: "a", Parent: "b"}, AccountChange{}, "k"},
		"no label":        {AccountHost{Kind: "domain", Parent: "de"}, AccountChange{}, "k"},
		"fields, no kind": {AccountHost{Label: "a"}, AccountChange{}, "k"},
		"bad limit":       {AccountHost{}, AccountChange{Limits: map[AccountLimit]int{"max_foo": 1}}, "k"},
		"negative limit":  {AccountHost{}, AccountChange{Limits: map[AccountLimit]int{LimitDomains: -1}}, "k"},
		"bad mail":        {AccountHost{}, AccountChange{AccountOptions: AccountOptions{ContactMail: new("x")}}, "k"},
		"bad logging":     {AccountHost{}, AccountChange{AccountOptions: AccountOptions{Logging: new(AccessLog("Y"))}}, "k"},
		"bad log age":     {AccountHost{}, AccountChange{AccountOptions: AccountOptions{LogAge: new(0)}}, "k"},
	} {
		if _, err := c.Accounts.Create(ctx, tc.host, tc.ch, tc.kas, "f"); err == nil {
			t.Errorf("Create %s must fail", name)
		}
	}
	if rec.count("add_account") != before {
		t.Fatal("invalid input must not reach the API")
	}

	c, _ = newFake(t, map[string]string{"add_account": "TRUE"})
	if _, err := c.Accounts.Create(ctx, AccountHost{}, AccountChange{}, "k", "f"); err == nil || !strings.Contains(err.Error(), "returned no login") {
		t.Fatalf("a create without login must fail, got %v", err)
	}
	c, _ = newFake(t, map[string]string{"add_account": "!max_account_reached"})
	if _, err := c.Accounts.Create(ctx, AccountHost{}, AccountChange{}, "k", "f"); err == nil || !strings.Contains(err.Error(), "creating account") {
		t.Fatalf("fault must be returned with context, got %v", err)
	}
}

func TestAccounts_UpdateAndDelete(t *testing.T) {
	ctx := context.Background()
	c, rec := newFake(t, map[string]string{"update_account": "TRUE", "delete_account": "TRUE"})
	if err := c.Accounts.Update(ctx, "w1", AccountChange{Limits: map[AccountLimit]int{LimitMailingLists: 3}}); err != nil {
		t.Fatalf("Update: %v", err)
	}
	got := rec.last(t, "update_account")
	wantParams(t, got, map[string]string{"account_login": "w1", "max_mailinglist": "3"})
	wantAbsent(t, got, "account_kas_password", "logging", "inst_htaccess")
	if err := c.Accounts.UpdatePassword(ctx, "w1", "N3w!"); err != nil {
		t.Fatalf("UpdatePassword: %v", err)
	}
	got = rec.last(t, "update_account")
	wantParams(t, got, map[string]string{"account_login": "w1", "account_kas_password": "N3w!"})
	if err := c.Accounts.Delete(ctx, "w1"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	wantParams(t, rec.last(t, "delete_account"), map[string]string{"account_login": "w1"})

	for name, err := range map[string]error{
		"Update without login":          c.Accounts.Update(ctx, "", AccountChange{DNSSettings: new(true)}),
		"Update without change":         c.Accounts.Update(ctx, "w1", AccountChange{}),
		"Update with bad value":         c.Accounts.Update(ctx, "w1", AccountChange{AccountOptions: AccountOptions{LogAge: new(1000)}}),
		"UpdatePassword without login":  c.Accounts.UpdatePassword(ctx, "", "p"),
		"UpdatePassword without secret": c.Accounts.UpdatePassword(ctx, "w1", ""),
		"Delete without login":          c.Accounts.Delete(ctx, ""),
	} {
		if err == nil {
			t.Errorf("%s must fail", name)
		}
	}

	c, _ = newFake(t, map[string]string{"update_account": "!account_login_not_found", "delete_account": "!account_login_not_found"})
	if err := c.Accounts.Update(ctx, "w1", AccountChange{DNSSettings: new(true)}); !errors.Is(err, ErrNotFound) {
		t.Errorf("Update: expected ErrNotFound, got %v", err)
	}
	if err := c.Accounts.Delete(ctx, "w1"); !errors.Is(err, ErrNotFound) {
		t.Errorf("Delete: expected ErrNotFound, got %v", err)
	}
	c, _ = newFake(t, map[string]string{"update_account": "!in_progress", "delete_account": "!account_has_active_subaccounts"})
	if err := c.Accounts.UpdatePassword(ctx, "w1", "p"); err == nil || !strings.Contains(err.Error(), "updating password of account w1") {
		t.Errorf("UpdatePassword fault: %v", err)
	}
	if err := c.Accounts.Delete(ctx, "w1"); err == nil || !strings.Contains(err.Error(), "deleting account w1") {
		t.Errorf("Delete fault: %v", err)
	}
}

func TestAccounts_UpdateSSH(t *testing.T) {
	ctx := context.Background()
	c, rec := newFake(t, map[string]string{"update_superusersettings": "TRUE"})
	keys := []string{"ssh-ed25519 AAAA one", "ssh-rsa BBBB two"}
	if err := c.Accounts.UpdateSSH(ctx, "w1", SSHChange{Access: new(true), Keys: &keys}); err != nil {
		t.Fatalf("UpdateSSH: %v", err)
	}
	wantParams(t, rec.last(t, "update_superusersettings"), map[string]string{
		"account_login": "w1", "ssh_access": "Y", "ssh_keys": "ssh-ed25519 AAAA one\nssh-rsa BBBB two",
	})
	if err := c.Accounts.UpdateSSH(ctx, "w1", SSHChange{Access: new(false)}); err != nil {
		t.Fatalf("UpdateSSH: %v", err)
	}
	wantAbsent(t, rec.last(t, "update_superusersettings"), "ssh_keys")

	for name, tc := range map[string]struct {
		login string
		ch    SSHChange
	}{
		"no login":      {"", SSHChange{Access: new(true)}},
		"no change":     {"w1", SSHChange{}},
		"empty key":     {"w1", SSHChange{Keys: new([]string{""})}},
		"multiline key": {"w1", SSHChange{Keys: new([]string{"a\nb"})}},
	} {
		if err := c.Accounts.UpdateSSH(ctx, tc.login, tc.ch); err == nil {
			t.Errorf("UpdateSSH %s must fail", name)
		}
	}
	c, _ = newFake(t, map[string]string{"update_superusersettings": "!kas_login_is_no_main_login"})
	if err := c.Accounts.UpdateSSH(ctx, "w1", SSHChange{Access: new(true)}); err == nil ||
		!strings.Contains(err.Error(), "updating SSH access of account w1") {
		t.Errorf("fault must be returned with context, got %v", err)
	}
}

func settingsXML() string {
	fp := kasapitest.MapItem("MD5:", "1a:2b") + kasapitest.MapItem("SHA256:", "AbCd")
	return kasapitest.MapItem("settings",
		kasapitest.MapItem("account_login", "w0000000")+
			kasapitest.MapItem("account_comment", "Administrator")+
			kasapitest.MapItem("account_contact_mail", "admin@example.org")+
			kasapitest.MapItem("account_password", "plaintext-password")+
			kasapitest.MapItem("is_superuser", "Y")+
			kasapitest.MapItem("show_password", "Y")+
			kasapitest.MapItem("logging", "kurz")+
			kasapitest.MapItem("logage", "7")+
			kasapitest.MapItem("statistic", "0")+
			kasapitest.MapItem("dns_settings", "Y")+
			kasapitest.MapItem("inst_htaccess", "Y")+
			kasapitest.MapItem("inst_software", "N")+
			kasapitest.MapItem("ssh_access", "Y")+
			kasapitest.MapItem("ssh_keys", "ssh-ed25519 AAAA one\nssh-rsa BBBB two")+
			kasapitest.MapItem("ssh_fingerprints", kasapitest.MapItem("RSA", fp)+kasapitest.MapItem("ED25519", fp))+
			kasapitest.MapItem("server", "d012345")+
			kasapitest.MapItem("account_2fa", "N")+
			kasapitest.MapItem("in_progress", "FALSE"))
}

func TestAccounts_Settings(t *testing.T) {
	ctx := context.Background()
	c, _ := newFake(t, map[string]string{"get_accountsettings": settingsXML()})
	s, err := c.Accounts.Settings(ctx)
	if err != nil {
		t.Fatalf("Settings: %v", err)
	}
	want := &AccountSettings{
		Login: "w0000000", Comment: "Administrator", ContactMail: "admin@example.org",
		Superuser: true, Server: "d012345", DirectoryProtection: true, DNSSettings: true,
		SSHAccess: true, SSHKeys: []string{"ssh-ed25519 AAAA one", "ssh-rsa BBBB two"},
		SSHHostKeys: []SSHFingerprint{
			{"ED25519", "MD5", "1a:2b"}, {"ED25519", "SHA256", "AbCd"},
			{"RSA", "MD5", "1a:2b"}, {"RSA", "SHA256", "AbCd"},
		},
		Logging: LogShort, LogAge: 7, Statistics: "0", ShowPassword: true,
	}
	if !reflect.DeepEqual(s, want) {
		t.Fatalf("got %+v\nwant %+v", s, want)
	}

	// A response without the "settings" wrapper is read as it is.
	c, _ = newFake(t, map[string]string{"get_accountsettings": kasapitest.MapItem("account_login", "w0000000")})
	if s, err := c.Accounts.Settings(ctx); err != nil || s.Login != "w0000000" {
		t.Fatalf("unwrapped: %+v %v", s, err)
	}
	c, _ = newFake(t, map[string]string{"get_accountsettings": "TRUE"})
	if _, err := c.Accounts.Settings(ctx); err == nil || !strings.Contains(err.Error(), "unexpected response") {
		t.Fatalf("scalar response must fail, got %v", err)
	}
	c, _ = newFake(t, map[string]string{"get_accountsettings": "!kas_error"})
	if _, err := c.Accounts.Settings(ctx); err == nil || !strings.Contains(err.Error(), "reading account settings") {
		t.Fatalf("fault: %v", err)
	}
}

func TestAccounts_UpdateSettings(t *testing.T) {
	ctx := context.Background()
	c, rec := newFake(t, map[string]string{"update_accountsettings": "TRUE"})
	if err := c.Accounts.UpdateSettings(ctx, AccountOptions{LogAge: new(30), Logging: new(LogNoIP), ContactMail: new("")}); err != nil {
		t.Fatalf("UpdateSettings: %v", err)
	}
	got := rec.last(t, "update_accountsettings")
	wantParams(t, got, map[string]string{"logage": "30", "logging": "ohneip", "account_contact_mail": ""})
	wantAbsent(t, got, "account_password", "account_comment", "show_password", "statistic")
	if err := c.Accounts.UpdateOwnPassword(ctx, "N3w!"); err != nil {
		t.Fatalf("UpdateOwnPassword: %v", err)
	}
	got = rec.last(t, "update_accountsettings")
	wantParams(t, got, map[string]string{"account_password": "N3w!"})
	wantAbsent(t, got, "logage")
	if c.cfg.Password != "N3w!" {
		t.Fatalf("the client must log in with the new password from now on, has %q", c.cfg.Password)
	}

	before := rec.count("update_accountsettings")
	if err := c.Accounts.UpdateSettings(ctx, AccountOptions{}); err == nil {
		t.Error("UpdateSettings without change must fail")
	}
	if err := c.Accounts.UpdateSettings(ctx, AccountOptions{Logging: new(AccessLog("full"))}); err == nil {
		t.Error("UpdateSettings with bad logging must fail")
	}
	if err := c.Accounts.UpdateOwnPassword(ctx, ""); err == nil {
		t.Error("UpdateOwnPassword without password must fail")
	}
	if rec.count("update_accountsettings") != before {
		t.Fatal("invalid input must not reach the API")
	}

	c, _ = newFake(t, map[string]string{"update_accountsettings": "!nothing_to_do"})
	if err := c.Accounts.UpdateSettings(ctx, AccountOptions{Comment: new("x")}); err != nil {
		t.Errorf("nothing_to_do must be success, got %v", err)
	}
	c, _ = newFake(t, map[string]string{"update_accountsettings": "!in_progress"})
	if err := c.Accounts.UpdateSettings(ctx, AccountOptions{Comment: new("x")}); err == nil || !strings.Contains(err.Error(), "updating account settings") {
		t.Errorf("UpdateSettings fault: %v", err)
	}
	if err := c.Accounts.UpdateOwnPassword(ctx, "p"); err == nil || !strings.Contains(err.Error(), "updating account password") {
		t.Errorf("UpdateOwnPassword fault: %v", err)
	}
}

func TestAccounts_Resources(t *testing.T) {
	ctx := context.Background()
	res := func(max, used, free string) string {
		return kasapitest.MapItem("max", max) + kasapitest.MapItem("exceeded", "false") +
			kasapitest.MapItem("reserved", "13") + kasapitest.MapItem("created", "2") +
			kasapitest.MapItem("used", used) + kasapitest.MapItem("free", free)
	}
	c, _ := newFake(t, map[string]string{"get_accountresources": kasapitest.MapItem("max_subdomain", res("500", "15", "485")) +
		kasapitest.MapItem("max_domain", res("-1", "5", "-1")) +
		kasapitest.MapItem("max_mail_list", res("10", "1", "9")) +
		kasapitest.MapItem("odd", "scalar")})
	got, err := c.Accounts.Resources(ctx)
	if err != nil {
		t.Fatalf("Resources: %v", err)
	}
	want := map[AccountLimit]AccountResource{
		LimitSubdomains:   {Max: 500, Used: 15, Created: 2, Reserved: 13, Free: 485},
		LimitDomains:      {Max: -1, Used: 5, Created: 2, Reserved: 13, Free: -1},
		LimitMailingLists: {Max: 10, Used: 1, Created: 2, Reserved: 13, Free: 9},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v\nwant %+v", got, want)
	}
	c, _ = newFake(t, map[string]string{"get_accountresources": "!kas_error"})
	if _, err := c.Accounts.Resources(ctx); err == nil || !strings.Contains(err.Error(), "reading account resources") {
		t.Fatalf("fault: %v", err)
	}
}

func TestAccounts_ServerInfo(t *testing.T) {
	ctx := context.Background()
	c, _ := newFake(t, map[string]string{"get_server_information": entry("service", "mysql", "version", "10.6.12", "version_type", "server") +
		entry("service", "php", "interface", "cgi-fcgi", "file_extension", "php82", "version", "8.2.9") +
		entry("service", "os", "distribution", "ubuntu", "version", "22")})
	got, err := c.Accounts.ServerInfo(ctx)
	if err != nil {
		t.Fatalf("ServerInfo: %v", err)
	}
	want := []ServerComponent{
		{Service: "mysql", Version: "10.6.12", VersionType: "server"},
		{Service: "php", Version: "8.2.9", Interface: "cgi-fcgi", FileExtension: "php82"},
		{Service: "os", Version: "22", Distribution: "ubuntu"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v\nwant %+v", got, want)
	}
	c, _ = newFake(t, map[string]string{"get_server_information": "!kas_error"})
	if _, err := c.Accounts.ServerInfo(ctx); err == nil || !strings.Contains(err.Error(), "reading server information") {
		t.Fatalf("fault: %v", err)
	}
}
