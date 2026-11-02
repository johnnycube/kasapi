// Copyright 2026 The kasapi Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	kasapi "github.com/johnnycube/kasapi"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

// Accounts, account settings, resources, server information and statistics.

// limitName is the kascli name of a limit: its KAS name without "max_".
func limitName(l kasapi.AccountLimit) string {
	return strings.TrimPrefix(string(l), "max_")
}

func limitsObject(limits map[kasapi.AccountLimit]int) map[string]any {
	out := make(map[string]any, len(limits))
	for l, v := range limits {
		out[limitName(l)] = v
	}
	return out
}

func getAccounts(r getRequest) (listing, error) {
	accounts, err := r.client.Accounts.List(r.ctx)
	return listOf(accounts, err,
		[]string{"LOGIN", "COMMENT", "CONTACT-MAIL"},
		[]string{"WEBSPACE-MB", "LOGGING", "DNS", "SSH", "2FA"},
		func(a kasapi.Subaccount) row {
			return row{
				name:  "account/" + a.Login,
				cells: []string{a.Login, a.Comment, a.ContactMail},
				wideCells: []string{
					strconv.Itoa(a.Limits[kasapi.LimitWebspace]), string(a.Logging),
					boolWord(a.DNSSettings), boolWord(a.SSHAccess), boolWord(a.TwoFactor),
				},
				object: map[string]any{
					"login": a.Login, "comment": a.Comment, "contactMail": a.ContactMail,
					"limits":              limitsObject(a.Limits),
					"directoryProtection": a.DirectoryProtection, "softwareInstall": a.SoftwareInstall,
					"dnsSettings": a.DNSSettings, "kasAccessForbidden": a.KASAccessForbidden,
					"sshAccess": a.SSHAccess, "logging": string(a.Logging), "logAge": a.LogAge,
					"statistics": a.Statistics, "showPassword": a.ShowPassword,
					"twoFactor": a.TwoFactor, "inProgress": a.InProgress,
				},
			}
		})
}

func getAccountSettings(r getRequest) (listing, error) {
	s, err := r.client.Accounts.Settings(r.ctx)
	if err != nil {
		return listing{}, err
	}
	hostKeys := make([]any, 0, len(s.SSHHostKeys))
	for _, fp := range s.SSHHostKeys {
		hostKeys = append(hostKeys, map[string]any{"keyType": fp.KeyType, "hash": fp.Hash, "fingerprint": fp.Fingerprint})
	}
	return listing{
		headers:     []string{"LOGIN", "COMMENT", "CONTACT-MAIL", "SERVER"},
		wideHeaders: []string{"LOGGING", "LOG-AGE", "SSH", "2FA"},
		rows: []row{{
			name:      "accountsettings/" + s.Login,
			cells:     []string{s.Login, s.Comment, s.ContactMail, s.Server},
			wideCells: []string{string(s.Logging), strconv.Itoa(s.LogAge), boolWord(s.SSHAccess), boolWord(s.TwoFactor)},
			object: map[string]any{
				"login": s.Login, "comment": s.Comment, "contactMail": s.ContactMail,
				"superuser": s.Superuser, "server": s.Server,
				"directoryProtection": s.DirectoryProtection, "softwareInstall": s.SoftwareInstall,
				"dnsSettings": s.DNSSettings, "sshAccess": s.SSHAccess,
				"sshKeys": anySlice(s.SSHKeys), "sshHostKeys": hostKeys,
				"logging": string(s.Logging), "logAge": s.LogAge, "statistics": s.Statistics,
				"showPassword": s.ShowPassword, "twoFactor": s.TwoFactor, "inProgress": s.InProgress,
			},
		}},
	}, nil
}

// countWord renders a limit; -1 means unlimited.
func countWord(n int) string {
	if n < 0 {
		return "unlimited"
	}
	return strconv.Itoa(n)
}

func getAccountResources(r getRequest) (listing, error) {
	res, err := r.client.Accounts.Resources(r.ctx)
	if err != nil {
		return listing{}, err
	}
	var rows []row
	for _, l := range kasapi.AccountLimits {
		u, ok := res[l]
		if !ok {
			continue
		}
		rows = append(rows, row{
			name:      "accountresource/" + limitName(l),
			cells:     []string{limitName(l), countWord(u.Max), strconv.Itoa(u.Used), countWord(u.Free)},
			wideCells: []string{strconv.Itoa(u.Created), strconv.Itoa(u.Reserved), boolWord(u.Exceeded)},
			object: map[string]any{
				"resource": limitName(l), "max": u.Max, "used": u.Used, "free": u.Free,
				"created": u.Created, "reserved": u.Reserved, "exceeded": u.Exceeded,
			},
		})
	}
	return listing{
		headers:     []string{"RESOURCE", "MAX", "USED", "FREE"},
		wideHeaders: []string{"CREATED", "RESERVED", "EXCEEDED"},
		rows:        rows,
	}, nil
}

func getServerInfo(r getRequest) (listing, error) {
	components, err := r.client.Accounts.ServerInfo(r.ctx)
	return listOf(components, err, []string{"SERVICE", "VERSION", "DETAIL"}, nil, func(c kasapi.ServerComponent) row {
		detail := c.FileExtension + c.Distribution + c.VersionType
		return row{
			name:  "serverinfo/" + c.Service + "-" + c.Version,
			cells: []string{c.Service, c.Version, detail},
			object: map[string]any{
				"service": c.Service, "version": c.Version, "interface": c.Interface,
				"fileExtension": c.FileExtension, "versionType": c.VersionType,
				"distribution": c.Distribution,
			},
		}
	})
}

// timeWord renders a calculation time; the zero time is empty.
func timeWord(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.Format(time.RFC3339)
}

func getSpace(r getRequest) (listing, error) {
	spaces, err := r.client.Statistics.Space(r.ctx, r.subaccounts)
	return listOf(spaces, err,
		[]string{"LOGIN", "USED-KB", "MAX-KB"},
		[]string{"HTDOCS-KB", "CHROOT-KB", "DATABASES-KB", "MAIL-KB", "CALCULATED"},
		func(s kasapi.AccountSpace) row {
			i64 := func(n int64) string { return strconv.FormatInt(n, 10) }
			return row{
				name:  "space/" + s.Login,
				cells: []string{s.Login, i64(s.Webspace), i64(s.MaxWebspace)},
				wideCells: []string{
					i64(s.HTDocs), i64(s.Chroot), i64(s.Databases), i64(s.MailAccounts), timeWord(s.Calculated),
				},
				object: map[string]any{
					"login": s.Login, "webspaceKB": s.Webspace, "maxWebspaceKB": s.MaxWebspace,
					"htdocsKB": s.HTDocs, "chrootKB": s.Chroot, "databasesKB": s.Databases,
					"mailAccountsKB": s.MailAccounts, "calculated": timeWord(s.Calculated),
				},
			}
		})
}

func getSpaceUsage(r getRequest) (listing, error) {
	dir := ""
	if len(r.args) > 1 {
		dir = r.args[1]
	}
	dirs, err := r.client.Statistics.SpaceUsage(r.ctx, dir)
	return listOf(dirs, err, []string{"DIRECTORY", "BYTES", "COUNT", "SUBDIRS"}, []string{"CALCULATED"},
		func(d kasapi.DirectoryUsage) row {
			return row{
				name: "spaceusage/" + d.Directory,
				cells: []string{
					d.Directory, strconv.FormatInt(d.Bytes, 10), strconv.FormatInt(d.Count, 10), boolWord(d.HasSubdirs),
				},
				wideCells: []string{timeWord(d.Calculated)},
				object: map[string]any{
					"directory": d.Directory, "bytes": d.Bytes, "count": d.Count,
					"hasSubdirs": d.HasSubdirs, "calculated": timeWord(d.Calculated),
				},
			}
		})
}

// trafficPeriod renders YYYY-MM, or YYYY-MM-DD for a day.
func trafficPeriod(t kasapi.Traffic) string {
	if t.Day == 0 {
		return fmt.Sprintf("%04d-%02d", t.Year, t.Month)
	}
	return fmt.Sprintf("%04d-%02d-%02d", t.Year, t.Month, t.Day)
}

func getTraffic(r getRequest) (listing, error) {
	traffic, err := r.client.Statistics.Traffic(r.ctx, r.year, r.month)
	return listOf(traffic, err, []string{"LOGIN", "PERIOD", "HTTP-BYTES", "HTTP-HITS", "FTP-BYTES", "FTP-HITS"}, nil,
		func(t kasapi.Traffic) row {
			i64 := func(n int64) string { return strconv.FormatInt(n, 10) }
			return row{
				name:  "traffic/" + t.Login + "/" + trafficPeriod(t),
				cells: []string{t.Login, trafficPeriod(t), i64(t.HTTPBytes), i64(t.HTTPHits), i64(t.FTPBytes), i64(t.FTPHits)},
				object: map[string]any{
					"login": t.Login, "year": t.Year, "month": t.Month, "day": t.Day,
					"httpBytes": t.HTTPBytes, "httpHits": t.HTTPHits, "ftpBytes": t.FTPBytes, "ftpHits": t.FTPHits,
				},
			}
		})
}

// accountOptionFlags are the settings an account and its subaccounts share.
type accountOptionFlags struct {
	comment, contactMail, logging, statistics string
	logAge                                    int
	showPassword                              bool
}

func (o *accountOptionFlags) register(f *pflag.FlagSet) {
	f.StringVar(&o.comment, "comment", "", "free text describing the account")
	f.StringVar(&o.contactMail, "contact-mail", "", "contact address of the account")
	f.StringVar(&o.logging, "logging", "", "access log: voll, kurz, ohneip or keine")
	f.IntVar(&o.logAge, "log-age", 0, "days the access logs are kept, 1-999")
	f.StringVar(&o.statistics, "statistics", "", `language of the /usage statistics, or "0" for none`)
	f.BoolVar(&o.showPassword, "show-password", false, "the panel's show_password setting")
}

// options returns the flags that were given.
func (o *accountOptionFlags) options(fl *pflag.FlagSet) kasapi.AccountOptions {
	var opts kasapi.AccountOptions
	if fl.Changed("comment") {
		opts.Comment = &o.comment
	}
	if fl.Changed("contact-mail") {
		opts.ContactMail = &o.contactMail
	}
	if fl.Changed("logging") {
		opts.Logging = new(kasapi.AccessLog(o.logging))
	}
	if fl.Changed("log-age") {
		opts.LogAge = &o.logAge
	}
	if fl.Changed("statistics") {
		opts.Statistics = &o.statistics
	}
	if fl.Changed("show-password") {
		opts.ShowPassword = &o.showPassword
	}
	return opts
}

// accountFlags are the flags create and update of a subaccount share.
type accountFlags struct {
	accountOptionFlags
	limits                                   map[string]int
	htaccess, software, dns, accessForbidden bool
}

func (af *accountFlags) register(cmd *cobra.Command) {
	f := cmd.Flags()
	af.accountOptionFlags.register(f)
	names := make([]string, 0, len(kasapi.AccountLimits))
	for _, l := range kasapi.AccountLimits {
		names = append(names, limitName(l))
	}
	f.StringToIntVar(&af.limits, "limit", nil, "resource limits, e.g. subdomain=10,webspace=8192 (MB); names: "+strings.Join(names, ", "))
	f.BoolVar(&af.htaccess, "directory-protection", true, "may protect directories")
	f.BoolVar(&af.software, "software-install", true, "may use the software installer")
	f.BoolVar(&af.dns, "dns-settings", false, "may edit DNS records")
	f.BoolVar(&af.accessForbidden, "kas-access-forbidden", false, "may not log in to the KAS panel")
}

// change returns the flags that were given.
func (af *accountFlags) change(fl *pflag.FlagSet) (kasapi.AccountChange, error) {
	ch := kasapi.AccountChange{AccountOptions: af.options(fl)}
	if len(af.limits) > 0 {
		ch.Limits = map[kasapi.AccountLimit]int{}
	}
	for name, v := range af.limits {
		l := kasapi.AccountLimit("max_" + name)
		if !knownLimitName(l) {
			return ch, fmt.Errorf("--limit: unknown resource %q", name)
		}
		ch.Limits[l] = v
	}
	for flag, dst := range map[string]**bool{
		"directory-protection": &ch.DirectoryProtection, "software-install": &ch.SoftwareInstall,
		"dns-settings": &ch.DNSSettings, "kas-access-forbidden": &ch.KASAccessForbidden,
	} {
		if fl.Changed(flag) {
			v, _ := fl.GetBool(flag)
			*dst = &v
		}
	}
	return ch, nil
}

func knownLimitName(l kasapi.AccountLimit) bool {
	for _, k := range kasapi.AccountLimits {
		if k == l {
			return true
		}
	}
	return false
}

// accountHost reads --domain or --subdomain: the label up to the first dot, then the rest.
func accountHost(domain, subdomain, path string) (kasapi.AccountHost, error) {
	if domain != "" && subdomain != "" {
		return kasapi.AccountHost{}, errors.New("--domain and --subdomain exclude each other")
	}
	kind, host := "domain", domain
	if subdomain != "" {
		kind, host = "subdomain", subdomain
	}
	if host == "" {
		if path != "" {
			return kasapi.AccountHost{}, errors.New("--path needs --domain or --subdomain")
		}
		return kasapi.AccountHost{}, nil
	}
	label, parent, ok := strings.Cut(host, ".")
	if !ok || label == "" || parent == "" {
		return kasapi.AccountHost{}, fmt.Errorf("--%s: invalid host %q", kind, host)
	}
	return kasapi.AccountHost{Kind: kind, Label: label, Parent: parent, Path: path}, nil
}

func createAccountCmd(g *globals) *cobra.Command {
	var (
		af                      accountFlags
		domain, subdomain, path string
		passwordStdin           bool
	)
	cmd := resourceCmd("accounts", "create a subaccount", false)
	cmd.RunE = func(cmd *cobra.Command, _ []string) error {
		host, err := accountHost(domain, subdomain, path)
		if err != nil {
			return err
		}
		ch, err := af.change(cmd.Flags())
		if err != nil {
			return err
		}
		kasPassword, err := newSecret(passwordStdin, "KAS password of the new account")
		if err != nil {
			return err
		}
		ftpPassword, err := newSecret(passwordStdin, "FTP password of the new account")
		if err != nil {
			return err
		}
		client, ctx, cancel, err := newClient(g)
		if err != nil {
			return err
		}
		defer cancel()
		login, err := client.Accounts.Create(ctx, host, ch, kasPassword, ftpPassword)
		if err != nil {
			return err
		}
		fmt.Printf("account/%s created\n", login)
		return nil
	}
	af.register(cmd)
	f := cmd.Flags()
	f.StringVar(&domain, "domain", "", "create the account with this domain, e.g. example.de")
	f.StringVar(&subdomain, "subdomain", "", "create the account with this subdomain, e.g. forum.example.de")
	f.StringVar(&path, "path", "", "document root of the host")
	f.BoolVar(&passwordStdin, "password-stdin", false, "read the KAS password, then the FTP password, one per line from stdin")
	return cmd
}

func updateAccountCmd(g *globals) *cobra.Command {
	var (
		af            accountFlags
		sshAccess     bool
		sshKeys       []string
		passwordStdin bool
	)
	cmd := resourceCmd("accounts", "change a subaccount", true)
	cmd.RunE = func(cmd *cobra.Command, args []string) error {
		if err := noChange(cmd); err != nil {
			return err
		}
		fl := cmd.Flags()
		ch, err := af.change(fl)
		if err != nil {
			return err
		}
		var ssh kasapi.SSHChange
		if fl.Changed("ssh-access") {
			ssh.Access = &sshAccess
		}
		if fl.Changed("ssh-key") {
			ssh.Keys = new(nonEmpty(sshKeys))
		}
		password, err := optionalSecret(passwordStdin)
		if err != nil {
			return err
		}
		client, ctx, cancel, err := newClient(g)
		if err != nil {
			return err
		}
		defer cancel()
		login := args[0]
		err = runSteps([]updateStep{
			{settingsChanged(cmd, "password-stdin", "ssh-access", "ssh-key"), func() error { return client.Accounts.Update(ctx, login, ch) }},
			{ssh.Access != nil || ssh.Keys != nil, func() error { return client.Accounts.UpdateSSH(ctx, login, ssh) }},
			{passwordStdin, func() error { return client.Accounts.UpdatePassword(ctx, login, password) }},
		})
		if err != nil {
			return err
		}
		fmt.Printf("account/%s updated\n", login)
		return nil
	}
	af.register(cmd)
	f := cmd.Flags()
	f.BoolVar(&sshAccess, "ssh-access", false, "allow SSH logins (main account only)")
	f.StringSliceVar(&sshKeys, "ssh-key", nil, `public key allowed to log in (repeatable); replaces the keys, --ssh-key "" removes all`)
	f.BoolVar(&passwordStdin, "password-stdin", false, "read the new KAS password from stdin")
	return cmd
}

func updateAccountSettingsCmd(g *globals) *cobra.Command {
	var (
		o             accountOptionFlags
		passwordStdin bool
	)
	cmd := resourceCmd("accountsettings", "change the settings of the logged-in account", false)
	cmd.RunE = func(cmd *cobra.Command, _ []string) error {
		if err := noChange(cmd); err != nil {
			return err
		}
		opts := o.options(cmd.Flags())
		password, err := optionalSecret(passwordStdin)
		if err != nil {
			return err
		}
		client, ctx, cancel, err := newClient(g)
		if err != nil {
			return err
		}
		defer cancel()
		err = runSteps([]updateStep{
			{settingsChanged(cmd, "password-stdin"), func() error { return client.Accounts.UpdateSettings(ctx, opts) }},
			{passwordStdin, func() error { return client.Accounts.UpdateOwnPassword(ctx, password) }},
		})
		if err != nil {
			return err
		}
		fmt.Println("accountsettings updated")
		return nil
	}
	o.register(cmd.Flags())
	cmd.Flags().BoolVar(&passwordStdin, "password-stdin", false, "read a new KAS password for the logged-in account from stdin")
	return cmd
}

// deleteAccount is the deleter of accounts.
func deleteAccount(ctx context.Context, c *kasapi.Client, id string) (string, error) {
	return "account/" + id, c.Accounts.Delete(ctx, id)
}
