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
)

// resource describes one resource type kascli knows.
type resource struct {
	name, kind, short, verbs string
}

// resources lists the supported resource types in api-resources order.
var resources = []resource{
	{"accountresources", "accountresource", "", "get"},
	{"accounts", "account", "acc", "get,create,update,delete"},
	{"accountsettings", "accountsettings", "", "get,update"},
	{"cronjobs", "cronjob", "cj", "get,create,update,delete"},
	{"databases", "database", "db", "get,create,update,delete"},
	{"ddnsusers", "ddnsuser", "ddns", "get,create,update,delete"},
	{"directoryprotections", "directoryprotection", "dp", "get,create,update,delete"},
	{"dnsrecords", "dnsrecord", "dns", "get,create,update,delete"},
	{"domains", "domain", "do", "get,update"},
	{"ftpusers", "ftpuser", "ftp", "get,create,update,delete"},
	{"mailaccounts", "mailaccount", "ma", "get,create,update,delete"},
	{"mailfilters", "mailfilter", "mfi", "get"},
	{"mailforwards", "mailforward", "mf", "get,create,update,delete"},
	{"mailinglists", "mailinglist", "ml", "get,create,update,delete"},
	{"sambausers", "sambauser", "smb", "get,create,update,delete"},
	{"serverinfo", "serverinfo", "", "get"},
	{"space", "space", "", "get"},
	{"spaceusage", "spaceusage", "", "get"},
	{"subdomains", "subdomain", "sub", "get,create,update,delete"},
	{"tls", "tls", "", "get,update"},
	{"traffic", "traffic", "", "get"},
}

// aliases returns the names a resource answers to besides its canonical one.
func (r resource) aliases() []string {
	out := []string{}
	for _, a := range []string{r.name, r.kind, r.short} {
		if a != "" && a != r.kind {
			out = append(out, a)
		}
	}
	return out
}

func resourceNames() string {
	names := make([]string, 0, len(resources))
	for _, r := range resources {
		names = append(names, r.name)
	}
	return strings.Join(names, ", ")
}

// canonicalResource maps kubectl-style names, aliases and short names to the
// canonical resource.
func canonicalResource(s string) (string, error) {
	want := strings.ToLower(s)
	for _, r := range resources {
		if want == r.name || want == r.kind || (r.short != "" && want == r.short) {
			return r.name, nil
		}
	}
	return "", fmt.Errorf(`the server doesn't have a resource type %q (available: %s)`, s, resourceNames())
}

func newGetCmd(g *globals) *cobra.Command {
	var opts getOptions
	cmd := &cobra.Command{
		Use:   "get <resource> [name]",
		Short: "list resources; a name selects the host of tls, the list of mailinglists or the directory of spaceusage (see api-resources)",
		Args:  cobra.RangeArgs(1, 2),
		RunE: func(_ *cobra.Command, args []string) error {
			return cmdGet(g, args, opts)
		},
	}
	f := cmd.Flags()
	f.StringVarP(&opts.zone, "zone", "z", "", "DNS zone (required for dnsrecords)")
	f.BoolVar(&opts.subaccounts, "subaccounts", false, "space: show the subaccounts instead of the account")
	f.IntVar(&opts.year, "year", 0, "traffic: year (default: current)")
	f.IntVar(&opts.month, "month", 0, "traffic: month 1-12 (default: current)")
	return cmd
}

// hostWideHeaders are the -o wide columns domains and subdomains share.
var hostWideHeaders = []string{"REDIRECT", "PHP", "ACTIVE", "TLS", "FORCE-HTTPS"}

func hostWideCells(redirect int, php string, active bool, t kasapi.HostTLS) []string {
	return []string{strconv.Itoa(redirect), php, boolWord(active), tlsWord(t), boolWord(t.ForceHTTPS)}
}

// tlsWord summarizes the TLS state of a host in one table cell.
func tlsWord(t kasapi.HostTLS) string {
	switch {
	case !t.Active:
		return "off"
	case t.LetsEncrypt():
		return "letsencrypt"
	case t.Type != "":
		return t.Type
	}
	return "on"
}

func tlsObject(t kasapi.HostTLS) map[string]any {
	return map[string]any{
		"active": t.Active, "type": t.Type, "letsEncrypt": t.LetsEncrypt(),
		"forceHTTPS": t.ForceHTTPS, "hstsMaxAge": t.HSTSMaxAge,
	}
}

// hostObject adds the settings domains and subdomains share to base.
func hostObject(base map[string]any, redirect int, php string, phpDeprecated, active, inProgress bool, t kasapi.HostTLS) map[string]any {
	base["redirectStatus"] = redirect
	base["phpVersion"] = php
	base["phpDeprecated"] = phpDeprecated
	base["active"] = active
	base["inProgress"] = inProgress
	base["tls"] = tlsObject(t)
	return base
}

func mailStateWord(s kasapi.MailState) string {
	switch s {
	case kasapi.MailActive:
		return "active"
	case kasapi.MailReceiveDisabled:
		return "receive-disabled"
	}
	return string(s)
}

func responderObject(r kasapi.Responder) map[string]any {
	m := map[string]any{
		"active": r.Active, "text": r.Text,
		"contentType": r.ContentType, "displayName": r.DisplayName,
	}
	if !r.Start.IsZero() {
		m["start"] = r.Start.Format(time.RFC3339)
		m["end"] = r.End.Format(time.RFC3339)
	}
	return m
}

// ftpPermissions renders the permissions as "rwl", with "-" for a missing one.
func ftpPermissions(u kasapi.FTPUser) string {
	flag := func(on bool, c string) string {
		if on {
			return c
		}
		return "-"
	}
	return flag(u.Read, "r") + flag(u.Write, "w") + flag(u.List, "l")
}

func cronSchedule(j kasapi.Cronjob) string {
	return strings.Join([]string{j.Minute, j.Hour, j.DayOfMonth, j.Month, j.DayOfWeek}, " ")
}

func newDeleteCmd(g *globals) *cobra.Command {
	return &cobra.Command{
		Use:   "delete <resource> <id>",
		Short: "delete one resource",
		Args:  cobra.ExactArgs(2),
		RunE: func(_ *cobra.Command, args []string) error {
			return cmdDelete(g, args)
		},
	}
}

// deleters deletes one object of each resource type and names it for the
// confirmation.
var deleters = map[string]func(ctx context.Context, c *kasapi.Client, id string) (string, error){
	"dnsrecords": func(ctx context.Context, c *kasapi.Client, id string) (string, error) {
		return "dnsrecord/" + id, c.DNS.Delete(ctx, id)
	},
	"mailaccounts": func(ctx context.Context, c *kasapi.Client, id string) (string, error) {
		return "mailaccount/" + id, c.Mail.DeleteAccount(ctx, id)
	},
	"mailforwards": func(ctx context.Context, c *kasapi.Client, id string) (string, error) {
		return "mailforward/" + id, c.Mail.DeleteForward(ctx, id)
	},
	"subdomains": func(ctx context.Context, c *kasapi.Client, id string) (string, error) {
		return "subdomain/" + id, c.Subdomains.Delete(ctx, id)
	},
	"ftpusers": func(ctx context.Context, c *kasapi.Client, id string) (string, error) {
		return "ftpuser/" + id, c.FTP.Delete(ctx, id)
	},
	"databases": func(ctx context.Context, c *kasapi.Client, id string) (string, error) {
		return "database/" + id, c.Databases.Delete(ctx, id)
	},
	"cronjobs": func(ctx context.Context, c *kasapi.Client, id string) (string, error) {
		return "cronjob/" + id, c.Cronjobs.Delete(ctx, id)
	},
	"ddnsusers": func(ctx context.Context, c *kasapi.Client, id string) (string, error) {
		return "ddnsuser/" + id, c.DDNS.Delete(ctx, id)
	},
	"mailinglists": func(ctx context.Context, c *kasapi.Client, id string) (string, error) {
		return "mailinglist/" + id, c.MailingLists.Delete(ctx, id)
	},
	// The id is <path>:<user>.
	"directoryprotections": func(ctx context.Context, c *kasapi.Client, id string) (string, error) {
		path, user, err := splitDirectoryID(id)
		if err != nil {
			return "", err
		}
		return "directoryprotection/" + id, c.DirectoryProtection.Delete(ctx, path, user)
	},
	"sambausers": func(ctx context.Context, c *kasapi.Client, id string) (string, error) {
		return "sambauser/" + id, c.Samba.Delete(ctx, id)
	},
	"accounts": deleteAccount,
	// The id is the mail login.
	"mailfilters": func(ctx context.Context, c *kasapi.Client, id string) (string, error) {
		return "mailfilters of mailaccount/" + id, c.Mail.DeleteFilters(ctx, id)
	},
	"domains": func(context.Context, *kasapi.Client, string) (string, error) {
		return "", errors.New("domains cannot be deleted with kascli; use 'kascli exec delete_domain ...' if you really mean it")
	},
	"tls": func(_ context.Context, _ *kasapi.Client, id string) (string, error) {
		return "", fmt.Errorf("a certificate cannot be deleted; disable it with 'kascli update tls %s --active=false'", id)
	},
}

func cmdDelete(g *globals, args []string) error {
	res, err := canonicalResource(args[0])
	if err != nil {
		return err
	}
	client, ctx, cancel, err := newClient(g)
	if err != nil {
		return err
	}
	defer cancel()

	del, ok := deleters[res]
	if !ok {
		return fmt.Errorf("cannot delete %q (see kascli api-resources)", args[0])
	}
	name, err := del(ctx, client, args[1])
	if err != nil {
		return err
	}
	fmt.Printf("%s deleted\n", name)
	return nil
}

func newExecCmd(g *globals) *cobra.Command {
	var raw bool
	cmd := &cobra.Command{
		Use:   "exec <action> [key=value ...]",
		Short: "run any raw KAS action; passwords and keys in the response are redacted (--raw shows them)",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			return cmdExec(g, args, raw)
		},
	}
	cmd.Flags().BoolVar(&raw, "raw", false, "print the passwords and private keys KAS returns instead of REDACTED")
	return cmd
}

// isSecretKey marks the response fields of get_* actions that carry a secret:
// the stored passwords and the TLS private key. show_password is a flag.
func isSecretKey(key string) bool {
	return (strings.HasSuffix(key, "_password") && key != "show_password") || key == "ssl_certificate_sni_key"
}

// redactSecrets replaces secret values in a decoded response with REDACTED.
func redactSecrets(v any) any {
	switch t := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, val := range t {
			if s, ok := val.(string); ok && s != "" && isSecretKey(k) {
				out[k] = "REDACTED"
				continue
			}
			out[k] = redactSecrets(val)
		}
		return out
	case []any:
		out := make([]any, len(t))
		for i, val := range t {
			out[i] = redactSecrets(val)
		}
		return out
	}
	return v
}

func cmdExec(g *globals, args []string, raw bool) error {
	action := args[0]
	params := map[string]any{}
	for _, arg := range args[1:] {
		k, v, ok := strings.Cut(arg, "=")
		if !ok || k == "" {
			return fmt.Errorf("invalid parameter %q, expected key=value", arg)
		}
		params[k] = v
	}

	p, err := newPrinter(g.output, g.noHeaders)
	if err != nil {
		return err
	}
	client, ctx, cancel, err := newClient(g)
	if err != nil {
		return err
	}
	defer cancel()

	ret, err := client.Exec(ctx, action, params)
	if err != nil {
		return err
	}
	if !raw {
		ret = redactSecrets(ret)
	}
	return p.printObject(ret)
}

func anySlice(in []string) []any {
	out := make([]any, 0, len(in))
	for _, s := range in {
		out = append(out, s)
	}
	return out
}

func newAPIResourcesCmd(g *globals) *cobra.Command {
	return &cobra.Command{
		Use:   "api-resources",
		Short: "list the resource types and the verbs each one supports",
		Args:  cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			return cmdAPIResources(g)
		},
	}
}

// cmdAPIResources lists the supported resources, kubectl-style.
func cmdAPIResources(g *globals) error {
	p, err := newPrinter(g.output, g.noHeaders)
	if err != nil {
		return err
	}
	rows := make([]row, 0, len(resources))
	for _, r := range resources {
		rows = append(rows, row{
			name:   r.name,
			cells:  []string{r.name, r.short, r.verbs},
			object: map[string]any{"name": r.name, "shortName": r.short, "verbs": r.verbs},
		})
	}
	return p.printList([]string{"NAME", "SHORTNAMES", "VERBS"}, nil, rows)
}
