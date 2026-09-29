// Copyright 2026 The kasapi Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
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
	{"cronjobs", "cronjob", "cj", "get,create,update,delete"},
	{"databases", "database", "db", "get,create,update,delete"},
	{"ddnsusers", "ddnsuser", "ddns", "get,create,update,delete"},
	{"dnsrecords", "dnsrecord", "dns", "get,create,update,delete"},
	{"domains", "domain", "do", "get,update"},
	{"ftpusers", "ftpuser", "ftp", "get,create,update,delete"},
	{"mailaccounts", "mailaccount", "ma", "get,create,update,delete"},
	{"mailfilters", "mailfilter", "mfi", "get"},
	{"mailforwards", "mailforward", "mf", "get,create,update,delete"},
	{"subdomains", "subdomain", "sub", "get,create,update,delete"},
	{"tls", "tls", "", "get,update"},
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
	var zone string
	cmd := &cobra.Command{
		Use:   "get <resource> [name]",
		Short: "list resources, or show the TLS state of one host (see api-resources)",
		Args:  cobra.RangeArgs(1, 2),
		RunE: func(_ *cobra.Command, args []string) error {
			return cmdGet(g, args, zone)
		},
	}
	cmd.Flags().StringVarP(&zone, "zone", "z", "", "DNS zone (required for dnsrecords)")
	return cmd
}

func cmdGet(g *globals, args []string, zone string) error {
	res, err := canonicalResource(args[0])
	if err != nil {
		return err
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

	switch res {
	case "domains":
		domains, err := client.Domains.List(ctx)
		if err != nil {
			return err
		}
		rows := make([]row, 0, len(domains))
		for _, d := range domains {
			rows = append(rows, row{
				name:      "domain/" + d.Name,
				cells:     []string{d.Name, d.Path},
				wideCells: hostWideCells(d.RedirectStatus, d.PHPVersion, d.Active, d.TLS),
				object: hostObject(map[string]any{"name": d.Name, "path": d.Path, "dkimSelector": d.DKIMSelector},
					d.RedirectStatus, d.PHPVersion, d.PHPDeprecated, d.Active, d.InProgress, d.TLS),
			})
		}
		return p.printList([]string{"NAME", "PATH"}, hostWideHeaders, rows)

	case "dnsrecords":
		if zone == "" {
			return fmt.Errorf("--zone is required for dnsrecords (e.g. kascli get dns --zone example.com)")
		}
		records, err := client.DNS.List(ctx, zone)
		if err != nil {
			return err
		}
		rows := make([]row, 0, len(records))
		for _, r := range records {
			rows = append(rows, row{
				name: "dnsrecord/" + r.ID,
				cells: []string{
					r.ID, r.Name, r.Type, r.Data, strconv.Itoa(r.Aux),
				},
				wideCells: []string{r.Zone, boolWord(r.Changeable), boolWord(r.Deletable)},
				object: map[string]any{
					"id": r.ID, "zone": r.Zone, "name": r.Name, "type": r.Type,
					"data": r.Data, "aux": r.Aux, "changeable": r.Changeable,
					"deletable": r.Deletable,
				},
			})
		}
		return p.printList(
			[]string{"ID", "NAME", "TYPE", "DATA", "AUX"},
			[]string{"ZONE", "CHANGEABLE", "DELETABLE"}, rows)

	case "mailaccounts":
		accounts, err := client.Mail.ListAccounts(ctx)
		if err != nil {
			return err
		}
		rows := make([]row, 0, len(accounts))
		for _, a := range accounts {
			rows = append(rows, row{
				name:  "mailaccount/" + a.Login,
				cells: []string{a.Login, a.Address(), boolWord(a.ResponderActive)},
				wideCells: []string{
					strings.Join(a.CopyAddresses, ","), strings.Join(a.SenderAliases, ","),
					mailStateWord(a.State), strings.Join(a.AllowNets, ","), strings.Join(a.SpamFilters, ","),
				},
				object: map[string]any{
					"login": a.Login, "address": a.Address(),
					"responderActive":  a.ResponderActive,
					"responder":        responderObject(a.Responder),
					"copyAddresses":    anySlice(a.CopyAddresses),
					"senderAliases":    anySlice(a.SenderAliases),
					"state":            mailStateWord(a.State),
					"allowNets":        anySlice(a.AllowNets),
					"spamFilters":      anySlice(a.SpamFilters),
					"webmailAutologin": a.WebmailAutologin,
					"inProgress":       a.InProgress,
				},
			})
		}
		return p.printList(
			[]string{"LOGIN", "ADDRESS", "RESPONDER"},
			[]string{"COPY-ADDRESSES", "SENDER-ALIASES", "STATE", "ALLOW-NETS", "FILTERS"}, rows)

	case "mailforwards":
		forwards, err := client.Mail.ListForwards(ctx)
		if err != nil {
			return err
		}
		rows := make([]row, 0, len(forwards))
		for _, f := range forwards {
			rows = append(rows, row{
				name:      "mailforward/" + f.Source(),
				cells:     []string{f.Source(), strings.Join(f.Targets, ",")},
				wideCells: []string{strings.Join(f.SpamFilters, ",")},
				object: map[string]any{
					"source": f.Source(), "targets": anySlice(f.Targets),
					"spamFilters": anySlice(f.SpamFilters), "inProgress": f.InProgress,
				},
			})
		}
		return p.printList([]string{"SOURCE", "TARGETS"}, []string{"FILTERS"}, rows)

	case "subdomains":
		subs, err := client.Subdomains.List(ctx)
		if err != nil {
			return err
		}
		rows := make([]row, 0, len(subs))
		for _, s := range subs {
			rows = append(rows, row{
				name:      "subdomain/" + s.FQDN,
				cells:     []string{s.FQDN, s.Path},
				wideCells: hostWideCells(s.RedirectStatus, s.PHPVersion, s.Active, s.TLS),
				object: hostObject(map[string]any{"fqdn": s.FQDN, "path": s.Path},
					s.RedirectStatus, s.PHPVersion, s.PHPDeprecated, s.Active, s.InProgress, s.TLS),
			})
		}
		return p.printList([]string{"FQDN", "PATH"}, hostWideHeaders, rows)

	case "tls":
		if len(args) < 2 {
			return fmt.Errorf("a host name is required (e.g. kascli get tls example.com)")
		}
		state, err := client.TLS.Get(ctx, args[1])
		if err != nil {
			return err
		}
		rows := []row{{
			name: "tls/" + args[1],
			cells: []string{
				args[1], boolWord(state.Active), state.Type,
				boolWord(state.ForceHTTPS), strconv.Itoa(state.HSTSMaxAge),
			},
			object: func() map[string]any {
				m := tlsObject(*state)
				m["host"] = args[1]
				return m
			}(),
		}}
		return p.printList([]string{"HOST", "ACTIVE", "TYPE", "FORCE-HTTPS", "HSTS-MAX-AGE"}, nil, rows)

	case "mailfilters":
		filters, err := client.Mail.AvailableFilters(ctx)
		if err != nil {
			return err
		}
		rows := make([]row, 0, len(filters))
		for _, f := range filters {
			rows = append(rows, row{
				name:  "mailfilter/" + f.Name,
				cells: []string{f.Name, f.Type, f.Title, boolWord(f.Recommended)},
				object: map[string]any{
					"name": f.Name, "type": f.Type, "title": f.Title, "recommended": f.Recommended,
				},
			})
		}
		return p.printList([]string{"NAME", "TYPE", "TITLE", "RECOMMENDED"}, nil, rows)

	case "ftpusers":
		users, err := client.FTP.List(ctx)
		if err != nil {
			return err
		}
		rows := make([]row, 0, len(users))
		for _, u := range users {
			rows = append(rows, row{
				name:      "ftpuser/" + u.Login,
				cells:     []string{u.Login, u.Path, ftpPermissions(u), u.Comment},
				wideCells: []string{boolWord(u.VirusScan), boolWord(u.MainUser)},
				object: map[string]any{
					"login": u.Login, "path": u.Path, "comment": u.Comment,
					"read": u.Read, "write": u.Write, "list": u.List,
					"virusScan": u.VirusScan, "mainUser": u.MainUser, "inProgress": u.InProgress,
				},
			})
		}
		return p.printList(
			[]string{"LOGIN", "PATH", "PERMISSIONS", "COMMENT"},
			[]string{"VIRUS-SCAN", "MAIN-USER"}, rows)

	case "databases":
		dbs, err := client.Databases.List(ctx)
		if err != nil {
			return err
		}
		rows := make([]row, 0, len(dbs))
		for _, d := range dbs {
			rows = append(rows, row{
				name:      "database/" + d.Login,
				cells:     []string{d.Login, d.Comment, strings.Join(d.AllowedHosts, ",")},
				wideCells: []string{d.Name, strconv.Itoa(d.UsedSpace)},
				object: map[string]any{
					"login": d.Login, "name": d.Name, "comment": d.Comment,
					"allowedHosts": anySlice(d.AllowedHosts), "usedSpace": d.UsedSpace,
					"inProgress": d.InProgress,
				},
			})
		}
		return p.printList(
			[]string{"LOGIN", "COMMENT", "ALLOWED-HOSTS"},
			[]string{"NAME", "USED-SPACE"}, rows)

	case "cronjobs":
		jobs, err := client.Cronjobs.List(ctx)
		if err != nil {
			return err
		}
		rows := make([]row, 0, len(jobs))
		for _, j := range jobs {
			rows = append(rows, row{
				name:      "cronjob/" + j.ID,
				cells:     []string{j.ID, cronSchedule(j), j.Protocol + "://" + j.URL, boolWord(j.Active), j.Comment},
				wideCells: []string{j.MailAddress, j.HTTPUser},
				object: map[string]any{
					"id": j.ID, "comment": j.Comment, "protocol": j.Protocol, "url": j.URL,
					"minute": j.Minute, "hour": j.Hour, "dayOfMonth": j.DayOfMonth,
					"month": j.Month, "dayOfWeek": j.DayOfWeek, "httpUser": j.HTTPUser,
					"mailAddress": j.MailAddress, "mailCondition": j.MailCondition,
					"mailSubject": j.MailSubject, "active": j.Active,
				},
			})
		}
		return p.printList(
			[]string{"ID", "SCHEDULE", "URL", "ACTIVE", "COMMENT"},
			[]string{"MAIL", "HTTP-USER"}, rows)

	case "ddnsusers":
		users, err := client.DDNS.List(ctx)
		if err != nil {
			return err
		}
		rows := make([]row, 0, len(users))
		for _, u := range users {
			rows = append(rows, row{
				name:      "ddnsuser/" + u.Login,
				cells:     []string{u.Login, u.Host(), u.TargetIP, u.Comment},
				wideCells: []string{u.TargetIPv6, boolWord(u.DualStack)},
				object: map[string]any{
					"login": u.Login, "host": u.Host(), "zone": u.Zone, "label": u.Label,
					"targetIP": u.TargetIP, "targetIPv6": u.TargetIPv6,
					"dualStack": u.DualStack, "comment": u.Comment,
				},
			})
		}
		return p.printList(
			[]string{"LOGIN", "HOST", "TARGET-IP", "COMMENT"},
			[]string{"TARGET-IPV6", "DUAL-STACK"}, rows)
	}
	return nil
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

func cmdDelete(g *globals, args []string) error {
	res, err := canonicalResource(args[0])
	if err != nil {
		return err
	}
	id := args[1]

	client, ctx, cancel, err := newClient(g)
	if err != nil {
		return err
	}
	defer cancel()

	switch res {
	case "dnsrecords":
		if err := client.DNS.Delete(ctx, id); err != nil {
			return err
		}
		fmt.Printf("dnsrecord/%s deleted\n", id)
	case "mailaccounts":
		if err := client.Mail.DeleteAccount(ctx, id); err != nil {
			return err
		}
		fmt.Printf("mailaccount/%s deleted\n", id)
	case "mailforwards":
		if err := client.Mail.DeleteForward(ctx, id); err != nil {
			return err
		}
		fmt.Printf("mailforward/%s deleted\n", id)
	case "subdomains":
		if err := client.Subdomains.Delete(ctx, id); err != nil {
			return err
		}
		fmt.Printf("subdomain/%s deleted\n", id)
	case "ftpusers":
		if err := client.FTP.Delete(ctx, id); err != nil {
			return err
		}
		fmt.Printf("ftpuser/%s deleted\n", id)
	case "databases":
		if err := client.Databases.Delete(ctx, id); err != nil {
			return err
		}
		fmt.Printf("database/%s deleted\n", id)
	case "cronjobs":
		if err := client.Cronjobs.Delete(ctx, id); err != nil {
			return err
		}
		fmt.Printf("cronjob/%s deleted\n", id)
	case "ddnsusers":
		if err := client.DDNS.Delete(ctx, id); err != nil {
			return err
		}
		fmt.Printf("ddnsuser/%s deleted\n", id)
	case "mailfilters":
		// The id is the mail login.
		if err := client.Mail.DeleteFilters(ctx, id); err != nil {
			return err
		}
		fmt.Printf("mailfilters of mailaccount/%s deleted\n", id)
	case "domains":
		return fmt.Errorf("domains cannot be deleted with kascli; use 'kascli exec delete_domain ...' if you really mean it")
	case "tls":
		return fmt.Errorf("a certificate cannot be deleted; disable it with 'kascli update tls %s --active=false'", id)
	}
	return nil
}

func newExecCmd(g *globals) *cobra.Command {
	return &cobra.Command{
		Use:   "exec <action> [key=value ...]",
		Short: "run any raw KAS action",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			return cmdExec(g, args)
		},
	}
}

func cmdExec(g *globals, args []string) error {
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
