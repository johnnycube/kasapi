// Copyright 2026 The kasapi Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/spf13/cobra"
)

// canonicalResource maps kubectl-style names, aliases and short names to the
// canonical resource.
func canonicalResource(s string) (string, error) {
	switch strings.ToLower(s) {
	case "domains", "domain", "do":
		return "domains", nil
	case "dnsrecords", "dnsrecord", "dns":
		return "dnsrecords", nil
	case "mailaccounts", "mailaccount", "ma":
		return "mailaccounts", nil
	case "mailforwards", "mailforward", "mf":
		return "mailforwards", nil
	case "subdomains", "subdomain", "sub":
		return "subdomains", nil
	}
	return "", fmt.Errorf(`the server doesn't have a resource type %q (available: domains, dnsrecords, mailaccounts, mailforwards, subdomains)`, s)
}

func newGetCmd(g *globals) *cobra.Command {
	var zone string
	cmd := &cobra.Command{
		Use:   "get <resource>",
		Short: "list resources (domains, dnsrecords, mailaccounts, mailforwards, subdomains)",
		Args:  cobra.MinimumNArgs(1),
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
				name:   "domain/" + d.Name,
				cells:  []string{d.Name, d.Path},
				object: map[string]any{"name": d.Name, "path": d.Path},
			})
		}
		return p.printList([]string{"NAME", "PATH"}, nil, rows)

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
				wideCells: []string{r.Zone, boolWord(r.Changeable)},
				object: map[string]any{
					"id": r.ID, "zone": r.Zone, "name": r.Name, "type": r.Type,
					"data": r.Data, "aux": r.Aux, "changeable": r.Changeable,
				},
			})
		}
		return p.printList(
			[]string{"ID", "NAME", "TYPE", "DATA", "AUX"},
			[]string{"ZONE", "CHANGEABLE"}, rows)

	case "mailaccounts":
		accounts, err := client.Mail.ListAccounts(ctx)
		if err != nil {
			return err
		}
		rows := make([]row, 0, len(accounts))
		for _, a := range accounts {
			rows = append(rows, row{
				name:      "mailaccount/" + a.Login,
				cells:     []string{a.Login, a.Address(), boolWord(a.ResponderActive)},
				wideCells: []string{strings.Join(a.CopyAddresses, ",")},
				object: map[string]any{
					"login": a.Login, "address": a.Address(),
					"responderActive": a.ResponderActive,
					"copyAddresses":   anySlice(a.CopyAddresses),
				},
			})
		}
		return p.printList(
			[]string{"LOGIN", "ADDRESS", "RESPONDER"},
			[]string{"COPY-ADDRESSES"}, rows)

	case "mailforwards":
		forwards, err := client.Mail.ListForwards(ctx)
		if err != nil {
			return err
		}
		rows := make([]row, 0, len(forwards))
		for _, f := range forwards {
			rows = append(rows, row{
				name:  "mailforward/" + f.Source(),
				cells: []string{f.Source(), strings.Join(f.Targets, ",")},
				object: map[string]any{
					"source": f.Source(), "targets": anySlice(f.Targets),
				},
			})
		}
		return p.printList([]string{"SOURCE", "TARGETS"}, nil, rows)

	case "subdomains":
		subs, err := client.Subdomains.List(ctx)
		if err != nil {
			return err
		}
		rows := make([]row, 0, len(subs))
		for _, s := range subs {
			rows = append(rows, row{
				name:   "subdomain/" + s.FQDN,
				cells:  []string{s.FQDN, s.Path},
				object: map[string]any{"fqdn": s.FQDN, "path": s.Path},
			})
		}
		return p.printList([]string{"FQDN", "PATH"}, nil, rows)
	}
	return nil
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
	case "domains":
		return fmt.Errorf("domains are read-only in kascli; use 'kascli exec delete_domain ...' if you really mean it")
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
		Short: "list resources supported by get/delete",
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
	type res struct{ name, short, verbs string }
	resources := []res{
		{"dnsrecords", "dns", "get,delete"},
		{"domains", "do", "get"},
		{"mailaccounts", "ma", "get,delete"},
		{"mailforwards", "mf", "get,delete"},
		{"subdomains", "sub", "get,delete"},
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
