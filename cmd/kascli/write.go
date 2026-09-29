// Copyright 2026 The kasapi Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	kasapi "github.com/johnnycube/kasapi"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

// Secrets are read from stdin or a prompt, never from flag values.

// resourceCmd returns the subcommand of a resource, with its aliases.
func resourceCmd(name, short string, withID bool) *cobra.Command {
	for _, r := range resources {
		if r.name != name {
			continue
		}
		cmd := &cobra.Command{Use: r.kind, Aliases: r.aliases(), Short: short, Args: cobra.NoArgs}
		if withID {
			cmd.Use += " <id>"
			cmd.Args = cobra.ExactArgs(1)
		}
		return cmd
	}
	panic("kascli: unknown resource " + name)
}

// changedLocal counts the given flags of cmd, without inherited ones and the exceptions.
func changedLocal(cmd *cobra.Command, except ...string) int {
	n := 0
	cmd.Flags().Visit(func(f *pflag.Flag) {
		if cmd.InheritedFlags().Lookup(f.Name) != nil {
			return
		}
		for _, name := range except {
			if f.Name == name {
				return
			}
		}
		n++
	})
	return n
}

// nonEmpty drops empty entries, so that --flag "" yields an empty list.
func nonEmpty(items []string) []string {
	out := make([]string, 0, len(items))
	for _, it := range items {
		if it = strings.TrimSpace(it); it != "" {
			out = append(out, it)
		}
	}
	return out
}

// newSecret reads a new password from stdin or a terminal prompt.
func newSecret(fromStdin bool, label string) (string, error) {
	if fromStdin {
		return readSecretLine()
	}
	return promptSecret(label)
}

// readPEM reads a PEM file named by a flag.
func readPEM(flag, path string) (string, error) {
	// G304: the path is the caller's own command-line argument.
	data, err := os.ReadFile(path) //nolint:gosec
	if err != nil {
		return "", fmt.Errorf("--%s: %w", flag, err)
	}
	return string(data), nil
}

// splitAddress splits local@domain.
func splitAddress(addr string) (local, domain string, err error) {
	local, domain, ok := strings.Cut(addr, "@")
	if !ok || local == "" || domain == "" {
		return "", "", fmt.Errorf("invalid address %q, expected local@domain", addr)
	}
	return local, domain, nil
}

// hostFlags are the flags domains and subdomains share.
type hostFlags struct {
	path     string
	redirect int
	php      string
	active   bool
}

func (h *hostFlags) register(cmd *cobra.Command, withActive bool) {
	f := cmd.Flags()
	f.StringVar(&h.path, "path", "", "document root, or the redirect target with --redirect")
	f.IntVar(&h.redirect, "redirect", 0, "redirect status: 0 (none), 301, 302 or 307")
	f.StringVar(&h.php, "php", "", "PHP version, e.g. 8.4")
	if withActive {
		f.BoolVar(&h.active, "active", true, "serve the host")
	}
}

// settings returns the flags that were given as HostSettings.
func (h *hostFlags) settings(cmd *cobra.Command) kasapi.HostSettings {
	hs := kasapi.HostSettings{Path: h.path, PHPVersion: h.php}
	if cmd.Flags().Changed("redirect") {
		hs.RedirectStatus = &h.redirect
	}
	if f := cmd.Flags().Lookup("active"); f != nil && f.Changed {
		hs.Active = &h.active
	}
	return hs
}

// --- create -----------------------------------------------------------------

func newCreateCmd(g *globals) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "create <resource>",
		Short: "create one resource (see api-resources)",
		RunE: func(_ *cobra.Command, args []string) error {
			if len(args) == 0 {
				return fmt.Errorf("usage: kascli create <resource> [flags]")
			}
			return fmt.Errorf("cannot create %q (see kascli api-resources)", args[0])
		},
	}
	cmd.AddCommand(
		createDNSRecordCmd(g),
		createMailAccountCmd(g),
		createMailForwardCmd(g),
		createSubdomainCmd(g),
		createFTPUserCmd(g),
		createDatabaseCmd(g),
		createCronjobCmd(g),
		createDDNSUserCmd(g),
	)
	return cmd
}

func createDNSRecordCmd(g *globals) *cobra.Command {
	var r kasapi.DNSRecord
	cmd := resourceCmd("dnsrecords", "create a DNS record", false)
	cmd.RunE = func(_ *cobra.Command, _ []string) error {
		if r.Zone == "" || r.Type == "" || r.Data == "" {
			return errors.New("--zone, --type and --data are required")
		}
		client, ctx, cancel, err := newClient(g)
		if err != nil {
			return err
		}
		defer cancel()
		id, err := client.DNS.Create(ctx, r)
		if err != nil {
			return err
		}
		fmt.Printf("dnsrecord/%s created\n", id)
		return nil
	}
	f := cmd.Flags()
	f.StringVarP(&r.Zone, "zone", "z", "", "DNS zone, e.g. example.com")
	f.StringVar(&r.Name, "name", "", "record name relative to the zone; empty for the apex")
	f.StringVar(&r.Type, "type", "", "record type: A, AAAA, CNAME, MX, TXT, ...")
	f.StringVar(&r.Data, "data", "", "record data")
	f.IntVar(&r.Aux, "aux", 0, "auxiliary value, e.g. the MX priority")
	return cmd
}

func createMailAccountCmd(g *globals) *cobra.Command {
	var (
		address       string
		copies        []string
		aliases       []string
		allowNets     []string
		passwordStdin bool
	)
	cmd := resourceCmd("mailaccounts", "create a mailbox", false)
	cmd.RunE = func(_ *cobra.Command, _ []string) error {
		local, domain, err := splitAddress(address)
		if err != nil {
			return fmt.Errorf("--address: %w", err)
		}
		password, err := newSecret(passwordStdin, "Password for the mailbox "+address)
		if err != nil {
			return err
		}
		client, ctx, cancel, err := newClient(g)
		if err != nil {
			return err
		}
		defer cancel()
		login, err := client.Mail.CreateAccount(ctx, kasapi.MailAccount{
			LocalPart: local, Domain: domain,
			CopyAddresses: nonEmpty(copies), SenderAliases: nonEmpty(aliases), AllowNets: nonEmpty(allowNets),
		}, password)
		if err != nil {
			return err
		}
		fmt.Printf("mailaccount/%s created\n", login)
		return nil
	}
	f := cmd.Flags()
	f.StringVar(&address, "address", "", "mailbox address, local@domain")
	f.StringSliceVar(&copies, "copy", nil, "address that receives a copy of incoming mail (repeatable)")
	f.StringSliceVar(&aliases, "sender-alias", nil, "address the mailbox may send as (repeatable)")
	f.StringSliceVar(&allowNets, "allow-net", nil, "client allowed to access the mailbox: IP, CIDR or webmail (repeatable)")
	f.BoolVar(&passwordStdin, "password-stdin", false, "read the mailbox password from stdin instead of asking for it")
	return cmd
}

func createMailForwardCmd(g *globals) *cobra.Command {
	var (
		source  string
		targets []string
	)
	cmd := resourceCmd("mailforwards", "create a mail forward", false)
	cmd.RunE = func(_ *cobra.Command, _ []string) error {
		local, domain, err := splitAddress(source)
		if err != nil {
			return fmt.Errorf("--source: %w", err)
		}
		client, ctx, cancel, err := newClient(g)
		if err != nil {
			return err
		}
		defer cancel()
		fw := kasapi.MailForward{LocalPart: local, Domain: domain, Targets: nonEmpty(targets)}
		if err := client.Mail.CreateForward(ctx, fw); err != nil {
			return err
		}
		fmt.Printf("mailforward/%s created\n", fw.Source())
		return nil
	}
	f := cmd.Flags()
	f.StringVar(&source, "source", "", "address to forward, local@domain")
	f.StringSliceVar(&targets, "target", nil, "address to forward to (repeatable, at most 10)")
	return cmd
}

func createSubdomainCmd(g *globals) *cobra.Command {
	var (
		name, domain string
		host         hostFlags
	)
	cmd := resourceCmd("subdomains", "create a subdomain", false)
	cmd.RunE = func(cmd *cobra.Command, _ []string) error {
		if name == "" || domain == "" {
			return errors.New("--name and --domain are required")
		}
		client, ctx, cancel, err := newClient(g)
		if err != nil {
			return err
		}
		defer cancel()
		if err := client.Subdomains.CreateWithSettings(ctx, name, domain, host.settings(cmd)); err != nil {
			return err
		}
		fmt.Printf("subdomain/%s.%s created\n", name, domain)
		return nil
	}
	f := cmd.Flags()
	f.StringVar(&name, "name", "", "subdomain label, e.g. blog")
	f.StringVar(&domain, "domain", "", "domain the label is added to, e.g. example.com")
	host.register(cmd, false)
	return cmd
}

// ftpFlags are the flags create and update of an FTP user share.
type ftpFlags struct {
	path, comment          string
	read, write, list, scn bool
	passwordStdin          bool
}

func (ff *ftpFlags) register(cmd *cobra.Command) {
	f := cmd.Flags()
	f.StringVar(&ff.path, "path", "", "directory the login is confined to (default /)")
	f.StringVar(&ff.comment, "comment", "", "free text describing the login")
	f.BoolVar(&ff.read, "read", true, "may download files")
	f.BoolVar(&ff.write, "write", true, "may upload, change and delete files")
	f.BoolVar(&ff.list, "list", true, "may list directories")
	f.BoolVar(&ff.scn, "virus-scan", true, "scan uploads with ClamAV")
}

// apply sets the given flags on u.
func (ff *ftpFlags) apply(cmd *cobra.Command, u *kasapi.FTPUser) {
	fl := cmd.Flags()
	if fl.Changed("path") {
		u.Path = ff.path
	}
	if fl.Changed("comment") {
		u.Comment = ff.comment
	}
	if fl.Changed("read") {
		u.Read = ff.read
	}
	if fl.Changed("write") {
		u.Write = ff.write
	}
	if fl.Changed("list") {
		u.List = ff.list
	}
	if fl.Changed("virus-scan") {
		u.VirusScan = ff.scn
	}
}

func createFTPUserCmd(g *globals) *cobra.Command {
	var ff ftpFlags
	cmd := resourceCmd("ftpusers", "create an FTP user", false)
	cmd.RunE = func(_ *cobra.Command, _ []string) error {
		if ff.comment == "" {
			return errors.New("--comment is required")
		}
		password, err := newSecret(ff.passwordStdin, "Password for the FTP user")
		if err != nil {
			return err
		}
		client, ctx, cancel, err := newClient(g)
		if err != nil {
			return err
		}
		defer cancel()
		login, err := client.FTP.Create(ctx, kasapi.FTPUser{
			Path: ff.path, Comment: ff.comment,
			Read: ff.read, Write: ff.write, List: ff.list, VirusScan: ff.scn,
		}, password)
		if err != nil {
			return err
		}
		fmt.Printf("ftpuser/%s created\n", login)
		return nil
	}
	ff.register(cmd)
	cmd.Flags().BoolVar(&ff.passwordStdin, "password-stdin", false, "read the FTP password from stdin instead of asking for it")
	return cmd
}

func createDatabaseCmd(g *globals) *cobra.Command {
	var (
		comment       string
		hosts         []string
		passwordStdin bool
	)
	cmd := resourceCmd("databases", "create a database", false)
	cmd.RunE = func(_ *cobra.Command, _ []string) error {
		if comment == "" {
			return errors.New("--comment is required")
		}
		password, err := newSecret(passwordStdin, "Password for the database")
		if err != nil {
			return err
		}
		client, ctx, cancel, err := newClient(g)
		if err != nil {
			return err
		}
		defer cancel()
		login, err := client.Databases.Create(ctx, kasapi.Database{Comment: comment, AllowedHosts: nonEmpty(hosts)}, password)
		if err != nil {
			return err
		}
		fmt.Printf("database/%s created\n", login)
		return nil
	}
	f := cmd.Flags()
	f.StringVar(&comment, "comment", "", "free text describing the database")
	f.StringSliceVar(&hosts, "allowed-host", nil, "host allowed to connect from outside: IP or CIDR (repeatable)")
	f.BoolVar(&passwordStdin, "password-stdin", false, "read the database password from stdin instead of asking for it")
	return cmd
}

// cronFlags are the flags create and update of a cronjob share.
type cronFlags struct {
	job               kasapi.Cronjob
	httpPasswordStdin bool
}

func (cf *cronFlags) register(cmd *cobra.Command) {
	f := cmd.Flags()
	j := &cf.job
	f.StringVar(&j.URL, "url", "", "address to request, without protocol, e.g. example.com/cron.php")
	f.StringVar(&j.Protocol, "protocol", "https", "http or https")
	f.StringVar(&j.Comment, "comment", "", "free text describing the job")
	f.StringVar(&j.Minute, "minute", "*", "minute: 0-59, * or */n")
	f.StringVar(&j.Hour, "hour", "*", "hour: 0-23, * or */n")
	f.StringVar(&j.DayOfMonth, "day-of-month", "*", "day of month: 1-31 or *")
	f.StringVar(&j.Month, "month", "*", "month")
	f.StringVar(&j.DayOfWeek, "day-of-week", "*", "day of week: 0-7 or * (Sunday is 0 or 7)")
	f.StringVar(&j.HTTPUser, "http-user", "", "HTTP basic auth user")
	f.BoolVar(&cf.httpPasswordStdin, "http-password-stdin", false, "read the HTTP basic auth password from stdin")
	f.StringVar(&j.MailAddress, "mail", "", "address that receives the output of each run")
	f.StringVar(&j.MailCondition, "mail-condition", "", "no mail when the output contains this word")
	f.StringVar(&j.MailSubject, "mail-subject", "", "default or comment")
	f.BoolVar(&j.Active, "active", true, "run the job")
}

// apply sets the given flags on j.
func (cf *cronFlags) apply(cmd *cobra.Command, j *kasapi.Cronjob) {
	src := cf.job
	for flag, set := range map[string]func(){
		"url":            func() { j.URL = src.URL },
		"protocol":       func() { j.Protocol = src.Protocol },
		"comment":        func() { j.Comment = src.Comment },
		"minute":         func() { j.Minute = src.Minute },
		"hour":           func() { j.Hour = src.Hour },
		"day-of-month":   func() { j.DayOfMonth = src.DayOfMonth },
		"month":          func() { j.Month = src.Month },
		"day-of-week":    func() { j.DayOfWeek = src.DayOfWeek },
		"http-user":      func() { j.HTTPUser = src.HTTPUser },
		"mail":           func() { j.MailAddress = src.MailAddress },
		"mail-condition": func() { j.MailCondition = src.MailCondition },
		"mail-subject":   func() { j.MailSubject = src.MailSubject },
		"active":         func() { j.Active = src.Active },
	} {
		if cmd.Flags().Changed(flag) {
			set()
		}
	}
}

// httpPassword reads the basic auth password from stdin if requested.
func (cf *cronFlags) httpPassword() (string, error) {
	if !cf.httpPasswordStdin {
		return "", nil
	}
	return readSecretLine()
}

func createCronjobCmd(g *globals) *cobra.Command {
	var cf cronFlags
	cmd := resourceCmd("cronjobs", "create a cronjob", false)
	cmd.RunE = func(_ *cobra.Command, _ []string) error {
		if cf.job.URL == "" || cf.job.Comment == "" {
			return errors.New("--url and --comment are required")
		}
		password, err := cf.httpPassword()
		if err != nil {
			return err
		}
		job := cf.job
		job.HTTPPassword = password
		client, ctx, cancel, err := newClient(g)
		if err != nil {
			return err
		}
		defer cancel()
		id, err := client.Cronjobs.Create(ctx, job)
		if err != nil {
			return err
		}
		fmt.Printf("cronjob/%s created\n", id)
		return nil
	}
	cf.register(cmd)
	return cmd
}

func createDDNSUserCmd(g *globals) *cobra.Command {
	var (
		u             kasapi.DDNSUser
		passwordStdin bool
	)
	cmd := resourceCmd("ddnsusers", "create a dynamic DNS user", false)
	cmd.RunE = func(_ *cobra.Command, _ []string) error {
		if u.Zone == "" || u.Label == "" || u.TargetIP == "" || u.Comment == "" {
			return errors.New("--zone, --label, --target-ip and --comment are required")
		}
		password, err := newSecret(passwordStdin, "Password for the DDNS user")
		if err != nil {
			return err
		}
		client, ctx, cancel, err := newClient(g)
		if err != nil {
			return err
		}
		defer cancel()
		login, err := client.DDNS.Create(ctx, u, password)
		if err != nil {
			return err
		}
		fmt.Printf("ddnsuser/%s created\n", login)
		return nil
	}
	f := cmd.Flags()
	f.StringVarP(&u.Zone, "zone", "z", "", "zone of the host, e.g. example.com")
	f.StringVar(&u.Label, "label", "", "host label inside the zone, e.g. home")
	f.StringVar(&u.TargetIP, "target-ip", "", "initial IPv4 address of the host")
	f.StringVar(&u.Comment, "comment", "", "free text describing the user")
	f.BoolVar(&u.DualStack, "dual-stack", false, "let the host carry an A and an AAAA record")
	f.BoolVar(&passwordStdin, "password-stdin", false, "read the DDNS password from stdin instead of asking for it")
	return cmd
}

// --- update -----------------------------------------------------------------

func newUpdateCmd(g *globals) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "update <resource> <id>",
		Short: "change one resource; only the given flags are changed (see api-resources)",
		RunE: func(_ *cobra.Command, args []string) error {
			if len(args) == 0 {
				return fmt.Errorf("usage: kascli update <resource> <id> [flags]")
			}
			return fmt.Errorf("cannot update %q (see kascli api-resources)", args[0])
		},
	}
	cmd.AddCommand(
		updateDNSRecordCmd(g),
		updateDomainCmd(g),
		updateSubdomainCmd(g),
		updateTLSCmd(g),
		updateMailAccountCmd(g),
		updateMailForwardCmd(g),
		updateFTPUserCmd(g),
		updateDatabaseCmd(g),
		updateCronjobCmd(g),
		updateDDNSUserCmd(g),
	)
	return cmd
}

// noChange is the error of an update without any flag.
func noChange(cmd *cobra.Command) error {
	if changedLocal(cmd) == 0 {
		return errors.New("nothing to update: give at least one flag")
	}
	return nil
}

func updateDNSRecordCmd(g *globals) *cobra.Command {
	var (
		zone, name, data string
		aux              int
	)
	cmd := resourceCmd("dnsrecords", "change name, data or aux of a DNS record", true)
	cmd.RunE = func(cmd *cobra.Command, args []string) error {
		if zone == "" {
			return errors.New("--zone is required: the current record is read from it")
		}
		fl := cmd.Flags()
		if !fl.Changed("name") && !fl.Changed("data") && !fl.Changed("aux") {
			return errors.New("nothing to update: give --name, --data or --aux")
		}
		client, ctx, cancel, err := newClient(g)
		if err != nil {
			return err
		}
		defer cancel()
		rec, err := client.DNS.Get(ctx, zone, args[0])
		if err != nil {
			return err
		}
		if fl.Changed("name") {
			rec.Name = name
		}
		if fl.Changed("data") {
			rec.Data = data
		}
		if fl.Changed("aux") {
			rec.Aux = aux
		}
		if err := client.DNS.Update(ctx, *rec); err != nil {
			return err
		}
		fmt.Printf("dnsrecord/%s updated\n", rec.ID)
		return nil
	}
	f := cmd.Flags()
	f.StringVarP(&zone, "zone", "z", "", "DNS zone of the record")
	f.StringVar(&name, "name", "", "record name relative to the zone")
	f.StringVar(&data, "data", "", "record data")
	f.IntVar(&aux, "aux", 0, "auxiliary value, e.g. the MX priority")
	return cmd
}

func updateDomainCmd(g *globals) *cobra.Command {
	var host hostFlags
	cmd := resourceCmd("domains", "change the host settings of a domain", true)
	cmd.RunE = func(cmd *cobra.Command, args []string) error {
		if err := noChange(cmd); err != nil {
			return err
		}
		client, ctx, cancel, err := newClient(g)
		if err != nil {
			return err
		}
		defer cancel()
		if err := client.Domains.Update(ctx, args[0], host.settings(cmd)); err != nil {
			return err
		}
		fmt.Printf("domain/%s updated\n", args[0])
		return nil
	}
	host.register(cmd, true)
	return cmd
}

func updateSubdomainCmd(g *globals) *cobra.Command {
	var host hostFlags
	cmd := resourceCmd("subdomains", "change the host settings of a subdomain", true)
	cmd.RunE = func(cmd *cobra.Command, args []string) error {
		if err := noChange(cmd); err != nil {
			return err
		}
		client, ctx, cancel, err := newClient(g)
		if err != nil {
			return err
		}
		defer cancel()
		if err := client.Subdomains.Update(ctx, args[0], host.settings(cmd)); err != nil {
			return err
		}
		fmt.Printf("subdomain/%s updated\n", args[0])
		return nil
	}
	host.register(cmd, true)
	return cmd
}

func updateTLSCmd(g *globals) *cobra.Command {
	var (
		certFile, keyFile, bundleFile, csrFile string
		active, forceHTTPS                     bool
		hsts                                   int
	)
	cmd := resourceCmd("tls", "install a certificate on a host, or set its HTTPS redirect and HSTS", true)
	cmd.Long = `Install a certificate on a domain or subdomain, or set its HTTPS redirect
and HSTS.

The KAS API installs certificates you bring. It cannot request a Let's Encrypt
certificate: that switch exists in the KAS panel only (Domain -> Edit -> SSL
protection -> Let's Encrypt). "kascli get tls <host>" shows whether a host
uses one.`
	cmd.RunE = func(cmd *cobra.Command, args []string) error {
		if err := noChange(cmd); err != nil {
			return err
		}
		var (
			u   kasapi.TLSUpdate
			err error
		)
		for _, file := range []struct {
			flag, path string
			dst        *string
		}{
			{"cert", certFile, &u.Certificate},
			{"key", keyFile, &u.Key},
			{"bundle", bundleFile, &u.Bundle},
			{"csr", csrFile, &u.CSR},
		} {
			if file.path == "" {
				continue
			}
			if *file.dst, err = readPEM(file.flag, file.path); err != nil {
				return err
			}
		}
		fl := cmd.Flags()
		if fl.Changed("active") {
			u.Active = &active
		}
		if fl.Changed("force-https") {
			u.ForceHTTPS = &forceHTTPS
		}
		if fl.Changed("hsts-max-age") {
			u.HSTSMaxAge = &hsts
		}
		client, ctx, cancel, err := newClient(g)
		if err != nil {
			return err
		}
		defer cancel()
		if err := client.TLS.Update(ctx, args[0], u); err != nil {
			return err
		}
		fmt.Printf("tls/%s updated\n", args[0])
		return nil
	}
	f := cmd.Flags()
	f.StringVar(&certFile, "cert", "", "PEM file with the certificate")
	f.StringVar(&keyFile, "key", "", "PEM file with the private key")
	f.StringVar(&bundleFile, "bundle", "", "PEM file with the intermediate certificates")
	f.StringVar(&csrFile, "csr", "", "PEM file with the signing request")
	f.BoolVar(&active, "active", true, "serve the certificate")
	f.BoolVar(&forceHTTPS, "force-https", false, "redirect HTTP requests to HTTPS")
	f.IntVar(&hsts, "hsts-max-age", -1, "HSTS max-age in seconds; -1 turns HSTS off")
	return cmd
}

func updateMailAccountCmd(g *globals) *cobra.Command {
	var (
		copies, aliases, allowNets, filters []string
		state                               string
		autologin, passwordStdin            bool
		responder                           string
		responderText, responderType        string
		responderName, responderFrom        string
		responderUntil                      string
	)
	cmd := resourceCmd("mailaccounts", "change a mailbox", true)
	cmd.RunE = func(cmd *cobra.Command, args []string) error {
		if err := noChange(cmd); err != nil {
			return err
		}
		login := args[0]
		fl := cmd.Flags()

		// Validate every flag before the first request.
		var mailState kasapi.MailState
		if fl.Changed("state") {
			switch state {
			case "active":
				mailState = kasapi.MailActive
			case "receive-disabled":
				mailState = kasapi.MailReceiveDisabled
			case "forbidden":
				mailState = kasapi.MailForbidden
			default:
				return fmt.Errorf("--state must be active, receive-disabled or forbidden")
			}
		}
		var resp *kasapi.Responder
		if fl.Changed("responder") {
			r, err := responderFromFlags(responder, responderText, responderType, responderName, responderFrom, responderUntil)
			if err != nil {
				return err
			}
			resp = &r
		} else if fl.Changed("responder-text") || fl.Changed("responder-from") || fl.Changed("responder-until") ||
			fl.Changed("responder-type") || fl.Changed("responder-name") {
			return errors.New("the responder flags need --responder on")
		}
		var mailFilters []kasapi.MailFilter
		for _, f := range nonEmpty(filters) {
			name, action, _ := strings.Cut(f, ":")
			mailFilters = append(mailFilters, kasapi.MailFilter{Name: name, Action: action})
		}
		var password string
		if passwordStdin {
			var err error
			if password, err = readSecretLine(); err != nil {
				return err
			}
		}

		client, ctx, cancel, err := newClient(g)
		if err != nil {
			return err
		}
		defer cancel()

		steps := []struct {
			on  bool
			run func() error
		}{
			{passwordStdin, func() error { return client.Mail.UpdatePassword(ctx, login, password) }},
			{fl.Changed("copy"), func() error { return client.Mail.UpdateCopyAddresses(ctx, login, nonEmpty(copies)) }},
			{fl.Changed("sender-alias"), func() error { return client.Mail.UpdateSenderAliases(ctx, login, nonEmpty(aliases)) }},
			{fl.Changed("allow-net"), func() error { return client.Mail.UpdateAllowNets(ctx, login, nonEmpty(allowNets)) }},
			{fl.Changed("state"), func() error { return client.Mail.UpdateState(ctx, login, mailState) }},
			{fl.Changed("webmail-autologin"), func() error { return client.Mail.UpdateWebmailAutologin(ctx, login, autologin) }},
			{resp != nil, func() error { return client.Mail.UpdateResponder(ctx, login, *resp) }},
			{fl.Changed("filter"), func() error {
				if len(mailFilters) == 0 {
					return client.Mail.DeleteFilters(ctx, login)
				}
				return client.Mail.SetFilters(ctx, login, mailFilters)
			}},
		}
		for _, step := range steps {
			if !step.on {
				continue
			}
			if err := step.run(); err != nil {
				return err
			}
		}
		fmt.Printf("mailaccount/%s updated\n", login)
		return nil
	}
	f := cmd.Flags()
	f.StringSliceVar(&copies, "copy", nil, `addresses that receive a copy of incoming mail; --copy "" clears them`)
	f.StringSliceVar(&aliases, "sender-alias", nil, `addresses the mailbox may send as; --sender-alias "" clears them`)
	f.StringSliceVar(&allowNets, "allow-net", nil, `clients allowed to access the mailbox: IP, CIDR or webmail; --allow-net "" lifts the restriction`)
	f.StringVar(&state, "state", "", "active, receive-disabled or forbidden")
	f.BoolVar(&autologin, "webmail-autologin", true, "let the KAS panel log into webmail without the mailbox password")
	f.BoolVar(&passwordStdin, "password-stdin", false, "read the new mailbox password from stdin")
	f.StringVar(&responder, "responder", "", "on or off")
	f.StringVar(&responderText, "responder-text", "", "reply text of the responder")
	f.StringVar(&responderType, "responder-type", "", "text or html")
	f.StringVar(&responderName, "responder-name", "", "sender name shown on the reply")
	f.StringVar(&responderFrom, "responder-from", "", "start of the responder window, RFC 3339 or YYYY-MM-DD")
	f.StringVar(&responderUntil, "responder-until", "", "end of the responder window, RFC 3339 or YYYY-MM-DD")
	f.StringSliceVar(&filters, "filter", nil, `standard filters as name or name:action (see "kascli get mailfilters"); --filter "" removes them`)
	return cmd
}

// responderFromFlags builds the responder of "update mailaccount".
func responderFromFlags(mode, text, contentType, name, from, until string) (kasapi.Responder, error) {
	switch mode {
	case "off":
		return kasapi.Responder{}, nil
	case "on":
	default:
		return kasapi.Responder{}, errors.New("--responder must be on or off")
	}
	r := kasapi.Responder{Active: true, Text: text, ContentType: contentType, DisplayName: name}
	var err error
	if from != "" {
		if r.Start, err = parseTime(from); err != nil {
			return r, fmt.Errorf("--responder-from: %w", err)
		}
	}
	if until != "" {
		if r.End, err = parseTime(until); err != nil {
			return r, fmt.Errorf("--responder-until: %w", err)
		}
	}
	return r, nil
}

// parseTime accepts RFC 3339 or a plain date, which is read as local midnight.
func parseTime(s string) (time.Time, error) {
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t, nil
	}
	t, err := time.ParseInLocation(time.DateOnly, s, time.Local)
	if err != nil {
		return time.Time{}, fmt.Errorf("invalid time %q, expected RFC 3339 or YYYY-MM-DD", s)
	}
	return t, nil
}

func updateMailForwardCmd(g *globals) *cobra.Command {
	var targets []string
	cmd := resourceCmd("mailforwards", "replace the targets of a mail forward", true)
	cmd.RunE = func(_ *cobra.Command, args []string) error {
		local, domain, err := splitAddress(args[0])
		if err != nil {
			return err
		}
		if len(nonEmpty(targets)) == 0 {
			return errors.New("--target is required")
		}
		client, ctx, cancel, err := newClient(g)
		if err != nil {
			return err
		}
		defer cancel()
		fw := kasapi.MailForward{LocalPart: local, Domain: domain, Targets: nonEmpty(targets)}
		if err := client.Mail.UpdateForward(ctx, fw); err != nil {
			return err
		}
		fmt.Printf("mailforward/%s updated\n", fw.Source())
		return nil
	}
	cmd.Flags().StringSliceVar(&targets, "target", nil, "address to forward to (repeatable, at most 10)")
	return cmd
}

func updateFTPUserCmd(g *globals) *cobra.Command {
	var ff ftpFlags
	cmd := resourceCmd("ftpusers", "change an FTP user", true)
	cmd.RunE = func(cmd *cobra.Command, args []string) error {
		if err := noChange(cmd); err != nil {
			return err
		}
		var password string
		if ff.passwordStdin {
			var err error
			if password, err = readSecretLine(); err != nil {
				return err
			}
		}
		client, ctx, cancel, err := newClient(g)
		if err != nil {
			return err
		}
		defer cancel()
		if settingsChanged(cmd, "password-stdin") {
			u, err := client.FTP.Get(ctx, args[0])
			if err != nil {
				return err
			}
			ff.apply(cmd, u)
			if err := client.FTP.Update(ctx, *u); err != nil {
				return err
			}
		}
		if ff.passwordStdin {
			if err := client.FTP.UpdatePassword(ctx, args[0], password); err != nil {
				return err
			}
		}
		fmt.Printf("ftpuser/%s updated\n", args[0])
		return nil
	}
	ff.register(cmd)
	cmd.Flags().BoolVar(&ff.passwordStdin, "password-stdin", false, "read the new FTP password from stdin")
	return cmd
}

// settingsChanged reports whether a flag other than the named ones was given.
func settingsChanged(cmd *cobra.Command, except ...string) bool {
	return changedLocal(cmd, except...) > 0
}

func updateDatabaseCmd(g *globals) *cobra.Command {
	var (
		comment       string
		hosts         []string
		passwordStdin bool
	)
	cmd := resourceCmd("databases", "change a database", true)
	cmd.RunE = func(cmd *cobra.Command, args []string) error {
		if err := noChange(cmd); err != nil {
			return err
		}
		var password string
		if passwordStdin {
			var err error
			if password, err = readSecretLine(); err != nil {
				return err
			}
		}
		client, ctx, cancel, err := newClient(g)
		if err != nil {
			return err
		}
		defer cancel()
		if settingsChanged(cmd, "password-stdin") {
			db, err := client.Databases.Get(ctx, args[0])
			if err != nil {
				return err
			}
			if cmd.Flags().Changed("comment") {
				db.Comment = comment
			}
			if cmd.Flags().Changed("allowed-host") {
				db.AllowedHosts = nonEmpty(hosts)
			}
			if err := client.Databases.Update(ctx, *db); err != nil {
				return err
			}
		}
		if passwordStdin {
			if err := client.Databases.UpdatePassword(ctx, args[0], password); err != nil {
				return err
			}
		}
		fmt.Printf("database/%s updated\n", args[0])
		return nil
	}
	f := cmd.Flags()
	f.StringVar(&comment, "comment", "", "free text describing the database")
	f.StringSliceVar(&hosts, "allowed-host", nil, `hosts allowed to connect from outside: IP or CIDR; --allowed-host "" closes external access`)
	f.BoolVar(&passwordStdin, "password-stdin", false, "read the new database password from stdin")
	return cmd
}

func updateCronjobCmd(g *globals) *cobra.Command {
	var cf cronFlags
	cmd := resourceCmd("cronjobs", "change a cronjob", true)
	cmd.RunE = func(cmd *cobra.Command, args []string) error {
		if err := noChange(cmd); err != nil {
			return err
		}
		password, err := cf.httpPassword()
		if err != nil {
			return err
		}
		client, ctx, cancel, err := newClient(g)
		if err != nil {
			return err
		}
		defer cancel()
		job, err := client.Cronjobs.Get(ctx, args[0])
		if err != nil {
			return err
		}
		cf.apply(cmd, job)
		job.HTTPPassword = password
		if err := client.Cronjobs.Update(ctx, *job); err != nil {
			return err
		}
		fmt.Printf("cronjob/%s updated\n", job.ID)
		return nil
	}
	cf.register(cmd)
	return cmd
}

func updateDDNSUserCmd(g *globals) *cobra.Command {
	var (
		comment       string
		dualStack     bool
		passwordStdin bool
	)
	cmd := resourceCmd("ddnsusers", "change a dynamic DNS user", true)
	cmd.RunE = func(cmd *cobra.Command, args []string) error {
		if err := noChange(cmd); err != nil {
			return err
		}
		var password string
		if passwordStdin {
			var err error
			if password, err = readSecretLine(); err != nil {
				return err
			}
		}
		client, ctx, cancel, err := newClient(g)
		if err != nil {
			return err
		}
		defer cancel()
		if settingsChanged(cmd, "password-stdin") {
			u, err := client.DDNS.Get(ctx, args[0])
			if err != nil {
				return err
			}
			if cmd.Flags().Changed("comment") {
				u.Comment = comment
			}
			if cmd.Flags().Changed("dual-stack") {
				u.DualStack = dualStack
			}
			if err := client.DDNS.Update(ctx, *u); err != nil {
				return err
			}
		}
		if passwordStdin {
			if err := client.DDNS.UpdatePassword(ctx, args[0], password); err != nil {
				return err
			}
		}
		fmt.Printf("ddnsuser/%s updated\n", args[0])
		return nil
	}
	f := cmd.Flags()
	f.StringVar(&comment, "comment", "", "free text describing the user")
	f.BoolVar(&dualStack, "dual-stack", false, "let the host carry an A and an AAAA record")
	f.BoolVar(&passwordStdin, "password-stdin", false, "read the new DDNS password from stdin")
	return cmd
}
