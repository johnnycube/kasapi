// Copyright 2026 The kasapi Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
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
		setIfChanged(fl, "name", &rec.Name, name)
		setIfChanged(fl, "data", &rec.Data, data)
		setIfChanged(fl, "aux", &rec.Aux, aux)
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

// setIfChanged sets *dst to v when the flag was given.
func setIfChanged[T any](fl *pflag.FlagSet, flag string, dst *T, v T) {
	if fl.Changed(flag) {
		*dst = v
	}
}

func updateDomainCmd(g *globals) *cobra.Command {
	return updateHostCmd(g, "domains", "domain", func(ctx context.Context, c *kasapi.Client, name string, s kasapi.HostSettings) error {
		return c.Domains.Update(ctx, name, s)
	})
}

func updateSubdomainCmd(g *globals) *cobra.Command {
	return updateHostCmd(g, "subdomains", "subdomain", func(ctx context.Context, c *kasapi.Client, name string, s kasapi.HostSettings) error {
		return c.Subdomains.Update(ctx, name, s)
	})
}

// updateHostCmd changes the host settings of a domain or subdomain.
func updateHostCmd(g *globals, res, kind string, update func(context.Context, *kasapi.Client, string, kasapi.HostSettings) error) *cobra.Command {
	var host hostFlags
	cmd := resourceCmd(res, "change the host settings of a "+kind, true)
	cmd.RunE = func(cmd *cobra.Command, args []string) error {
		if err := noChange(cmd); err != nil {
			return err
		}
		client, ctx, cancel, err := newClient(g)
		if err != nil {
			return err
		}
		defer cancel()
		if err := update(ctx, client, args[0], host.settings(cmd)); err != nil {
			return err
		}
		fmt.Printf("%s/%s updated\n", kind, args[0])
		return nil
	}
	host.register(cmd, true)
	return cmd
}

// tlsFlags are the flags of "update tls".
type tlsFlags struct {
	certFile, keyFile, bundleFile, csrFile string
	active, forceHTTPS                     bool
	hsts                                   int
}

func (tf *tlsFlags) register(cmd *cobra.Command) {
	f := cmd.Flags()
	f.StringVar(&tf.certFile, "cert", "", "PEM file with the certificate")
	f.StringVar(&tf.keyFile, "key", "", "PEM file with the private key")
	f.StringVar(&tf.bundleFile, "bundle", "", "PEM file with the intermediate certificates")
	f.StringVar(&tf.csrFile, "csr", "", "PEM file with the signing request")
	f.BoolVar(&tf.active, "active", true, "serve the certificate")
	f.BoolVar(&tf.forceHTTPS, "force-https", false, "redirect HTTP requests to HTTPS")
	f.IntVar(&tf.hsts, "hsts-max-age", -1, "HSTS max-age in seconds; -1 turns HSTS off")
}

// update reads the PEM files and collects the given settings.
func (tf *tlsFlags) update(cmd *cobra.Command) (kasapi.TLSUpdate, error) {
	var u kasapi.TLSUpdate
	for _, file := range []struct {
		flag, path string
		dst        *string
	}{
		{"cert", tf.certFile, &u.Certificate},
		{"key", tf.keyFile, &u.Key},
		{"bundle", tf.bundleFile, &u.Bundle},
		{"csr", tf.csrFile, &u.CSR},
	} {
		if file.path == "" {
			continue
		}
		pem, err := readPEM(file.flag, file.path)
		if err != nil {
			return u, err
		}
		*file.dst = pem
	}
	fl := cmd.Flags()
	setIfChanged(fl, "active", &u.Active, &tf.active)
	setIfChanged(fl, "force-https", &u.ForceHTTPS, &tf.forceHTTPS)
	setIfChanged(fl, "hsts-max-age", &u.HSTSMaxAge, &tf.hsts)
	return u, nil
}

func updateTLSCmd(g *globals) *cobra.Command {
	var tf tlsFlags
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
		u, err := tf.update(cmd)
		if err != nil {
			return err
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
	tf.register(cmd)
	return cmd
}

// mailAccountFlags are the flags of "update mailaccount".
type mailAccountFlags struct {
	copies, aliases, allowNets, filters []string
	state                               string
	autologin, passwordStdin            bool
	responder                           string
	responderText, responderType        string
	responderName, responderFrom        string
	responderUntil                      string
}

func (mf *mailAccountFlags) register(cmd *cobra.Command) {
	f := cmd.Flags()
	f.StringSliceVar(&mf.copies, "copy", nil, `addresses that receive a copy of incoming mail; --copy "" clears them`)
	f.StringSliceVar(&mf.aliases, "sender-alias", nil, `addresses the mailbox may send as; --sender-alias "" clears them`)
	f.StringSliceVar(&mf.allowNets, "allow-net", nil, `clients allowed to access the mailbox: IP, CIDR or webmail; --allow-net "" lifts the restriction`)
	f.StringVar(&mf.state, "state", "", "active, receive-disabled or forbidden")
	f.BoolVar(&mf.autologin, "webmail-autologin", true, "let the KAS panel log into webmail without the mailbox password")
	f.BoolVar(&mf.passwordStdin, "password-stdin", false, "read the new mailbox password from stdin")
	f.StringVar(&mf.responder, "responder", "", "on or off")
	f.StringVar(&mf.responderText, "responder-text", "", "reply text of the responder")
	f.StringVar(&mf.responderType, "responder-type", "", "text or html")
	f.StringVar(&mf.responderName, "responder-name", "", "sender name shown on the reply")
	f.StringVar(&mf.responderFrom, "responder-from", "", "start of the responder window, RFC 3339 or YYYY-MM-DD")
	f.StringVar(&mf.responderUntil, "responder-until", "", "end of the responder window, RFC 3339 or YYYY-MM-DD")
	f.StringSliceVar(&mf.filters, "filter", nil, `standard filters as name or name:action (see "kascli get mailfilters"); --filter "" removes them`)
}

// mailAccountUpdate is the validated input of "update mailaccount".
type mailAccountUpdate struct {
	state     kasapi.MailState
	responder *kasapi.Responder
	filters   []kasapi.MailFilter
	password  string
}

var mailStates = map[string]kasapi.MailState{
	"active":           kasapi.MailActive,
	"receive-disabled": kasapi.MailReceiveDisabled,
	"forbidden":        kasapi.MailForbidden,
}

// parse validates every flag, so no request is sent for an invalid command.
func (mf *mailAccountFlags) parse(fl *pflag.FlagSet) (mailAccountUpdate, error) {
	var u mailAccountUpdate
	if fl.Changed("state") {
		s, ok := mailStates[mf.state]
		if !ok {
			return u, errors.New("--state must be active, receive-disabled or forbidden")
		}
		u.state = s
	}
	resp, err := mf.parseResponder(fl)
	if err != nil {
		return u, err
	}
	u.responder = resp
	for _, f := range nonEmpty(mf.filters) {
		name, action, _ := strings.Cut(f, ":")
		u.filters = append(u.filters, kasapi.MailFilter{Name: name, Action: action})
	}
	if u.password, err = optionalSecret(mf.passwordStdin); err != nil {
		return u, err
	}
	return u, nil
}

func (mf *mailAccountFlags) parseResponder(fl *pflag.FlagSet) (*kasapi.Responder, error) {
	if !fl.Changed("responder") {
		for _, name := range []string{"responder-text", "responder-from", "responder-until", "responder-type", "responder-name"} {
			if fl.Changed(name) {
				return nil, errors.New("the responder flags need --responder on")
			}
		}
		return nil, nil
	}
	r, err := responderFromFlags(mf.responder, mf.responderText, mf.responderType, mf.responderName, mf.responderFrom, mf.responderUntil)
	if err != nil {
		return nil, err
	}
	return &r, nil
}

// updateStep is one request of an update that is sent when its flag was given.
type updateStep struct {
	on  bool
	run func() error
}

func runSteps(steps []updateStep) error {
	for _, step := range steps {
		if !step.on {
			continue
		}
		if err := step.run(); err != nil {
			return err
		}
	}
	return nil
}

// steps lists the requests of "update mailaccount" in the order they are sent.
func (mf *mailAccountFlags) steps(ctx context.Context, c *kasapi.Client, fl *pflag.FlagSet, login string, u mailAccountUpdate) []updateStep {
	return []updateStep{
		{mf.passwordStdin, func() error { return c.Mail.UpdatePassword(ctx, login, u.password) }},
		{fl.Changed("copy"), func() error { return c.Mail.UpdateCopyAddresses(ctx, login, nonEmpty(mf.copies)) }},
		{fl.Changed("sender-alias"), func() error { return c.Mail.UpdateSenderAliases(ctx, login, nonEmpty(mf.aliases)) }},
		{fl.Changed("allow-net"), func() error { return c.Mail.UpdateAllowNets(ctx, login, nonEmpty(mf.allowNets)) }},
		{fl.Changed("state"), func() error { return c.Mail.UpdateState(ctx, login, u.state) }},
		{fl.Changed("webmail-autologin"), func() error { return c.Mail.UpdateWebmailAutologin(ctx, login, mf.autologin) }},
		{u.responder != nil, func() error { return c.Mail.UpdateResponder(ctx, login, *u.responder) }},
		{fl.Changed("filter"), func() error {
			if len(u.filters) == 0 {
				return c.Mail.DeleteFilters(ctx, login)
			}
			return c.Mail.SetFilters(ctx, login, u.filters)
		}},
	}
}

func updateMailAccountCmd(g *globals) *cobra.Command {
	var mf mailAccountFlags
	cmd := resourceCmd("mailaccounts", "change a mailbox", true)
	cmd.RunE = func(cmd *cobra.Command, args []string) error {
		if err := noChange(cmd); err != nil {
			return err
		}
		login := args[0]
		fl := cmd.Flags()
		u, err := mf.parse(fl)
		if err != nil {
			return err
		}
		client, ctx, cancel, err := newClient(g)
		if err != nil {
			return err
		}
		defer cancel()
		if err := runSteps(mf.steps(ctx, client, fl, login, u)); err != nil {
			return err
		}
		fmt.Printf("mailaccount/%s updated\n", login)
		return nil
	}
	mf.register(cmd)
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

// optionalSecret reads a secret from stdin when on is set.
func optionalSecret(on bool) (string, error) {
	if !on {
		return "", nil
	}
	return readSecretLine()
}

// secretUpdate is an update that changes settings, the password or both.
type secretUpdate struct {
	kind          string
	passwordStdin bool
	settings      func(context.Context, *kasapi.Client, string) error
	password      func(context.Context, *kasapi.Client, string, string) error
}

// run reads the password before the first request, then sends the settings
// when a flag other than --password-stdin was given, then the password.
func (su secretUpdate) run(g *globals, cmd *cobra.Command, id string) error {
	if err := noChange(cmd); err != nil {
		return err
	}
	password, err := optionalSecret(su.passwordStdin)
	if err != nil {
		return err
	}
	client, ctx, cancel, err := newClient(g)
	if err != nil {
		return err
	}
	defer cancel()
	err = runSteps([]updateStep{
		{settingsChanged(cmd, "password-stdin"), func() error { return su.settings(ctx, client, id) }},
		{su.passwordStdin, func() error { return su.password(ctx, client, id, password) }},
	})
	if err != nil {
		return err
	}
	fmt.Printf("%s/%s updated\n", su.kind, id)
	return nil
}

func updateFTPUserCmd(g *globals) *cobra.Command {
	var ff ftpFlags
	cmd := resourceCmd("ftpusers", "change an FTP user", true)
	cmd.RunE = func(cmd *cobra.Command, args []string) error {
		return secretUpdate{
			kind:          "ftpuser",
			passwordStdin: ff.passwordStdin,
			settings: func(ctx context.Context, c *kasapi.Client, id string) error {
				u, err := c.FTP.Get(ctx, id)
				if err != nil {
					return err
				}
				ff.apply(cmd, u)
				return c.FTP.Update(ctx, *u)
			},
			password: func(ctx context.Context, c *kasapi.Client, id, pw string) error {
				return c.FTP.UpdatePassword(ctx, id, pw)
			},
		}.run(g, cmd, args[0])
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
		return secretUpdate{
			kind:          "database",
			passwordStdin: passwordStdin,
			settings: func(ctx context.Context, c *kasapi.Client, id string) error {
				db, err := c.Databases.Get(ctx, id)
				if err != nil {
					return err
				}
				fl := cmd.Flags()
				setIfChanged(fl, "comment", &db.Comment, comment)
				setIfChanged(fl, "allowed-host", &db.AllowedHosts, nonEmpty(hosts))
				return c.Databases.Update(ctx, *db)
			},
			password: func(ctx context.Context, c *kasapi.Client, id, pw string) error {
				return c.Databases.UpdatePassword(ctx, id, pw)
			},
		}.run(g, cmd, args[0])
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
		return secretUpdate{
			kind:          "ddnsuser",
			passwordStdin: passwordStdin,
			settings: func(ctx context.Context, c *kasapi.Client, id string) error {
				u, err := c.DDNS.Get(ctx, id)
				if err != nil {
					return err
				}
				fl := cmd.Flags()
				setIfChanged(fl, "comment", &u.Comment, comment)
				setIfChanged(fl, "dual-stack", &u.DualStack, dualStack)
				return c.DDNS.Update(ctx, *u)
			},
			password: func(ctx context.Context, c *kasapi.Client, id, pw string) error {
				return c.DDNS.UpdatePassword(ctx, id, pw)
			},
		}.run(g, cmd, args[0])
	}
	f := cmd.Flags()
	f.StringVar(&comment, "comment", "", "free text describing the user")
	f.BoolVar(&dualStack, "dual-stack", false, "let the host carry an A and an AAAA record")
	f.BoolVar(&passwordStdin, "password-stdin", false, "read the new DDNS password from stdin")
	return cmd
}
