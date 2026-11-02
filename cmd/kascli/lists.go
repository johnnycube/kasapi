// Copyright 2026 The kasapi Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"

	kasapi "github.com/johnnycube/kasapi"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

// Mailing lists, directory protection and network drive users.

func mailingListRow(l kasapi.MailingList, detailed bool) row {
	obj := map[string]any{
		"name": l.Name, "domain": l.Domain, "active": l.Active, "inProgress": l.InProgress,
	}
	subscribers := ""
	if detailed {
		obj["subscribers"] = anySlice(l.Subscribers)
		obj["restrictPost"] = anySlice(l.RestrictPost)
		obj["config"] = l.Config
		subscribers = strconv.Itoa(len(l.Subscribers))
	}
	return row{
		name:      "mailinglist/" + l.Name,
		cells:     []string{l.Name, l.Domain, boolWord(l.Active)},
		wideCells: []string{subscribers},
		object:    obj,
	}
}

// getMailingLists lists the lists, or shows one with its subscribers.
func getMailingLists(r getRequest) (listing, error) {
	headers, wide := []string{"NAME", "DOMAIN", "ACTIVE"}, []string{"SUBSCRIBERS"}
	if len(r.args) > 1 {
		l, err := r.client.MailingLists.Get(r.ctx, r.args[1])
		if err != nil {
			return listing{}, err
		}
		return listing{headers: headers, wideHeaders: wide, rows: []row{mailingListRow(*l, true)}}, nil
	}
	lists, err := r.client.MailingLists.List(r.ctx)
	return listOf(lists, err, headers, wide, func(l kasapi.MailingList) row {
		return mailingListRow(l, false)
	})
}

// directoryID renders the kascli identifier of a directory protection, path:user.
func directoryID(path, user string) string {
	return path + ":" + user
}

// splitDirectoryID splits path:user at the last colon; htpasswd users have none.
func splitDirectoryID(id string) (path, user string, err error) {
	i := strings.LastIndex(id, ":")
	if i <= 0 || i == len(id)-1 {
		return "", "", fmt.Errorf("invalid directory protection %q, expected <path>:<user>", id)
	}
	return id[:i], id[i+1:], nil
}

func getDirectoryProtections(r getRequest) (listing, error) {
	all, err := r.client.DirectoryProtection.List(r.ctx)
	return listOf(all, err, []string{"PATH", "USER", "AUTH-NAME"}, nil, func(p kasapi.DirectoryProtection) row {
		return row{
			name:  "directoryprotection/" + directoryID(p.Path, p.User),
			cells: []string{p.Path, p.User, p.AuthName},
			object: map[string]any{
				"path": p.Path, "user": p.User, "authName": p.AuthName, "inProgress": p.InProgress,
			},
		}
	})
}

func getSambaUsers(r getRequest) (listing, error) {
	users, err := r.client.Samba.List(r.ctx)
	return listOf(users, err, []string{"LOGIN", "PATH", "COMMENT"}, nil, func(u kasapi.SambaUser) row {
		return row{
			name:  "sambauser/" + u.Login,
			cells: []string{u.Login, u.Path, u.Comment},
			object: map[string]any{
				"login": u.Login, "path": u.Path, "comment": u.Comment, "inProgress": u.InProgress,
			},
		}
	})
}

func createMailingListCmd(g *globals) *cobra.Command {
	var (
		address       string
		passwordStdin bool
	)
	cmd := resourceCmd("mailinglists", "create a mailing list", false)
	cmd.RunE = func(_ *cobra.Command, _ []string) error {
		label, domain, err := splitAddress(address)
		if err != nil {
			return fmt.Errorf("--address: %w", err)
		}
		password, err := newSecret(passwordStdin, "Password for the mailing list "+address)
		if err != nil {
			return err
		}
		client, ctx, cancel, err := newClient(g)
		if err != nil {
			return err
		}
		defer cancel()
		name, err := client.MailingLists.Create(ctx, label, domain, password)
		if err != nil {
			return err
		}
		fmt.Printf("mailinglist/%s created\n", name)
		return nil
	}
	f := cmd.Flags()
	f.StringVar(&address, "address", "", "address of the list, label@domain")
	f.BoolVar(&passwordStdin, "password-stdin", false, "read the list password from stdin instead of asking for it")
	return cmd
}

// mailingListFlags are the flags of "update mailinglist".
type mailingListFlags struct {
	subscribers, restrictPost []string
	configFile                string
	active                    bool
}

func (mf *mailingListFlags) register(f *pflag.FlagSet) {
	f.StringSliceVar(&mf.subscribers, "subscriber", nil, `subscriber address (repeatable); replaces the list, --subscriber "" removes all`)
	f.StringSliceVar(&mf.restrictPost, "restrict-post", nil, `address allowed to post (repeatable); --restrict-post "" lifts the restriction`)
	f.StringVar(&mf.configFile, "config", "", "file with the complete Majordomo configuration")
	f.BoolVar(&mf.active, "active", true, "accept mail for the list")
}

// update returns the flags that were given.
func (mf *mailingListFlags) update(fl *pflag.FlagSet) (kasapi.MailingListUpdate, error) {
	var u kasapi.MailingListUpdate
	if fl.Changed("subscriber") {
		u.Subscribers = new(nonEmpty(mf.subscribers))
	}
	if fl.Changed("restrict-post") {
		u.RestrictPost = new(nonEmpty(mf.restrictPost))
	}
	if fl.Changed("active") {
		u.Active = &mf.active
	}
	if fl.Changed("config") {
		config, err := readFlagFile("config", mf.configFile)
		if err != nil {
			return u, err
		}
		u.Config = &config
	}
	return u, nil
}

func updateMailingListCmd(g *globals) *cobra.Command {
	var mf mailingListFlags
	cmd := resourceCmd("mailinglists", "change a mailing list", true)
	cmd.RunE = func(cmd *cobra.Command, args []string) error {
		if err := noChange(cmd); err != nil {
			return err
		}
		u, err := mf.update(cmd.Flags())
		if err != nil {
			return err
		}
		client, ctx, cancel, err := newClient(g)
		if err != nil {
			return err
		}
		defer cancel()
		if err := client.MailingLists.Update(ctx, args[0], u); err != nil {
			return err
		}
		fmt.Printf("mailinglist/%s updated\n", args[0])
		return nil
	}
	mf.register(cmd.Flags())
	return cmd
}

func createDirectoryProtectionCmd(g *globals) *cobra.Command {
	var (
		p             kasapi.DirectoryProtection
		passwordStdin bool
	)
	cmd := resourceCmd("directoryprotections", "protect a directory with a login", false)
	cmd.RunE = func(_ *cobra.Command, _ []string) error {
		if p.Path == "" || p.User == "" || p.AuthName == "" {
			return errors.New("--path, --user and --auth-name are required")
		}
		password, err := newSecret(passwordStdin, "Password for "+p.User)
		if err != nil {
			return err
		}
		client, ctx, cancel, err := newClient(g)
		if err != nil {
			return err
		}
		defer cancel()
		if err := client.DirectoryProtection.Create(ctx, p, password); err != nil {
			return err
		}
		fmt.Printf("directoryprotection/%s created\n", directoryID(p.Path, p.User))
		return nil
	}
	f := cmd.Flags()
	f.StringVar(&p.Path, "path", "", "directory to protect, e.g. /example.com/admin/")
	f.StringVar(&p.User, "user", "", "login name")
	f.StringVar(&p.AuthName, "auth-name", "", "realm the login prompt shows")
	f.BoolVar(&passwordStdin, "password-stdin", false, "read the password from stdin instead of asking for it")
	return cmd
}

// updateDirectoryProtectionCmd always asks for the password: KAS documents
// it as required on update and cannot report the old one.
func updateDirectoryProtectionCmd(g *globals) *cobra.Command {
	var (
		authName      string
		passwordStdin bool
	)
	cmd := resourceCmd("directoryprotections", "change realm and password of a directory login (id: <path>:<user>)", true)
	cmd.RunE = func(cmd *cobra.Command, args []string) error {
		path, user, err := splitDirectoryID(args[0])
		if err != nil {
			return err
		}
		password, err := newSecret(passwordStdin, "Password for "+user)
		if err != nil {
			return err
		}
		client, ctx, cancel, err := newClient(g)
		if err != nil {
			return err
		}
		defer cancel()
		p, err := client.DirectoryProtection.Get(ctx, path, user)
		if err != nil {
			return err
		}
		setIfChanged(cmd.Flags(), "auth-name", &p.AuthName, authName)
		if err := client.DirectoryProtection.Update(ctx, *p, password); err != nil {
			return err
		}
		fmt.Printf("directoryprotection/%s updated\n", args[0])
		return nil
	}
	f := cmd.Flags()
	f.StringVar(&authName, "auth-name", "", "realm the login prompt shows")
	f.BoolVar(&passwordStdin, "password-stdin", false, "read the password from stdin instead of asking for it")
	return cmd
}

func createSambaUserCmd(g *globals) *cobra.Command {
	var (
		u             kasapi.SambaUser
		passwordStdin bool
	)
	cmd := resourceCmd("sambausers", "create a network drive user", false)
	cmd.RunE = func(_ *cobra.Command, _ []string) error {
		if u.Path == "" || u.Comment == "" {
			return errors.New("--path and --comment are required")
		}
		password, err := newSecret(passwordStdin, "Password for the network drive user")
		if err != nil {
			return err
		}
		client, ctx, cancel, err := newClient(g)
		if err != nil {
			return err
		}
		defer cancel()
		login, err := client.Samba.Create(ctx, u, password)
		if err != nil {
			return err
		}
		fmt.Printf("sambauser/%s created\n", login)
		return nil
	}
	f := cmd.Flags()
	f.StringVar(&u.Path, "path", "", "directory the drive exposes")
	f.StringVar(&u.Comment, "comment", "", "free text describing the user")
	f.BoolVar(&passwordStdin, "password-stdin", false, "read the password from stdin instead of asking for it")
	return cmd
}

func updateSambaUserCmd(g *globals) *cobra.Command {
	var (
		path, comment string
		passwordStdin bool
	)
	cmd := resourceCmd("sambausers", "change a network drive user", true)
	// settings reads the user, so that what no flag names keeps its value.
	settings := func(fl *pflag.FlagSet) func(context.Context, *kasapi.Client, string) error {
		return func(ctx context.Context, c *kasapi.Client, login string) error {
			u, err := c.Samba.Get(ctx, login)
			if err != nil {
				return err
			}
			setIfChanged(fl, "path", &u.Path, path)
			setIfChanged(fl, "comment", &u.Comment, comment)
			return c.Samba.Update(ctx, *u)
		}
	}
	cmd.RunE = func(cmd *cobra.Command, args []string) error {
		su := secretUpdate{kind: "sambauser", passwordStdin: passwordStdin, settings: settings(cmd.Flags()), password: updateSambaPassword}
		return su.run(g, cmd, args[0])
	}
	f := cmd.Flags()
	f.StringVar(&path, "path", "", "directory the drive exposes")
	f.StringVar(&comment, "comment", "", "free text describing the user")
	f.BoolVar(&passwordStdin, "password-stdin", false, "read the new password from stdin")
	return cmd
}

func updateSambaPassword(ctx context.Context, c *kasapi.Client, login, password string) error {
	return c.Samba.UpdatePassword(ctx, login, password)
}
