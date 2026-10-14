// Copyright 2026 The kasapi Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/johnnycube/kasapi/internal/kasconfig"
	"github.com/spf13/cobra"
)

func newConfigCmd(g *globals) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "config <subcommand>",
		Short: "manage contexts (get-contexts, current-context, use-context, set-context, delete-context, view)",
		// A bare "config" or an unknown subcommand is an error; the real work
		// lives in the subcommands below.
		RunE: func(_ *cobra.Command, args []string) error {
			if len(args) == 0 {
				return fmt.Errorf("usage: kascli config <get-contexts|current-context|use-context|set-context|delete-context|view>")
			}
			return fmt.Errorf("unknown config subcommand %q", args[0])
		},
	}
	cmd.AddCommand(
		newConfigGetContextsCmd(g),
		newConfigCurrentContextCmd(),
		newConfigUseContextCmd(),
		newConfigSetContextCmd(g),
		newConfigDeleteContextCmd(),
		newConfigViewCmd(g),
	)
	return cmd
}

func newConfigGetContextsCmd(g *globals) *cobra.Command {
	return &cobra.Command{
		Use:   "get-contexts",
		Short: "list contexts",
		Args:  cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			cfg, err := kasconfig.Load(kasconfig.Path())
			if err != nil {
				return err
			}
			p, err := newPrinter(g.output, g.noHeaders)
			if err != nil {
				return err
			}
			rows := make([]row, 0, len(cfg.Contexts))
			for _, c := range cfg.Contexts {
				current := " "
				if c.Name == cfg.CurrentContext {
					current = "*"
				}
				authType := c.AuthType
				if authType == "" {
					authType = "sha1"
				}
				rows = append(rows, row{
					name:      "context/" + c.Name,
					cells:     []string{current, c.Name, c.Login, authType},
					wideCells: []string{boolWord(c.TwoFactor)},
					object: map[string]any{
						"name": c.Name, "login": c.Login, "authType": authType,
						"current":   c.Name == cfg.CurrentContext,
						"twoFactor": c.TwoFactor,
					},
				})
			}
			return p.printList([]string{"CURRENT", "NAME", "LOGIN", "AUTH-TYPE"}, []string{"TWO-FACTOR"}, rows)
		},
	}
}

func newConfigCurrentContextCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "current-context",
		Short: "show the current context",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, err := kasconfig.Load(kasconfig.Path())
			if err != nil {
				return err
			}
			if cfg.CurrentContext == "" {
				return fmt.Errorf("current-context is not set")
			}
			fmt.Fprintln(cmd.OutOrStdout(), cfg.CurrentContext)
			return nil
		},
	}
}

func newConfigUseContextCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "use-context NAME",
		Short: "set the current context",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			path := kasconfig.Path()
			cfg, err := kasconfig.Load(path)
			if err != nil {
				return err
			}
			if _, err := cfg.Get(args[0]); err != nil {
				return err
			}
			cfg.CurrentContext = args[0]
			if err := cfg.Save(path); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "Switched to context %q.\n", args[0])
			return nil
		},
	}
}

// setContextFlags are the flags of "config set-context".
type setContextFlags struct {
	login, authType, password            string
	passwordStdin, setCurrent, twoFactor bool
}

// apply sets the given flags on ctx.
func (sf *setContextFlags) apply(cmd *cobra.Command, ctx *kasconfig.Context) error {
	if sf.login != "" {
		ctx.Login = sf.login
	}
	if sf.authType != "" {
		if sf.authType != "sha1" && sf.authType != "plain" {
			return errors.New("--auth-type must be sha1 or plain")
		}
		ctx.AuthType = sf.authType
	}
	pw, set, err := sf.newPassword()
	if err != nil {
		return err
	}
	if set {
		ctx.Password = pw
	}
	if cmd.Flags().Changed("two-factor") {
		ctx.TwoFactor = sf.twoFactor
	}
	if ctx.Login == "" {
		return errors.New("--login is required for a new context")
	}
	return nil
}

// newPassword returns the password to store and whether one was given.
func (sf *setContextFlags) newPassword() (string, bool, error) {
	switch {
	case sf.password != "" && sf.passwordStdin:
		return "", false, errors.New("--password and --password-stdin are mutually exclusive")
	case sf.password != "":
		return sf.password, true, nil
	case !sf.passwordStdin:
		return "", false, nil
	}
	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil && line == "" {
		return "", false, fmt.Errorf("reading password from stdin: %w", err)
	}
	return strings.TrimRight(line, "\r\n"), true, nil
}

func newConfigSetContextCmd(_ *globals) *cobra.Command {
	var sf setContextFlags
	cmd := &cobra.Command{
		Use:   "set-context NAME",
		Short: "create or update a context",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			path := kasconfig.Path()
			cfg, err := kasconfig.Load(path)
			if err != nil {
				return err
			}
			name := args[0]

			// Start from the existing context, if any, so set-context can
			// update single fields (kubectl behavior).
			ctx := kasconfig.Context{Name: name}
			if existing, err := cfg.Get(name); err == nil {
				ctx = *existing
			}
			if err := sf.apply(cmd, &ctx); err != nil {
				return err
			}
			cfg.Set(ctx)
			if sf.setCurrent || cfg.CurrentContext == "" {
				cfg.CurrentContext = name
			}
			if err := cfg.Save(path); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "Context %q modified in %s.\n", name, path)
			if ctx.Password != "" {
				fmt.Fprintln(os.Stderr, "warning: password stored in plaintext (file mode 0600); KAS_PASSWORD or the interactive prompt avoid this")
			}
			return nil
		},
	}
	f := cmd.Flags()
	f.StringVar(&sf.login, "login", "", "KAS login, e.g. w0123456")
	f.StringVar(&sf.authType, "auth-type", "", "sha1 (default) or plain")
	f.StringVar(&sf.password, "password", "", "store the password in the config file (visible in shell history; prefer --password-stdin or KAS_PASSWORD)")
	f.BoolVar(&sf.passwordStdin, "password-stdin", false, "read the password to store from stdin")
	f.BoolVar(&sf.setCurrent, "current", false, "also switch current-context to this context")
	f.BoolVar(&sf.twoFactor, "two-factor", false, "the account uses two-factor authentication; ask for the one-time PIN on login")
	return cmd
}

func newConfigDeleteContextCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "delete-context NAME",
		Short: "remove a context",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			path := kasconfig.Path()
			cfg, err := kasconfig.Load(path)
			if err != nil {
				return err
			}
			if err := cfg.Delete(args[0]); err != nil {
				return err
			}
			if err := cfg.Save(path); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "deleted context %q from %s\n", args[0], path)
			return nil
		},
	}
}

func newConfigViewCmd(g *globals) *cobra.Command {
	var raw bool
	cmd := &cobra.Command{
		Use:   "view",
		Short: "show the merged config (passwords redacted)",
		Args:  cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			cfg, err := kasconfig.Load(kasconfig.Path())
			if err != nil {
				return err
			}
			format := g.output
			if format == "" || format == "table" {
				format = "yaml" // kubectl config view defaults to YAML
			}
			p, err := newPrinter(format, g.noHeaders)
			if err != nil {
				return err
			}
			return p.printObject(cfg.View(raw))
		},
	}
	cmd.Flags().BoolVar(&raw, "raw", false, "include passwords instead of REDACTED")
	return cmd
}
