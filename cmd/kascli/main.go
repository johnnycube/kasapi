// Copyright 2026 The kasapi Authors
// SPDX-License-Identifier: Apache-2.0

// Command kascli is a kubectl-style CLI for the all-inkl.com KAS API: accounts
// as contexts in a kubeconfig-like file, kubectl verbs (get/delete) with
// table/json/yaml/name output, and "exec" for any raw KAS action. See the
// README or `kascli --help` for usage. Credentials resolve like kubectl
// (--context > current-context); KAS_LOGIN/KAS_PASSWORD override the context.
package main

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	kasapi "github.com/johnnycube/kasapi"
	"github.com/johnnycube/kasapi/internal/kasconfig"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

// version is set at release time via -ldflags "-X main.version=...".
var version = "dev"

type globals struct {
	context   string
	output    string
	noHeaders bool
	timeout   time.Duration
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

// run is the testable entry point: it builds the command tree and executes it
// against args. cli_test.go drives this directly.
func run(args []string) error {
	root := newRootCmd()
	root.SetArgs(legacyExecRewrite(root, args))
	return root.Execute()
}

// newRootCmd builds the kascli command tree. A fresh tree is created per call
// so flag state never leaks between invocations (important for tests).
func newRootCmd() *cobra.Command {
	g := &globals{}
	root := &cobra.Command{
		Use:   "kascli",
		Short: "kubectl-style CLI for the all-inkl.com KAS API (unofficial)",
		Long: `kascli - kubectl-style CLI for the all-inkl.com KAS API (unofficial)

Accounts are managed as contexts in a kubeconfig-like file at
~/.config/kasapi/config (override with $KASCONFIG). Resources are read and
deleted with kubectl verbs and output formats; any raw KAS action can be run
through "exec" (also the way to verify field names against a real account).

Environment:
  KASCONFIG                config file (default ~/.config/kasapi/config)
  KAS_LOGIN, KAS_PASSWORD  override the context's credentials`,
		SilenceUsage:  true,
		SilenceErrors: true,
		// A bare "kascli" is an error (kubectl-style: a verb is required).
		// Reached only when no subcommand matched.
		RunE: func(_ *cobra.Command, _ []string) error {
			return fmt.Errorf("no command given")
		},
	}

	// Global flags apply to every subcommand and may appear before or after
	// the verb (cobra parses interspersed flags by default).
	pf := root.PersistentFlags()
	pf.StringVar(&g.context, "context", "", "name of the kasconfig context to use")
	pf.StringVarP(&g.output, "output", "o", "", "output format: table|wide|json|yaml|name")
	pf.BoolVar(&g.noHeaders, "no-headers", false, "omit table headers")
	pf.DurationVar(&g.timeout, "timeout", 90*time.Second, "overall request timeout")

	root.AddCommand(
		newGetCmd(g),
		newDeleteCmd(g),
		newExecCmd(g),
		newConfigCmd(g),
		newAPIResourcesCmd(g),
		newVersionCmd(),
	)
	// cobra contributes a "completion" command (bash/zsh/fish/powershell) and
	// the "help" command automatically.
	return root
}

// legacyExecRewrite preserves the convenience shorthand where a bare KAS action
// name (which always contains an underscore) routes to "exec": "kascli
// get_ftpusers" becomes "kascli exec get_ftpusers". No real command contains an
// underscore, so the check is unambiguous.
func legacyExecRewrite(root *cobra.Command, args []string) []string {
	tok, idx := firstPositional(args)
	if idx < 0 || !strings.Contains(tok, "_") {
		return args
	}
	out := make([]string, 0, len(args)+1)
	out = append(out, args[:idx]...)
	out = append(out, "exec")
	out = append(out, args[idx:]...)
	return out
}

// firstPositional returns the first non-flag argument and its index, skipping
// global flags and their separate-form values.
func firstPositional(args []string) (string, int) {
	valueFlags := map[string]bool{"--context": true, "--output": true, "-o": true, "--timeout": true}
	for i := 0; i < len(args); i++ {
		a := args[i]
		if strings.HasPrefix(a, "-") {
			if valueFlags[a] {
				i++ // also skip the value in "--flag value" form
			}
			continue
		}
		return a, i
	}
	return "", -1
}

func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "print the kascli version",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			fmt.Fprintf(cmd.OutOrStdout(), "kascli version %s\n", version)
			return nil
		},
	}
}

func newClient(g *globals) (*kasapi.Client, context.Context, context.CancelFunc, error) {
	cfg, err := kasconfig.Load(kasconfig.Path())
	if err != nil {
		return nil, nil, nil, err
	}

	var ktx *kasconfig.Context
	name := g.context
	if name == "" {
		name = cfg.CurrentContext
	}
	if name != "" {
		ktx, err = cfg.Get(name)
		if err != nil {
			return nil, nil, nil, err
		}
	}

	login, password, authType := "", "", ""
	if ktx != nil {
		login, password, authType = ktx.Login, ktx.Password, ktx.AuthType
	}
	if v := os.Getenv("KAS_LOGIN"); v != "" {
		login = v
	}
	if v := os.Getenv("KAS_PASSWORD"); v != "" {
		password = v
	}
	if v := os.Getenv("KAS_AUTH_TYPE"); v != "" {
		authType = v
	}
	if authType == "" {
		authType = "sha1"
	}
	if login == "" {
		return nil, nil, nil, fmt.Errorf("no credentials: set a context (kascli config set-context NAME --login ...) or KAS_LOGIN/KAS_PASSWORD")
	}
	if password == "" {
		password, err = promptPassword(login)
		if err != nil {
			return nil, nil, nil, err
		}
	}

	client, err := kasapi.New(kasapi.Config{
		Login:        login,
		Password:     password,
		AuthType:     kasapi.AuthType(authType),
		UserAgent:    "kascli",
		APIEndpoint:  os.Getenv("KAS_API_ENDPOINT"),
		AuthEndpoint: os.Getenv("KAS_AUTH_ENDPOINT"),
	})
	if err != nil {
		return nil, nil, nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), g.timeout)
	return client, ctx, cancel, nil
}

// promptPassword reads a password from the terminal with echo disabled. When
// stdin is not a terminal (a pipe or redirect) it falls back to reading a
// plain line, so scripted input still works.
func promptPassword(login string) (string, error) {
	fmt.Fprintf(os.Stderr, "Password for %s: ", login)

	fd := int(os.Stdin.Fd())
	var (
		pw  string
		err error
	)
	if term.IsTerminal(fd) {
		var b []byte
		b, err = term.ReadPassword(fd)
		fmt.Fprintln(os.Stderr)
		pw = string(b)
	} else {
		var line string
		line, err = bufio.NewReader(os.Stdin).ReadString('\n')
		pw = strings.TrimRight(line, "\r\n")
	}
	if err != nil {
		return "", fmt.Errorf("reading password: %w", err)
	}
	if pw == "" {
		return "", fmt.Errorf("empty password")
	}
	return pw, nil
}
