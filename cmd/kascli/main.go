// Copyright 2026 The kasapi Authors
// SPDX-License-Identifier: Apache-2.0

// Command kascli is a kubectl-style CLI for the all-inkl.com KAS API: accounts
// as contexts in a kubeconfig-like file, kubectl verbs (get/create/update/
// delete) with table/json/yaml/name output, and "exec" for any raw KAS action.
// See the README or `kascli --help` for usage. Credentials resolve like
// kubectl (--context > current-context); KAS_LOGIN/KAS_PASSWORD override the
// context.
package main

import (
	"bufio"
	"context"
	"errors"
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
	otp       string
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
	root.SetArgs(legacyExecRewrite(args))
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
~/.config/kasapi/config (override with $KASCONFIG). Resources are read,
created, updated and deleted with kubectl verbs and output formats; any raw
KAS action can be run through "exec" (also the way to verify field names
against a real account).

Environment:
  KASCONFIG                config file (default ~/.config/kasapi/config)
  KAS_LOGIN, KAS_PASSWORD  override the context's credentials
  KAS_OTP                  one-time PIN for accounts with two-factor authentication`,
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
	pf.StringVar(&g.otp, "otp", "", "one-time PIN for accounts with two-factor authentication")

	root.AddCommand(
		newGetCmd(g),
		newCreateCmd(g),
		newUpdateCmd(g),
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
func legacyExecRewrite(args []string) []string {
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
	valueFlags := map[string]bool{"--context": true, "--output": true, "-o": true, "--timeout": true, "--otp": true}
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

// credentials are the login data of one kascli run.
type credentials struct {
	login, password, authType string
	twoFactor                 bool
}

// currentContext returns the selected context, or nil when none is set.
func currentContext(g *globals) (*kasconfig.Context, error) {
	cfg, err := kasconfig.Load(kasconfig.Path())
	if err != nil {
		return nil, err
	}
	name := g.context
	if name == "" {
		name = cfg.CurrentContext
	}
	if name == "" {
		return nil, nil
	}
	return cfg.Get(name)
}

// resolveCredentials takes the context's credentials, overridden by the
// KAS_* environment variables, and prompts for a missing password.
func resolveCredentials(g *globals) (credentials, error) {
	ktx, err := currentContext(g)
	if err != nil {
		return credentials{}, err
	}
	var c credentials
	if ktx != nil {
		c = credentials{login: ktx.Login, password: ktx.Password, authType: ktx.AuthType, twoFactor: ktx.TwoFactor}
	}
	envOverride(&c.login, "KAS_LOGIN")
	envOverride(&c.password, "KAS_PASSWORD")
	envOverride(&c.authType, "KAS_AUTH_TYPE")
	if c.authType == "" {
		c.authType = "sha1"
	}
	if c.login == "" {
		return c, errors.New("no credentials: set a context (kascli config set-context NAME --login ...) or KAS_LOGIN/KAS_PASSWORD")
	}
	if c.password == "" {
		if c.password, err = promptSecret("Password for " + c.login); err != nil {
			return c, err
		}
	}
	return c, nil
}

// envOverride replaces *dst with the variable's value when it is set.
func envOverride(dst *string, name string) {
	if v := os.Getenv(name); v != "" {
		*dst = v
	}
}

func newClient(g *globals) (*kasapi.Client, context.Context, context.CancelFunc, error) {
	creds, err := resolveCredentials(g)
	if err != nil {
		return nil, nil, nil, err
	}

	otp := g.otp
	if otp == "" {
		otp = os.Getenv("KAS_OTP")
	}

	client, err := kasapi.New(kasapi.Config{
		Login:        creds.login,
		Password:     creds.password,
		AuthType:     kasapi.AuthType(creds.authType),
		OTP:          otpSource(creds.login, otp, creds.twoFactor),
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

// otpSource returns the one-time PIN callback. A given PIN serves one login.
func otpSource(login, pin string, twoFactor bool) func(context.Context) (string, error) {
	if pin == "" && !twoFactor {
		return nil
	}
	return func(context.Context) (string, error) {
		if pin != "" {
			once := pin
			pin = ""
			return once, nil
		}
		return promptSecret("One-time PIN for " + login)
	}
}

// stdin is shared so consecutive reads do not lose buffered input.
var stdin = bufio.NewReader(os.Stdin)

// promptSecret reads a secret from the terminal with echo disabled. When
// stdin is not a terminal (a pipe or redirect) it falls back to reading a
// plain line, so scripted input still works.
func promptSecret(label string) (string, error) {
	fmt.Fprintf(os.Stderr, "%s: ", label)

	fd := int(os.Stdin.Fd())
	if term.IsTerminal(fd) {
		b, err := term.ReadPassword(fd)
		fmt.Fprintln(os.Stderr)
		if err != nil {
			return "", fmt.Errorf("reading input: %w", err)
		}
		if len(b) == 0 {
			return "", fmt.Errorf("empty input")
		}
		return string(b), nil
	}
	return readSecretLine()
}

// readSecretLine reads one line from stdin and strips the line ending.
func readSecretLine() (string, error) {
	line, err := stdin.ReadString('\n')
	secret := strings.TrimRight(line, "\r\n")
	if err != nil && secret == "" {
		return "", fmt.Errorf("reading input: %w", err)
	}
	if secret == "" {
		return "", fmt.Errorf("empty input")
	}
	return secret, nil
}
