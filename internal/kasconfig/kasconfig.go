// Copyright 2026 The kasapi Authors
// SPDX-License-Identifier: Apache-2.0

// Package kasconfig implements the kubectl-style configuration file for
// kascli: named contexts (one per KAS account) and a current-context, stored
// as YAML at ~/.config/kasapi/config (override with $KASCONFIG).
package kasconfig

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"

	"gopkg.in/yaml.v3"
)

// Context is one KAS account entry.
type Context struct {
	Name     string
	Login    string
	AuthType string // "sha1" (default) or "plain"
	Password string // optional; prefer KAS_PASSWORD or interactive prompt
	// TwoFactor makes kascli ask for the one-time PIN on login.
	TwoFactor bool
}

// Config is the on-disk configuration.
type Config struct {
	CurrentContext string
	Contexts       []Context

	// perm is the mode of the file Load read, for LoosePermissions.
	perm os.FileMode
}

// Path returns the config file location: $KASCONFIG if set, else
// ~/.config/kasapi/config. Without a home directory there is no default: a
// credentials file must not land in the working directory by accident.
func Path() (string, error) {
	if p := os.Getenv("KASCONFIG"); p != "" {
		return p, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("locating the config file: %w (set KASCONFIG)", err)
	}
	return filepath.Join(home, ".config", "kasapi", "config"), nil
}

// file is the on-disk YAML shape (kubeconfig-style). It is decoupled from the
// in-memory Config so the file format can carry apiVersion/kind without the
// rest of the program caring.
type file struct {
	APIVersion     string      `yaml:"apiVersion"`
	Kind           string      `yaml:"kind"`
	CurrentContext string      `yaml:"current-context"`
	Contexts       []fileEntry `yaml:"contexts"`
}

type fileEntry struct {
	Name      string `yaml:"name"`
	Login     string `yaml:"login"`
	AuthType  string `yaml:"auth-type,omitempty"`
	Password  string `yaml:"password,omitempty"`
	TwoFactor bool   `yaml:"two-factor,omitempty"`
}

// Load reads the config file. A missing file yields an empty config, not an
// error (same behavior as kubectl with no kubeconfig).
func Load(path string) (*Config, error) {
	// G304: path is the caller's own config file location ($KASCONFIG or
	// ~/.config/kasapi/config), not attacker-controlled input.
	data, err := os.ReadFile(path) //nolint:gosec

	if os.IsNotExist(err) {
		return &Config{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}

	var f file
	if err := yaml.Unmarshal(data, &f); err != nil {
		return nil, fmt.Errorf("parsing %s: %w", path, err)
	}

	cfg := &Config{CurrentContext: f.CurrentContext}
	if info, err := os.Stat(path); err == nil {
		cfg.perm = info.Mode().Perm()
	}
	for _, e := range f.Contexts {
		cfg.Contexts = append(cfg.Contexts, Context(e))
	}
	sort.Slice(cfg.Contexts, func(i, j int) bool { return cfg.Contexts[i].Name < cfg.Contexts[j].Name })
	return cfg, nil
}

// LoosePermissions reports whether the file Load read stores a password and
// other users may read it. Windows has no such mode bits, so it never warns.
func (c *Config) LoosePermissions() bool {
	if runtime.GOOS == "windows" || c.perm&0o077 == 0 {
		return false
	}
	for _, ctx := range c.Contexts {
		if ctx.Password != "" {
			return true
		}
	}
	return false
}

// Save writes the config with 0600 permissions (it may contain passwords),
// creating parent directories as needed. The file is written next to its
// final place and renamed over it, so a crash leaves the old config intact
// and a file that was loosened by hand gets its mode back. Contexts are
// already kept sorted by name, so the output is stable across saves.
func (c *Config) Save(path string) error {
	f := file{
		APIVersion:     "v1",
		Kind:           "Config",
		CurrentContext: c.CurrentContext,
	}
	for _, ctx := range c.Contexts {
		f.Contexts = append(f.Contexts, fileEntry(ctx))
	}
	data, err := yaml.Marshal(f)
	if err != nil {
		return fmt.Errorf("encoding config: %w", err)
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("creating config directory: %w", err)
	}
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".*")
	if err != nil {
		return fmt.Errorf("writing config: %w", err)
	}
	defer func() { _ = os.Remove(tmp.Name()) }()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("writing config: %w", err)
	}
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("writing config: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("writing config: %w", err)
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		return fmt.Errorf("writing config: %w", err)
	}
	return nil
}

// tree converts the config to the generic structure; redact replaces
// passwords with "REDACTED" (kubectl-view style).
func (c *Config) tree(redact bool) map[string]any {
	items := make([]any, 0, len(c.Contexts))
	for _, ctx := range c.Contexts {
		m := map[string]any{"name": ctx.Name, "login": ctx.Login}
		if ctx.AuthType != "" {
			m["auth-type"] = ctx.AuthType
		}
		if ctx.TwoFactor {
			m["two-factor"] = true
		}
		if ctx.Password != "" {
			if redact {
				m["password"] = "REDACTED"
			} else {
				m["password"] = ctx.Password
			}
		}
		items = append(items, m)
	}
	return map[string]any{
		"apiVersion":      "v1",
		"kind":            "Config",
		"current-context": c.CurrentContext,
		"contexts":        items,
	}
}

// View returns the config as a generic tree for -o yaml/json rendering,
// redacting passwords unless raw is set.
func (c *Config) View(raw bool) map[string]any { return c.tree(!raw) }

// Get returns the named context, or an error listing available names.
func (c *Config) Get(name string) (*Context, error) {
	for i := range c.Contexts {
		if c.Contexts[i].Name == name {
			return &c.Contexts[i], nil
		}
	}
	return nil, fmt.Errorf("context %q not found (available: %s)", name, c.names())
}

// Set adds or replaces a context by name.
func (c *Config) Set(ctx Context) {
	for i := range c.Contexts {
		if c.Contexts[i].Name == ctx.Name {
			c.Contexts[i] = ctx
			return
		}
	}
	c.Contexts = append(c.Contexts, ctx)
	sort.Slice(c.Contexts, func(i, j int) bool { return c.Contexts[i].Name < c.Contexts[j].Name })
}

// Delete removes a context; deleting the current context clears it.
func (c *Config) Delete(name string) error {
	for i := range c.Contexts {
		if c.Contexts[i].Name == name {
			c.Contexts = append(c.Contexts[:i], c.Contexts[i+1:]...)
			if c.CurrentContext == name {
				c.CurrentContext = ""
			}
			return nil
		}
	}
	return fmt.Errorf("context %q not found (available: %s)", name, c.names())
}

func (c *Config) names() string {
	if len(c.Contexts) == 0 {
		return "none"
	}
	s := ""
	for i, ctx := range c.Contexts {
		if i > 0 {
			s += ", "
		}
		s += ctx.Name
	}
	return s
}
