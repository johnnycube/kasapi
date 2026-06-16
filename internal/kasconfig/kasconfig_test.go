// Copyright 2026 The kasapi Authors
// SPDX-License-Identifier: Apache-2.0

package kasconfig

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestConfig_SaveLoadRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config")

	cfg := &Config{CurrentContext: "prod"}
	cfg.Set(Context{Name: "prod", Login: "w0123456", Password: `p@ss "1"`})
	cfg.Set(Context{Name: "staging", Login: "w0999999", AuthType: "plain"})

	if err := cfg.Save(path); err != nil {
		t.Fatalf("Save: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("expected 0600 permissions, got %o", perm)
	}

	loaded, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if loaded.CurrentContext != "prod" || len(loaded.Contexts) != 2 {
		t.Fatalf("unexpected config: %+v", loaded)
	}
	prod, err := loaded.Get("prod")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if prod.Password != `p@ss "1"` {
		t.Fatalf("password mangled: %q", prod.Password)
	}
	staging, _ := loaded.Get("staging")
	if staging.AuthType != "plain" {
		t.Fatalf("auth-type lost: %+v", staging)
	}
}

func TestConfig_MissingFileIsEmpty(t *testing.T) {
	cfg, err := Load(filepath.Join(t.TempDir(), "nope"))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(cfg.Contexts) != 0 || cfg.CurrentContext != "" {
		t.Fatalf("expected empty config, got %+v", cfg)
	}
}

func TestConfig_DeleteAndCurrent(t *testing.T) {
	cfg := &Config{CurrentContext: "a"}
	cfg.Set(Context{Name: "a", Login: "w1"})
	cfg.Set(Context{Name: "b", Login: "w2"})

	if err := cfg.Delete("a"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if cfg.CurrentContext != "" {
		t.Fatal("deleting current context must clear current-context")
	}
	if err := cfg.Delete("missing"); err == nil {
		t.Fatal("expected error for unknown context")
	}
}

func TestConfig_ViewRedacts(t *testing.T) {
	cfg := &Config{}
	cfg.Set(Context{Name: "a", Login: "w1", Password: "secret"})

	tree := cfg.View(false)
	item := tree["contexts"].([]any)[0].(map[string]any)
	if item["password"] != "REDACTED" {
		t.Fatalf("expected redaction, got %#v", item["password"])
	}
	raw := cfg.View(true)
	item = raw["contexts"].([]any)[0].(map[string]any)
	if item["password"] != "secret" {
		t.Fatalf("raw view must keep password, got %#v", item["password"])
	}
}

func TestPath_EnvOverrideAndDefault(t *testing.T) {
	t.Setenv("KASCONFIG", "/tmp/custom-kasconfig")
	if Path() != "/tmp/custom-kasconfig" {
		t.Fatalf("KASCONFIG override ignored: %q", Path())
	}
	t.Setenv("KASCONFIG", "")
	p := Path()
	if !strings.HasSuffix(p, "kasapi/config") && p != ".kasapi-config" {
		t.Fatalf("unexpected default path: %q", p)
	}
}

func TestConfig_GetSetUnknownAndUpdate(t *testing.T) {
	cfg := &Config{}
	if _, err := cfg.Get("missing"); err == nil || !strings.Contains(err.Error(), "none") {
		t.Fatalf("Get on empty config: %v", err)
	}
	cfg.Set(Context{Name: "a", Login: "w1"})
	cfg.Set(Context{Name: "a", Login: "w1-updated"}) // replace in place
	if len(cfg.Contexts) != 1 || cfg.Contexts[0].Login != "w1-updated" {
		t.Fatalf("Set should replace, got %+v", cfg.Contexts)
	}
	if _, err := cfg.Get("b"); err == nil || !strings.Contains(err.Error(), "a") {
		t.Fatalf("error should list available contexts: %v", err)
	}
}
