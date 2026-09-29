// Copyright 2026 The kasapi Authors
// SPDX-License-Identifier: Apache-2.0

package kasconfig

import (
	"os"
	"path/filepath"
	"reflect"
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

func TestConfig_TwoFactorRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config")
	cfg := &Config{}
	cfg.Set(Context{Name: "secure", Login: "w1", TwoFactor: true})
	cfg.Set(Context{Name: "plain", Login: "w2"})
	if err := cfg.Save(path); err != nil {
		t.Fatalf("Save: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(string(data), "two-factor") != 1 || !strings.Contains(string(data), "two-factor: true") {
		t.Fatalf("file:\n%s", data)
	}

	loaded, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	secure, _ := loaded.Get("secure")
	plain, _ := loaded.Get("plain")
	if !secure.TwoFactor || plain.TwoFactor {
		t.Fatalf("two-factor lost: %+v %+v", secure, plain)
	}

	view := loaded.View(false)
	var seen []any
	for _, c := range view["contexts"].([]any) {
		seen = append(seen, c.(map[string]any)["two-factor"])
	}
	if !reflect.DeepEqual(seen, []any{nil, true}) {
		t.Fatalf("view: %#v", view["contexts"])
	}
}

func TestConfig_LoadsFilesWithoutTwoFactor(t *testing.T) {
	// A file written before the flag existed.
	path := filepath.Join(t.TempDir(), "config")
	old := "apiVersion: v1\nkind: Config\ncurrent-context: prod\ncontexts:\n  - name: prod\n    login: w0123456\n"
	if err := os.WriteFile(path, []byte(old), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	prod, err := cfg.Get("prod")
	if err != nil || prod.TwoFactor || prod.Login != "w0123456" {
		t.Fatalf("context: %+v %v", prod, err)
	}
}
