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

func TestConfig_ContextsAreSorted(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config")
	unsorted := "contexts:\n  - name: zeta\n    login: w3\n  - name: alpha\n    login: w1\n"
	if err := os.WriteFile(path, []byte(unsorted), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	cfg.Set(Context{Name: "mid", Login: "w2"})
	var names []string
	for _, c := range cfg.Contexts {
		names = append(names, c.Name)
	}
	if !reflect.DeepEqual(names, []string{"alpha", "mid", "zeta"}) {
		t.Fatalf("order: %v", names)
	}
	if got := cfg.names(); got != "alpha, mid, zeta" {
		t.Fatalf("names(): %q", got)
	}
	if got := (&Config{}).names(); got != "none" {
		t.Fatalf("names() of an empty config: %q", got)
	}
}

func TestConfig_LoadErrors(t *testing.T) {
	dir := t.TempDir()

	broken := filepath.Join(dir, "broken")
	if err := os.WriteFile(broken, []byte("contexts: [\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(broken); err == nil || !strings.Contains(err.Error(), "parsing") {
		t.Fatalf("broken YAML: %v", err)
	}

	// A directory in place of the file is a read error, not a missing file.
	if _, err := Load(dir); err == nil || !strings.Contains(err.Error(), "reading") {
		t.Fatalf("directory: %v", err)
	}
}

func TestConfig_SaveErrors(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "file")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := &Config{}
	cfg.Set(Context{Name: "prod", Login: "w1"})

	// The parent is a file, so the directory cannot be created.
	if err := cfg.Save(filepath.Join(file, "sub", "config")); err == nil ||
		!strings.Contains(err.Error(), "creating config directory") {
		t.Fatalf("expected a directory error, got %v", err)
	}
	// The target is a directory, so the file cannot be written.
	if err := cfg.Save(dir); err == nil {
		t.Fatal("writing over a directory must fail")
	}

	// Parent directories are created, private to the user.
	nested := filepath.Join(dir, "a", "b", "config")
	if err := cfg.Save(nested); err != nil {
		t.Fatalf("Save: %v", err)
	}
	info, err := os.Stat(filepath.Dir(nested))
	if err != nil || info.Mode().Perm() != 0o700 {
		t.Fatalf("directory mode: %v %v", info.Mode().Perm(), err)
	}
}

func TestConfig_ViewRawAndAuthType(t *testing.T) {
	cfg := &Config{CurrentContext: "prod"}
	cfg.Set(Context{Name: "prod", Login: "w1", AuthType: "plain", Password: "s3cret"})

	raw := cfg.View(true)["contexts"].([]any)[0].(map[string]any)
	if raw["password"] != "s3cret" || raw["auth-type"] != "plain" {
		t.Fatalf("raw view: %#v", raw)
	}
	redacted := cfg.View(false)
	if redacted["contexts"].([]any)[0].(map[string]any)["password"] != "REDACTED" {
		t.Fatalf("redacted view: %#v", redacted)
	}
	if redacted["apiVersion"] != "v1" || redacted["kind"] != "Config" || redacted["current-context"] != "prod" {
		t.Fatalf("view header: %#v", redacted)
	}

	// A context without password or auth type shows neither key.
	cfg = &Config{}
	cfg.Set(Context{Name: "bare", Login: "w1"})
	bare := cfg.View(true)["contexts"].([]any)[0].(map[string]any)
	if len(bare) != 2 {
		t.Fatalf("bare view: %#v", bare)
	}
}

func TestPath_WithoutHome(t *testing.T) {
	t.Setenv("KASCONFIG", "")
	t.Setenv("HOME", "")
	t.Setenv("XDG_CONFIG_HOME", "")
	if got := Path(); got != ".kasapi-config" {
		t.Skipf("the platform resolves a home directory without $HOME: %q", got)
	}
}
