// Copyright 2026 The kasapi Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bufio"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/johnnycube/kasapi/kasapitest"
)

// recorder answers KAS actions from a table and records their parameters.
type recorder struct {
	mu   sync.Mutex
	seen map[string][]map[string]any
}

func (r *recorder) last(t *testing.T, action string) map[string]any {
	t.Helper()
	r.mu.Lock()
	defer r.mu.Unlock()
	all := r.seen[action]
	if len(all) == 0 {
		t.Fatalf("action %s was not called (called: %v)", action, r.actions())
	}
	return all[len(all)-1]
}

func (r *recorder) count(action string) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.seen[action])
}

// total returns the number of recorded calls of all actions.
func (r *recorder) total() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	n := 0
	for _, calls := range r.seen {
		n += len(calls)
	}
	return n
}

func (r *recorder) actions() []string {
	out := make([]string, 0, len(r.seen))
	for a := range r.seen {
		out = append(out, a)
	}
	return out
}

// setupFake points the CLI at a fake KAS server; an answer starting with "!" is a fault.
func setupFake(t *testing.T, answers map[string]string) *recorder {
	t.Helper()
	rec := &recorder{seen: map[string][]map[string]any{}}
	setupCLI(t, func(action string, params map[string]any) (string, string) {
		rec.mu.Lock()
		rec.seen[action] = append(rec.seen[action], params)
		rec.mu.Unlock()
		answer, ok := answers[action]
		if !ok {
			return "", "unknown_action"
		}
		if code, isFault := strings.CutPrefix(answer, "!"); isFault {
			return "", code
		}
		return answer, ""
	})
	return rec
}

// entry renders one list entry from key/value pairs.
func entry(kv ...string) string {
	var b strings.Builder
	b.WriteString("<item>")
	for i := 0; i+1 < len(kv); i += 2 {
		b.WriteString(kasapitest.MapItem(kv[i], kv[i+1]))
	}
	b.WriteString("</item>")
	return b.String()
}

// setStdin feeds input to the secret prompts of one test.
func setStdin(t *testing.T, input string) {
	t.Helper()
	old := stdin
	stdin = bufio.NewReader(strings.NewReader(input))
	t.Cleanup(func() { stdin = old })
}

// wantParams fails the test unless got carries every key of want with the same value.
func wantParams(t *testing.T, got map[string]any, want map[string]string) {
	t.Helper()
	for k, v := range want {
		if got[k] == nil || paramString(got[k]) != v {
			t.Errorf("parameter %s = %v, want %q", k, got[k], v)
		}
	}
}

// paramString renders numbers without exponent.
func paramString(v any) string {
	if f, ok := v.(float64); ok {
		return strconv.FormatFloat(f, 'f', -1, 64)
	}
	return fmt.Sprint(v)
}

// wantAbsent fails the test when got carries one of the keys.
func wantAbsent(t *testing.T, got map[string]any, keys ...string) {
	t.Helper()
	for _, k := range keys {
		if _, ok := got[k]; ok {
			t.Errorf("parameter %s must not be sent (all: %v)", k, got)
		}
	}
}

// wantErr fails the test unless the CLI returns an error containing want.
func wantErr(t *testing.T, want string, args ...string) {
	t.Helper()
	err := run(args)
	if err == nil || !strings.Contains(err.Error(), want) {
		t.Errorf("run(%v): got %v, want an error containing %q", args, err, want)
	}
}
