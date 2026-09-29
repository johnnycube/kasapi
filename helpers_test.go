// Copyright 2026 The kasapi Authors
// SPDX-License-Identifier: Apache-2.0

package kasapi

import (
	"strings"
	"sync"
	"testing"

	"github.com/johnnycube/kasapi/kasapitest"
)

// calls records the request parameters the fake server received, per action.
type calls struct {
	mu   sync.Mutex
	seen map[string][]map[string]any
}

func (c *calls) record(action string, params map[string]any) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.seen == nil {
		c.seen = map[string][]map[string]any{}
	}
	c.seen[action] = append(c.seen[action], params)
}

// last returns the parameters of the latest call of action.
func (c *calls) last(t *testing.T, action string) map[string]any {
	t.Helper()
	c.mu.Lock()
	defer c.mu.Unlock()
	all := c.seen[action]
	if len(all) == 0 {
		t.Fatalf("action %s was not called", action)
	}
	return all[len(all)-1]
}

// newFake starts a fake KAS server; an answer starting with "!" is a fault.
func newFake(t *testing.T, answers map[string]string) (*Client, *calls) {
	t.Helper()
	rec := &calls{}
	srv := kasapitest.New(t, func(action string, params map[string]any) (string, string) {
		rec.record(action, params)
		answer, ok := answers[action]
		if !ok {
			return "", "unknown_action"
		}
		if code, isFault := strings.CutPrefix(answer, "!"); isFault {
			return "", code
		}
		return answer, ""
	})
	return newTestClient(t, srv), rec
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

// wantParams fails the test unless got carries every key of want with the same value.
func wantParams(t *testing.T, got map[string]any, want map[string]string) {
	t.Helper()
	for k, v := range want {
		if asString(got[k]) != v {
			t.Errorf("parameter %s = %q, want %q (all: %v)", k, asString(got[k]), v, got)
		}
	}
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
