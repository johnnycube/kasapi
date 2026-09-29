// Copyright 2026 The kasapi Authors
// SPDX-License-Identifier: Apache-2.0

package kasapi

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestFloodDelay(t *testing.T) {
	c, _ := New(Config{Login: "w1", Password: "p"})

	before := time.Now()
	c.applyFloodDelayLocked(map[string]any{"KasFloodDelay": "0.5"})
	if d := c.notBefore.Sub(before); d < 400*time.Millisecond || d > 700*time.Millisecond {
		t.Fatalf("delay of 0.5s applied as %v", d)
	}

	// A response without the field gets the conservative default.
	before = time.Now()
	c.applyFloodDelayLocked(map[string]any{})
	if d := c.notBefore.Sub(before); d < 1900*time.Millisecond || d > 2200*time.Millisecond {
		t.Fatalf("default delay applied as %v", d)
	}

	// A response that is not a map leaves the window untouched.
	mark := c.notBefore
	c.applyFloodDelayLocked(nil)
	if !c.notBefore.Equal(mark) {
		t.Fatal("nil response must not move the window")
	}

	c.notBefore = time.Now().Add(-time.Second)
	if err := c.waitForFloodWindowLocked(context.Background()); err != nil {
		t.Fatalf("open window: %v", err)
	}
	c.notBefore = time.Now().Add(50 * time.Millisecond)
	start := time.Now()
	if err := c.waitForFloodWindowLocked(context.Background()); err != nil || time.Since(start) < 40*time.Millisecond {
		t.Fatalf("closed window: err=%v waited=%v", err, time.Since(start))
	}
	c.notBefore = time.Now().Add(time.Hour)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := c.waitForFloodWindowLocked(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled wait: %v", err)
	}
}
