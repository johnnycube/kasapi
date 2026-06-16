// Copyright 2026 The kasapi Authors
// SPDX-License-Identifier: Apache-2.0

package kasapi

import (
	"context"
	"time"
)

// Every KasApi response carries a KasFloodDelay (seconds) that must elapse
// before the next request, or the API answers with a "flood_protection" fault.
// The client honors it proactively. Both helpers require c.mu.

func (c *Client) waitForFloodWindowLocked(ctx context.Context) error {
	wait := time.Until(c.notBefore)
	if wait <= 0 {
		return nil
	}
	t := time.NewTimer(wait)
	defer t.Stop()
	select {
	case <-t.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (c *Client) applyFloodDelayLocked(top map[string]any) {
	if top == nil {
		return
	}
	delay := asFloat(top["KasFloodDelay"])
	if delay <= 0 {
		delay = 2 // conservative default between writes
	}
	c.notBefore = time.Now().Add(time.Duration(delay*1000) * time.Millisecond)
}
