// Copyright 2026 The kasapi Authors
// SPDX-License-Identifier: Apache-2.0

package kasapi

import (
	"context"
	"time"
)

// Every KasApi response carries a KasFloodDelay (seconds) that must elapse
// before the next request, or the API answers with a "flood_protection" fault.
// The client honors it proactively. Both helpers require c.sem.

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

// applyFloodDelayLocked reads KasFloodDelay from a decoded KasApi response.
// KAS reports it inside Response, next to ReturnString; the top level is read
// as a fallback.
func (c *Client) applyFloodDelayLocked(ret any) {
	top, ok := ret.(map[string]any)
	if !ok {
		return
	}
	response, _ := top["Response"].(map[string]any)
	delay := asFloat(response["KasFloodDelay"])
	if delay <= 0 {
		delay = asFloat(top["KasFloodDelay"])
	}
	if delay <= 0 {
		delay = 2 // conservative default between writes
	}
	c.notBefore = time.Now().Add(time.Duration(delay*1000) * time.Millisecond)
}
