// Copyright 2026 The kasapi Authors
// SPDX-License-Identifier: Apache-2.0

package kasapi

import "testing"

func TestAsString(t *testing.T) {
	for _, tc := range []struct {
		in   any
		want string
	}{
		{"text", "text"},
		{float64(2), "2"},
		{1.5, "1.5"},
		{42, "42"},
		{nil, ""},
		{true, "true"},
		{[]string{"a"}, "[a]"},
	} {
		if got := asString(tc.in); got != tc.want {
			t.Errorf("asString(%#v) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestAsFloatAndAsInt(t *testing.T) {
	for _, tc := range []struct {
		in   any
		want float64
	}{
		{1.5, 1.5},
		{3, 3},
		{"2.25", 2.25},
		{"-1", -1},
		{"not a number", 0},
		{"", 0},
		{nil, 0},
		{true, 0},
	} {
		if got := asFloat(tc.in); got != tc.want {
			t.Errorf("asFloat(%#v) = %v, want %v", tc.in, got, tc.want)
		}
	}
	if got := asInt("301"); got != 301 {
		t.Errorf("asInt(301) = %d", got)
	}
	if got := asInt(7.9); got != 7 {
		t.Errorf("asInt truncates, got %d", got)
	}
	if got := asInt(nil); got != 0 {
		t.Errorf("asInt(nil) = %d", got)
	}
}
