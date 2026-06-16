// Copyright 2026 The kasapi Authors
// SPDX-License-Identifier: Apache-2.0

package kasapi

import (
	"fmt"
	"strconv"
)

// Conversion helpers for the generic values decoded from KAS responses, which
// may arrive as string, float64 or int depending on the field.

func asString(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case float64:
		return strconv.FormatFloat(t, 'f', -1, 64)
	case int:
		return strconv.Itoa(t)
	case nil:
		return ""
	default:
		return fmt.Sprintf("%v", t)
	}
}

func asFloat(v any) float64 {
	switch t := v.(type) {
	case float64:
		return t
	case int:
		return float64(t)
	case string:
		f, _ := strconv.ParseFloat(t, 64)
		return f
	default:
		return 0
	}
}

func asInt(v any) int {
	return int(asFloat(v))
}
