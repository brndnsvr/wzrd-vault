package duration

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// ParseExpiry parses an expiry string relative to the current time.
// Accepts durations (24h, 90d, 12w, 6m, 1y) or absolute dates (2026-12-31).
func ParseExpiry(s string) (time.Time, error) {
	return ParseExpiryAt(s, time.Now())
}

// ParseExpiryAt parses an expiry string relative to the given time.
// Exists for testability.
func ParseExpiryAt(s string, now time.Time) (time.Time, error) {
	if s == "" {
		return time.Time{}, fmt.Errorf("empty expiry value")
	}

	// Try absolute date first: YYYY-MM-DD
	if t, err := time.Parse("2006-01-02", s); err == nil {
		return t, nil
	}

	// Parse relative duration: Nh, Nd, Nw, Nm, Ny
	if len(s) < 2 {
		return time.Time{}, fmt.Errorf("invalid expiry %q: expected a duration like 90d or a date like 2026-12-31", s)
	}

	unit := s[len(s)-1:]
	numStr := s[:len(s)-1]

	n, err := strconv.Atoi(numStr)
	if err != nil || n < 0 {
		return time.Time{}, fmt.Errorf("invalid expiry %q: expected a positive number followed by h/d/w/m/y", s)
	}

	switch strings.ToLower(unit) {
	case "h":
		return now.Add(time.Duration(n) * time.Hour), nil
	case "d":
		return now.AddDate(0, 0, n), nil
	case "w":
		return now.AddDate(0, 0, n*7), nil
	case "m":
		return now.AddDate(0, n, 0), nil
	case "y":
		return now.AddDate(n, 0, 0), nil
	default:
		return time.Time{}, fmt.Errorf("invalid expiry %q: unknown unit %q (use h, d, w, m, or y)", s, unit)
	}
}
