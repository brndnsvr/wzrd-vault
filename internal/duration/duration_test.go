package duration

import (
	"testing"
	"time"
)

func TestParseDuration(t *testing.T) {
	now := time.Date(2026, 3, 19, 12, 0, 0, 0, time.UTC)

	tests := []struct {
		name    string
		input   string
		want    time.Time
		wantErr bool
	}{
		{"hours", "24h", now.Add(24 * time.Hour), false},
		{"days", "90d", now.AddDate(0, 0, 90), false},
		{"weeks", "12w", now.AddDate(0, 0, 84), false},
		{"months", "6m", now.AddDate(0, 6, 0), false},
		{"years", "1y", now.AddDate(1, 0, 0), false},
		{"date_full", "2026-12-31", time.Date(2026, 12, 31, 0, 0, 0, 0, time.UTC), false},
		{"one_day", "1d", now.AddDate(0, 0, 1), false},
		{"large_hours", "720h", now.Add(720 * time.Hour), false},
		{"zero", "0d", now, false},
		{"invalid_unit", "90x", time.Time{}, true},
		{"no_number", "d", time.Time{}, true},
		{"empty", "", time.Time{}, true},
		{"negative", "-5d", time.Time{}, true},
		{"bad_date", "2026-13-45", time.Time{}, true},
		{"just_text", "tomorrow", time.Time{}, true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParseExpiryAt(tc.input, now)
			if tc.wantErr {
				if err == nil {
					t.Errorf("ParseExpiryAt(%q) = %v, want error", tc.input, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseExpiryAt(%q) error: %v", tc.input, err)
			}
			if !got.Equal(tc.want) {
				t.Errorf("ParseExpiryAt(%q) = %v, want %v", tc.input, got, tc.want)
			}
		})
	}
}
