package store

import "testing"

func TestValidatePath(t *testing.T) {
	valid := []string{
		"ab",
		"work/db/password",
		"personal/cloudflare/api_token",
		"home/unifi/admin_password",
		"dev/github/pat",
		"work/network/tacacs/key",
		"a/b",
		"work/example.com/api_key",
		"a1/b2/c3",
		"my-secret/value",
		"top_level/nested",
	}
	for _, p := range valid {
		t.Run("valid/"+p, func(t *testing.T) {
			if err := ValidatePath(p); err != nil {
				t.Errorf("ValidatePath(%q) = %v, want nil", p, err)
			}
		})
	}

	invalid := []struct {
		path   string
		reason string
	}{
		{"", "empty path"},
		{"a", "single character"},
		{"/leading/slash", "leading slash"},
		{"trailing/slash/", "trailing slash"},
		{"double//slash", "double slash"},
		{"../etc/passwd", "dot-dot component"},
		{"foo/../bar", "dot-dot component"},
		{"UPPER/case", "uppercase letters"},
		{"has space/in/path", "spaces"},
		{"special!/chars", "special characters"},
		{".hidden/path", "leading dot"},
		{"path/.hidden", "trailing dot"},
		{"work/café/key", "non-ascii"},
		{"-dash/start", "leading dash"},
		{"path/-dash", "component starting with dash"},
	}
	for _, tc := range invalid {
		t.Run("invalid/"+tc.reason, func(t *testing.T) {
			if err := ValidatePath(tc.path); err == nil {
				t.Errorf("ValidatePath(%q) = nil, want error (%s)", tc.path, tc.reason)
			}
		})
	}
}
