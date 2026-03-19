package store

import (
	"fmt"
	"regexp"
	"strings"
)

// pathPattern validates secret path format: lowercase alphanumeric with
// slashes, underscores, dots, and hyphens. Must start and end with
// alphanumeric. Minimum 2 characters.
var pathPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9/_.\-]*[a-z0-9]$`)

// componentPattern validates that each path component starts and ends with
// an alphanumeric character.
var componentPattern = regexp.MustCompile(`^[a-z0-9]`)

// ValidatePath checks that a secret path conforms to wzrd-vault naming rules.
// Paths must be lowercase, use / as separator, contain no .. components,
// no double slashes, no leading/trailing slashes, and be at least 2 characters.
// Each path component must start with a lowercase letter or digit.
// Returns a descriptive error if the path is invalid.
func ValidatePath(path string) error {
	if len(path) < 2 {
		return fmt.Errorf("invalid path %q: must be at least 2 characters", path)
	}

	if !pathPattern.MatchString(path) {
		return fmt.Errorf("invalid path %q: must contain only lowercase letters, numbers, '/', '_', '.', '-' and start/end with a letter or number", path)
	}

	if strings.Contains(path, "//") {
		return fmt.Errorf("invalid path %q: must not contain double slashes", path)
	}

	for _, component := range strings.Split(path, "/") {
		if component == ".." {
			return fmt.Errorf("invalid path %q: must not contain '..' components", path)
		}
		if !componentPattern.MatchString(component) {
			return fmt.Errorf("invalid path %q: each component must start with a lowercase letter or digit", path)
		}
	}

	return nil
}
