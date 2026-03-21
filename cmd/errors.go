package cmd

import "fmt"

// ExitError represents a command failure with a specific exit code.
// Commands return this instead of calling os.Exit directly, which would
// bypass deferred cleanup (like closing the database).
type ExitError struct {
	Code    int
	Message string
}

func (e *ExitError) Error() string {
	return e.Message
}

// newExitError creates an ExitError with the given code and formatted message.
func newExitError(code int, format string, args ...any) *ExitError {
	return &ExitError{
		Code:    code,
		Message: fmt.Sprintf(format, args...),
	}
}
