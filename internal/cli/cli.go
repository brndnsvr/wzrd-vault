package cli

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"

	"golang.org/x/term"
)

// IsTerminal reports whether the given file descriptor is a terminal.
func IsTerminal(fd int) bool {
	return term.IsTerminal(fd)
}

// ReadSecretFromPipe reads a secret value from a pipe (non-tty stdin).
// Strips a single trailing newline if present — this handles the common
// case of `echo "secret" | wzrd-vault set`. Does NOT strip if the input
// has multiple trailing newlines (only strips exactly one).
// Also strips a trailing \r\n (Windows line ending).
func ReadSecretFromPipe(r io.Reader) (string, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return "", fmt.Errorf("reading from stdin: %w", err)
	}
	s := string(data)

	if strings.HasSuffix(s, "\r\n") {
		s = s[:len(s)-2]
	} else if strings.HasSuffix(s, "\n") {
		s = s[:len(s)-1]
	}
	return s, nil
}

// ReadSecretInteractive prompts the user to enter a secret with echo disabled,
// then prompts for confirmation. Prompts and errors go to stderr.
// Returns the secret value or an error if the inputs don't match.
func ReadSecretInteractive(prompt string) (string, error) {
	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return "", fmt.Errorf("opening terminal: %w", err)
	}
	defer func() { _ = tty.Close() }()

	fd := int(tty.Fd())

	fmt.Fprintf(os.Stderr, "%s: ", prompt)
	secret1, err := term.ReadPassword(fd)
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return "", fmt.Errorf("reading secret: %w", err)
	}

	fmt.Fprintf(os.Stderr, "Confirm %s: ", strings.ToLower(prompt))
	secret2, err := term.ReadPassword(fd)
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return "", fmt.Errorf("reading confirmation: %w", err)
	}

	if !SecretsMatch(string(secret1), string(secret2)) {
		return "", fmt.Errorf("secrets do not match")
	}
	return string(secret1), nil
}

// PromptPassphrase prompts for a passphrase on stderr/tty with echo disabled.
// Unlike ReadSecretInteractive, this does NOT ask for confirmation —
// it's used for decryption where we just need the passphrase once.
func PromptPassphrase() (string, error) {
	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return "", fmt.Errorf("opening terminal: %w", err)
	}
	defer func() { _ = tty.Close() }()

	fd := int(tty.Fd())

	fmt.Fprint(os.Stderr, "Passphrase: ")
	passphrase, err := term.ReadPassword(fd)
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return "", fmt.Errorf("reading passphrase: %w", err)
	}
	return string(passphrase), nil
}

// ReadPassphraseFromFD reads a passphrase from the given file descriptor.
// Strips trailing newlines. Used for WZVAULT_PASSPHRASE_FD support.
func ReadPassphraseFromFD(fd int) (string, error) {
	f := os.NewFile(uintptr(fd), "passphrase-fd")
	if f == nil {
		return "", fmt.Errorf("invalid file descriptor: %d", fd)
	}

	data, err := io.ReadAll(f)
	if err != nil {
		return "", fmt.Errorf("reading passphrase from fd %d: %w", fd, err)
	}
	s := strings.TrimRight(string(data), "\r\n")
	return s, nil
}

// SecretsMatch compares two secret strings for equality.
func SecretsMatch(a, b string) bool {
	return a == b
}

// PromptYesNo prompts the user with a yes/no question.
// Returns true for "y" or "yes" (case-insensitive), false otherwise.
// Reads from r, writes prompt to w.
func PromptYesNo(r io.Reader, w io.Writer, prompt string) bool {
	_, _ = fmt.Fprintf(w, "%s [y/N]: ", prompt)
	scanner := bufio.NewScanner(r)
	if !scanner.Scan() {
		return false
	}
	answer := strings.TrimSpace(strings.ToLower(scanner.Text()))
	return answer == "y" || answer == "yes"
}
