// Package cli provides shared helpers for terminal interaction: TTY detection,
// secure stdin reading (pipe vs interactive with echo disabled), and passphrase
// prompting via stderr/tty. All user-facing prompts use stderr so stdout
// remains clean for piped secret output.
package cli
