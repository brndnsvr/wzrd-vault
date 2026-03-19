package cli

import (
	"bytes"
	"os"
	"strings"
	"testing"
)

func TestReadFromPipe(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"simple value", "my-secret", "my-secret"},
		{"strips single trailing newline", "my-secret\n", "my-secret"},
		{"preserves multiple trailing newlines minus one", "my-secret\n\n", "my-secret\n"},
		{"empty input", "", ""},
		{"just a newline", "\n", ""},
		{"value with internal newlines", "line1\nline2\n", "line1\nline2"},
		{"value with carriage return newline", "secret\r\n", "secret"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			reader := strings.NewReader(tc.input)
			got, err := ReadSecretFromPipe(reader)
			if err != nil {
				t.Fatalf("ReadSecretFromPipe() error: %v", err)
			}
			if got != tc.want {
				t.Errorf("ReadSecretFromPipe() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestConfirmationMatch(t *testing.T) {
	if !SecretsMatch("password", "password") {
		t.Error("identical secrets should match")
	}
	if SecretsMatch("password", "different") {
		t.Error("different secrets should not match")
	}
}

func TestPromptConfirmation_Yes(t *testing.T) {
	input := bytes.NewBufferString("y\n")
	var output bytes.Buffer

	confirmed := PromptYesNo(input, &output, "Delete this?")
	if !confirmed {
		t.Error("expected confirmation with 'y' input")
	}
}

func TestPromptConfirmation_No(t *testing.T) {
	input := bytes.NewBufferString("n\n")
	var output bytes.Buffer

	confirmed := PromptYesNo(input, &output, "Delete this?")
	if confirmed {
		t.Error("expected rejection with 'n' input")
	}
}

func TestPromptConfirmation_Default_No(t *testing.T) {
	input := bytes.NewBufferString("\n")
	var output bytes.Buffer

	confirmed := PromptYesNo(input, &output, "Delete this?")
	if confirmed {
		t.Error("expected rejection with empty input (default no)")
	}
}

func TestReadPassphraseFromFD(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = r.Close() }()

	go func() {
		_, _ = w.WriteString("my-passphrase\n")
		_ = w.Close()
	}()

	got, err := ReadPassphraseFromFD(int(r.Fd()))
	if err != nil {
		t.Fatalf("ReadPassphraseFromFD() error: %v", err)
	}
	if got != "my-passphrase" {
		t.Errorf("got %q, want %q", got, "my-passphrase")
	}
}
