//go:build integration

package cmd

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/brndnsvr/wzrd-vault/internal/crypto"
	"github.com/brndnsvr/wzrd-vault/internal/store"
)

type testVault struct {
	binary    string
	configDir string
	dbPath    string
	pubKey    string
	privKey   string
	env       []string
}

func setupTestVault(t *testing.T) *testVault {
	t.Helper()

	// Build binary from the module root (one directory up from cmd/).
	binDir := t.TempDir()
	binary := filepath.Join(binDir, "wzrd-vault")
	build := exec.Command("go", "build", "-o", binary, ".")
	build.Dir = ".."
	out, err := build.CombinedOutput()
	if err != nil {
		t.Fatalf("build failed: %s\n%s", err, out)
	}

	// Create temp config dir structure.
	configBase := t.TempDir()
	configDir := filepath.Join(configBase, "wzrd-vault")
	if err := os.MkdirAll(configDir, 0o700); err != nil {
		t.Fatal(err)
	}

	// Generate identity using the crypto package directly.
	identity, err := crypto.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}

	// Write public key.
	pubKeyPath := filepath.Join(configDir, "identity.pub")
	if err := os.WriteFile(pubKeyPath, []byte(identity.PublicKey+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	// Write placeholder identity.age (not needed with WZVAULT_AGE_KEY but file must exist).
	if err := os.WriteFile(filepath.Join(configDir, "identity.age"), []byte("placeholder"), 0o600); err != nil {
		t.Fatal(err)
	}

	// Create database using the store package directly.
	dbPath := filepath.Join(configDir, "stash.db")
	s, err := store.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	s.Close()

	env := []string{
		"HOME=" + t.TempDir(),
		"XDG_CONFIG_HOME=" + configBase,
		"WZVAULT_AGE_KEY=" + identity.PrivateKey,
		"WZVAULT_DB=",
		"WZVAULT_PASSPHRASE_FD=",
		"PATH=" + os.Getenv("PATH"),
	}

	return &testVault{
		binary:    binary,
		configDir: configDir,
		dbPath:    dbPath,
		pubKey:    identity.PublicKey,
		privKey:   identity.PrivateKey,
		env:       env,
	}
}

func (v *testVault) run(t *testing.T, stdin string, args ...string) (stdout, stderr string, exitCode int) {
	t.Helper()
	cmd := exec.Command(v.binary, args...)
	cmd.Env = v.env
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	var outBuf, errBuf strings.Builder
	cmd.Stdout = &outBuf
	cmd.Stderr = &errBuf

	err := cmd.Run()
	exitCode = 0
	if exitErr, ok := err.(*exec.ExitError); ok {
		exitCode = exitErr.ExitCode()
	} else if err != nil {
		t.Fatalf("unexpected error type: %v", err)
	}
	return outBuf.String(), errBuf.String(), exitCode
}

func TestIntegration_SetGetLifecycle(t *testing.T) {
	v := setupTestVault(t)

	_, stderr, code := v.run(t, "my-secret-value\n", "set", "work/db/password")
	if code != 0 {
		t.Fatalf("set exit code = %d, stderr: %s", code, stderr)
	}

	stdout, _, code := v.run(t, "", "get", "work/db/password")
	if code != 0 {
		t.Fatalf("get exit code = %d", code)
	}
	if stdout != "my-secret-value" {
		t.Errorf("get output = %q, want %q", stdout, "my-secret-value")
	}
}

func TestIntegration_GetWithNewline(t *testing.T) {
	v := setupTestVault(t)
	v.run(t, "secret123", "set", "test/key")

	stdout, _, _ := v.run(t, "", "get", "-n", "test/key")
	if stdout != "secret123\n" {
		t.Errorf("get -n output = %q, want %q", stdout, "secret123\n")
	}
}

func TestIntegration_ListAll(t *testing.T) {
	v := setupTestVault(t)
	v.run(t, "val1", "set", "aa/key1")
	v.run(t, "val2", "set", "bb/key2")
	v.run(t, "val3", "set", "aa/key3")

	stdout, _, code := v.run(t, "", "list")
	if code != 0 {
		t.Fatalf("list exit code = %d", code)
	}

	lines := strings.Split(strings.TrimSpace(stdout), "\n")
	if len(lines) != 3 {
		t.Fatalf("list returned %d lines, want 3: %v", len(lines), lines)
	}
	if lines[0] != "aa/key1" || lines[1] != "aa/key3" || lines[2] != "bb/key2" {
		t.Errorf("list output = %v, want [aa/key1, aa/key3, bb/key2]", lines)
	}
}

func TestIntegration_ListPrefix(t *testing.T) {
	v := setupTestVault(t)
	v.run(t, "val1", "set", "work/key1")
	v.run(t, "val2", "set", "work/key2")
	v.run(t, "val3", "set", "home/key3")

	stdout, _, _ := v.run(t, "", "list", "work/")
	lines := strings.Split(strings.TrimSpace(stdout), "\n")
	if len(lines) != 2 {
		t.Fatalf("list work/ returned %d lines, want 2", len(lines))
	}
}

func TestIntegration_Delete(t *testing.T) {
	v := setupTestVault(t)
	v.run(t, "val", "set", "test/delete_me")

	_, _, code := v.run(t, "", "delete", "--force", "test/delete_me")
	if code != 0 {
		t.Fatalf("delete exit code = %d", code)
	}

	_, _, code = v.run(t, "", "get", "test/delete_me")
	if code != 3 {
		t.Errorf("get after delete exit code = %d, want 3", code)
	}
}

func TestIntegration_GetNotFound_ExitCode3(t *testing.T) {
	v := setupTestVault(t)

	stdout, stderr, code := v.run(t, "", "get", "nonexistent/path")
	if code != 3 {
		t.Errorf("exit code = %d, want 3", code)
	}
	if stdout != "" {
		t.Errorf("stdout should be empty on not found, got %q", stdout)
	}
	if !strings.Contains(stderr, "not found") {
		t.Errorf("stderr should mention 'not found', got %q", stderr)
	}
}

func TestIntegration_DeleteNotFound_ExitCode3(t *testing.T) {
	v := setupTestVault(t)
	_, _, code := v.run(t, "", "delete", "--force", "nonexistent/path")
	if code != 3 {
		t.Errorf("exit code = %d, want 3", code)
	}
}

func TestIntegration_SetRejectsExtraArgs(t *testing.T) {
	v := setupTestVault(t)

	_, stderr, code := v.run(t, "", "set", "path", "secret-value")
	if code == 0 {
		t.Error("expected non-zero exit code when passing secret as argument")
	}
	if !strings.Contains(stderr, "stdin") {
		t.Errorf("stderr should mention stdin, got %q", stderr)
	}
}

func TestIntegration_GetProducesNoStdoutOnError(t *testing.T) {
	v := setupTestVault(t)
	stdout, _, _ := v.run(t, "", "get", "missing/secret")
	if stdout != "" {
		t.Errorf("stdout should be empty on error, got %q", stdout)
	}
}

func TestIntegration_Version(t *testing.T) {
	v := setupTestVault(t)
	stdout, _, code := v.run(t, "", "version")
	if code != 0 {
		t.Fatalf("version exit code = %d", code)
	}
	if !strings.Contains(stdout, "wzrd-vault version") {
		t.Errorf("version output missing expected text: %q", stdout)
	}
}

func TestIntegration_SetOverwrite(t *testing.T) {
	v := setupTestVault(t)
	v.run(t, "original", "set", "test/overwrite")
	v.run(t, "updated", "set", "--force", "test/overwrite")

	stdout, _, _ := v.run(t, "", "get", "test/overwrite")
	if stdout != "updated" {
		t.Errorf("get after overwrite = %q, want %q", stdout, "updated")
	}
}

func TestIntegration_PathValidation(t *testing.T) {
	v := setupTestVault(t)

	cases := []struct {
		name string
		path string
	}{
		{"dot-dot", "../etc/passwd"},
		{"double-slash", "foo//bar"},
		{"leading-slash", "/foo/bar"},
		{"uppercase", "FOO/bar"},
		{"single-char", "a"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, _, code := v.run(t, "secret", "set", tc.path)
			if code == 0 {
				t.Errorf("set %q should have failed", tc.path)
			}
		})
	}
}

func TestIntegration_FullLifecycle(t *testing.T) {
	v := setupTestVault(t)

	// Store three secrets.
	v.run(t, "tacacs-key", "set", "work/tacacs/key")
	v.run(t, "snmp-pass", "set", "work/snmp/v3_auth")
	v.run(t, "github-pat", "set", "dev/github/pat")

	// Verify each.
	for _, tc := range []struct {
		path string
		want string
	}{
		{"work/tacacs/key", "tacacs-key"},
		{"work/snmp/v3_auth", "snmp-pass"},
		{"dev/github/pat", "github-pat"},
	} {
		stdout, _, code := v.run(t, "", "get", tc.path)
		if code != 0 {
			t.Errorf("get %s exit code = %d", tc.path, code)
		}
		if stdout != tc.want {
			t.Errorf("get %s = %q, want %q", tc.path, stdout, tc.want)
		}
	}

	// List all.
	stdout, _, _ := v.run(t, "", "list")
	lines := strings.Split(strings.TrimSpace(stdout), "\n")
	if len(lines) != 3 {
		t.Fatalf("list returned %d, want 3", len(lines))
	}

	// List with prefix.
	stdout, _, _ = v.run(t, "", "list", "work/")
	lines = strings.Split(strings.TrimSpace(stdout), "\n")
	if len(lines) != 2 {
		t.Fatalf("list work/ returned %d, want 2", len(lines))
	}

	// Delete one.
	v.run(t, "", "delete", "--force", "work/snmp/v3_auth")

	// Verify deleted.
	_, _, code := v.run(t, "", "get", "work/snmp/v3_auth")
	if code != 3 {
		t.Errorf("expected exit 3 for deleted secret, got %d", code)
	}

	// List should now have 2.
	stdout, _, _ = v.run(t, "", "list")
	lines = strings.Split(strings.TrimSpace(stdout), "\n")
	if len(lines) != 2 {
		t.Errorf("list after delete returned %d, want 2", len(lines))
	}
}

func TestIntegration_ExportImportRoundTrip(t *testing.T) {
	v := setupTestVault(t)

	// Store some secrets.
	v.run(t, "tacacs-key-123", "set", "work/tacacs/key")
	v.run(t, "snmp-pass-456", "set", "work/snmp/auth")
	v.run(t, "github-pat-789", "set", "dev/github/pat")

	// Export as JSON.
	jsonOut, stderr, code := v.run(t, "", "export", "--format", "json")
	if code != 0 {
		t.Fatalf("export exit code = %d, stderr: %s", code, stderr)
	}

	// Verify JSON contains all secrets.
	if !strings.Contains(jsonOut, "tacacs-key-123") {
		t.Errorf("export JSON missing tacacs value")
	}
	if !strings.Contains(jsonOut, "snmp-pass-456") {
		t.Errorf("export JSON missing snmp value")
	}

	// Delete all secrets.
	v.run(t, "", "delete", "--prefix", "--force", "work/")
	v.run(t, "", "delete", "--force", "dev/github/pat")

	// Verify empty.
	stdout, _, _ := v.run(t, "", "list")
	if strings.TrimSpace(stdout) != "" {
		t.Fatalf("expected empty store after delete, got: %s", stdout)
	}

	// Import the JSON back.
	_, stderr, code = v.run(t, jsonOut, "import", "--format", "json")
	if code != 0 {
		t.Fatalf("import exit code = %d, stderr: %s", code, stderr)
	}

	// Verify all secrets restored.
	for _, tc := range []struct{ path, want string }{
		{"work/tacacs/key", "tacacs-key-123"},
		{"work/snmp/auth", "snmp-pass-456"},
		{"dev/github/pat", "github-pat-789"},
	} {
		stdout, _, code := v.run(t, "", "get", tc.path)
		if code != 0 {
			t.Errorf("get %s after import: exit %d", tc.path, code)
		}
		if stdout != tc.want {
			t.Errorf("get %s = %q, want %q", tc.path, stdout, tc.want)
		}
	}
}

func TestIntegration_Metadata(t *testing.T) {
	v := setupTestVault(t)

	// Set with metadata.
	_, _, code := v.run(t, "secret-val", "set", "work/tagged",
		"--tag", "env=prod", "--tag", "team=net", "--note", "test note", "--expires", "90d")
	if code != 0 {
		t.Fatalf("set with metadata exit code = %d", code)
	}

	// List as JSON and verify metadata.
	stdout, _, code := v.run(t, "", "list", "--json")
	if code != 0 {
		t.Fatalf("list --json exit code = %d", code)
	}
	if !strings.Contains(stdout, "env") || !strings.Contains(stdout, "prod") {
		t.Errorf("list --json missing tag env=prod: %s", stdout)
	}
	if !strings.Contains(stdout, "test note") {
		t.Errorf("list --json missing note: %s", stdout)
	}
	if !strings.Contains(stdout, "expires_at") {
		t.Errorf("list --json missing expires_at: %s", stdout)
	}
}

func TestIntegration_ExportFormats(t *testing.T) {
	v := setupTestVault(t)
	v.run(t, "myvalue", "set", "work/test/key")

	// Dotenv format.
	stdout, _, _ := v.run(t, "", "export", "--format", "dotenv")
	if !strings.Contains(stdout, "WORK_TEST_KEY=myvalue") {
		t.Errorf("dotenv format = %q, want WORK_TEST_KEY=myvalue", stdout)
	}

	// Shell format.
	stdout, _, _ = v.run(t, "", "export", "--format", "shell")
	if !strings.Contains(stdout, "export WORK_TEST_KEY='myvalue'") {
		t.Errorf("shell format = %q, want export WORK_TEST_KEY='myvalue'", stdout)
	}

	// Prefix strip.
	stdout, _, _ = v.run(t, "", "export", "work/", "--prefix-strip", "work/", "--format", "dotenv")
	if !strings.Contains(stdout, "TEST_KEY=myvalue") {
		t.Errorf("prefix-strip format = %q, want TEST_KEY=myvalue", stdout)
	}
}

func TestIntegration_ImportDryRun(t *testing.T) {
	v := setupTestVault(t)

	dotenv := "MY_KEY=hello\nOTHER_KEY=world\n"
	_, stderr, code := v.run(t, dotenv, "import", "--dry-run")
	if code != 0 {
		t.Fatalf("import --dry-run exit code = %d", code)
	}
	if !strings.Contains(stderr, "my/key") || !strings.Contains(stderr, "other/key") {
		t.Errorf("dry-run stderr should list paths: %s", stderr)
	}

	// Verify nothing was actually imported.
	stdout, _, _ := v.run(t, "", "list")
	if strings.TrimSpace(stdout) != "" {
		t.Errorf("dry-run should not import, but list shows: %s", stdout)
	}
}

func TestIntegration_VersionJSON(t *testing.T) {
	v := setupTestVault(t)
	stdout, _, code := v.run(t, "", "version", "--json")
	if code != 0 {
		t.Fatalf("version --json exit code = %d", code)
	}
	if !strings.Contains(stdout, "\"version\"") {
		t.Errorf("version --json missing version key: %s", stdout)
	}
	if !strings.Contains(stdout, "\"commit\"") {
		t.Errorf("version --json missing commit key: %s", stdout)
	}
}

func TestIntegration_Completion(t *testing.T) {
	v := setupTestVault(t)
	for _, shell := range []string{"bash", "zsh", "fish", "powershell"} {
		t.Run(shell, func(t *testing.T) {
			stdout, _, code := v.run(t, "", "completion", shell)
			if code != 0 {
				t.Errorf("completion %s exit code = %d", shell, code)
			}
			if stdout == "" {
				t.Errorf("completion %s produced no output", shell)
			}
		})
	}
}
