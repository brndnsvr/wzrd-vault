package crypto

import (
	"bytes"
	"testing"
)

func TestGenerateIdentity(t *testing.T) {
	identity, err := GenerateIdentity()
	if err != nil {
		t.Fatalf("GenerateIdentity() error: %v", err)
	}
	if identity.PrivateKey == "" {
		t.Error("PrivateKey is empty")
	}
	if identity.PublicKey == "" {
		t.Error("PublicKey is empty")
	}
	if identity.PublicKey[:4] != "age1" {
		t.Errorf("PublicKey doesn't start with age1: %q", identity.PublicKey)
	}
}

func TestEncryptDecryptIdentity(t *testing.T) {
	identity, err := GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}

	passphrase := "test-passphrase-123"

	encrypted, err := EncryptIdentity(identity.PrivateKey, passphrase)
	if err != nil {
		t.Fatalf("EncryptIdentity() error: %v", err)
	}
	if len(encrypted) == 0 {
		t.Fatal("encrypted identity is empty")
	}
	if bytes.Contains(encrypted, []byte(identity.PrivateKey)) {
		t.Error("encrypted identity contains raw private key")
	}

	decrypted, err := DecryptIdentity(encrypted, passphrase)
	if err != nil {
		t.Fatalf("DecryptIdentity() error: %v", err)
	}
	if decrypted != identity.PrivateKey {
		t.Errorf("round-trip failed: got %q, want %q", decrypted, identity.PrivateKey)
	}
}

func TestDecryptIdentity_WrongPassphrase(t *testing.T) {
	identity, err := GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}

	encrypted, err := EncryptIdentity(identity.PrivateKey, "correct-passphrase")
	if err != nil {
		t.Fatal(err)
	}

	_, err = DecryptIdentity(encrypted, "wrong-passphrase")
	if err == nil {
		t.Error("expected error with wrong passphrase, got nil")
	}
}

func TestEncryptDecryptValue(t *testing.T) {
	identity, err := GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}

	plaintext := []byte("super-secret-value-42")

	ciphertext, err := Encrypt(plaintext, identity.PublicKey)
	if err != nil {
		t.Fatalf("Encrypt() error: %v", err)
	}
	if len(ciphertext) == 0 {
		t.Fatal("ciphertext is empty")
	}
	if bytes.Equal(ciphertext, plaintext) {
		t.Error("ciphertext equals plaintext")
	}

	decrypted, err := Decrypt(ciphertext, identity.PrivateKey)
	if err != nil {
		t.Fatalf("Decrypt() error: %v", err)
	}
	if !bytes.Equal(decrypted, plaintext) {
		t.Errorf("round-trip failed: got %q, want %q", decrypted, plaintext)
	}
}

func TestEncryptDecryptValue_Empty(t *testing.T) {
	identity, err := GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}

	ciphertext, err := Encrypt([]byte{}, identity.PublicKey)
	if err != nil {
		t.Fatalf("Encrypt() error: %v", err)
	}

	decrypted, err := Decrypt(ciphertext, identity.PrivateKey)
	if err != nil {
		t.Fatalf("Decrypt() error: %v", err)
	}
	if len(decrypted) != 0 {
		t.Errorf("expected empty, got %q", decrypted)
	}
}

func TestDecryptValue_WrongKey(t *testing.T) {
	id1, _ := GenerateIdentity()
	id2, _ := GenerateIdentity()

	ciphertext, err := Encrypt([]byte("secret"), id1.PublicKey)
	if err != nil {
		t.Fatal(err)
	}

	_, err = Decrypt(ciphertext, id2.PrivateKey)
	if err == nil {
		t.Error("expected error decrypting with wrong key, got nil")
	}
}
