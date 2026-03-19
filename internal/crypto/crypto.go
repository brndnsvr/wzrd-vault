package crypto

import (
	"bytes"
	"fmt"
	"io"
	"strings"

	"filippo.io/age"
	"filippo.io/age/armor"
)

// Identity holds an age X25519 keypair.
type Identity struct {
	// PrivateKey is the AGE-SECRET-KEY-1... string.
	PrivateKey string
	// PublicKey is the age1... string.
	PublicKey string
}

// GenerateIdentity creates a new age X25519 keypair.
func GenerateIdentity() (*Identity, error) {
	id, err := age.GenerateX25519Identity()
	if err != nil {
		return nil, fmt.Errorf("generating age identity: %w", err)
	}
	return &Identity{
		PrivateKey: id.String(),
		PublicKey:  id.Recipient().String(),
	}, nil
}

// EncryptIdentity encrypts a private key string with a passphrase using
// age's scrypt recipient. The result is PEM-armored for safe file storage.
func EncryptIdentity(privateKey, passphrase string) ([]byte, error) {
	recipient, err := age.NewScryptRecipient(passphrase)
	if err != nil {
		return nil, fmt.Errorf("creating scrypt recipient: %w", err)
	}
	recipient.SetWorkFactor(18)

	var buf bytes.Buffer
	armorWriter := armor.NewWriter(&buf)

	writer, err := age.Encrypt(armorWriter, recipient)
	if err != nil {
		return nil, fmt.Errorf("creating age encryptor: %w", err)
	}
	if _, err := io.WriteString(writer, privateKey); err != nil {
		return nil, fmt.Errorf("writing private key: %w", err)
	}
	if err := writer.Close(); err != nil {
		return nil, fmt.Errorf("closing age encryptor: %w", err)
	}
	if err := armorWriter.Close(); err != nil {
		return nil, fmt.Errorf("closing armor writer: %w", err)
	}
	return buf.Bytes(), nil
}

// DecryptIdentity decrypts a passphrase-encrypted private key,
// returning the AGE-SECRET-KEY-1... string.
func DecryptIdentity(encrypted []byte, passphrase string) (string, error) {
	identity, err := age.NewScryptIdentity(passphrase)
	if err != nil {
		return "", fmt.Errorf("creating scrypt identity: %w", err)
	}

	armorReader := armor.NewReader(bytes.NewReader(encrypted))

	reader, err := age.Decrypt(armorReader, identity)
	if err != nil {
		return "", fmt.Errorf("decrypting identity — wrong passphrase? %w", err)
	}

	var buf bytes.Buffer
	if _, err := io.Copy(&buf, reader); err != nil {
		return "", fmt.Errorf("reading decrypted identity: %w", err)
	}
	return buf.String(), nil
}

// Encrypt encrypts plaintext bytes using an age public key.
// Returns raw (non-armored) ciphertext suitable for database storage.
func Encrypt(plaintext []byte, publicKey string) ([]byte, error) {
	recipient, err := age.ParseX25519Recipient(publicKey)
	if err != nil {
		return nil, fmt.Errorf("parsing public key: %w", err)
	}

	var buf bytes.Buffer
	writer, err := age.Encrypt(&buf, recipient)
	if err != nil {
		return nil, fmt.Errorf("creating age encryptor: %w", err)
	}
	if _, err := writer.Write(plaintext); err != nil {
		return nil, fmt.Errorf("writing plaintext: %w", err)
	}
	if err := writer.Close(); err != nil {
		return nil, fmt.Errorf("closing age encryptor: %w", err)
	}
	return buf.Bytes(), nil
}

// Decrypt decrypts ciphertext bytes using an age private key string.
func Decrypt(ciphertext []byte, privateKey string) ([]byte, error) {
	identity, err := age.ParseX25519Identity(strings.TrimSpace(privateKey))
	if err != nil {
		return nil, fmt.Errorf("parsing private key: %w", err)
	}

	reader, err := age.Decrypt(bytes.NewReader(ciphertext), identity)
	if err != nil {
		return nil, fmt.Errorf("decrypting: %w", err)
	}

	var buf bytes.Buffer
	if _, err := io.Copy(&buf, reader); err != nil {
		return nil, fmt.Errorf("reading decrypted data: %w", err)
	}
	return buf.Bytes(), nil
}
