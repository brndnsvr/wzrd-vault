// Package crypto wraps filippo.io/age to provide identity generation,
// passphrase-protected key storage, and symmetric encrypt/decrypt of
// arbitrary byte slices. All private key material is scrypt-encrypted
// at rest — plaintext keys exist only in memory during operations.
package crypto
