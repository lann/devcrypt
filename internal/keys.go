package internal

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/nacl/box"
)

const (
	privateKeyBlockType = "DEVCRYPT PRIVATE KEY"
)

var (
	errBadKeyEncoding = errors.New("invalid key encoding")
	errLabelNewline   = errors.New("labels may not contain newlines")
)

// GenerateKey generates a new PublicKey and PrivateKey pair.
func GenerateKey(label string) (*PublicKey, *PrivateKey, error) {
	if strings.ContainsRune(label, '\n') {
		return nil, nil, errLabelNewline
	}
	pubKeyBytes, privKeyBytes, err := box.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	pubKey := &PublicKey{
		Label: label,
		bytes: pubKeyBytes,
	}
	privKey := &PrivateKey{
		Label: label,
		bytes: privKeyBytes,
	}
	return pubKey, privKey, nil
}

// PublicKey stores the public key and label.
type PublicKey struct {
	Label string
	bytes *[32]byte
}

// Base64Key returns the base64-encoded public key.
func (k *PublicKey) Base64Key() string {
	return base64.StdEncoding.EncodeToString(k.bytes[:])
}

// MarshalString encodes the PublicKey into a single line like SSH's authorized_keys.
func (k *PublicKey) MarshalString() string {
	return fmt.Sprintf("devcrypt-key %s %s",
		k.Base64Key(),
		k.Label,
	)
}

// UnmarshalString decodes the PublicKey from a single line.
func (k *PublicKey) UnmarshalString(data string) error {
	data = strings.TrimSpace(data)
	if strings.ContainsRune(data, '\n') {
		return errBadKeyEncoding
	}

	fields := strings.SplitN(data, " ", 3)
	if len(fields) != 3 || fields[0] != "devcrypt-key" {
		return errBadKeyEncoding
	}

	if k.bytes == nil {
		k.bytes = new([32]byte)
	}
	if err := base64DecodeKey(k.bytes, fields[1]); err != nil {
		return fmt.Errorf("decode public key: %w", err)
	}
	k.Label = fields[2]
	return nil
}

// PrivateKey stores the private key and label.
type PrivateKey struct {
	Label string
	bytes *[32]byte
}

func (k *PrivateKey) publicKey() *PublicKey {
	// DANGER: this depends on the undocumented internals of golang.org/x/crypto/nacl/box !!!
	pubKey := &PublicKey{Label: k.Label, bytes: new([32]byte)}
	curve25519.ScalarBaseMult(pubKey.bytes, k.bytes)
	return pubKey
}

// Marshal encodes the PrivateKey into a PEM block.
func (k *PrivateKey) Marshal() ([]byte, error) {
	block := &pem.Block{
		Type:    privateKeyBlockType,
		Headers: map[string]string{"Label": k.Label},
		Bytes:   k.bytes[:],
	}
	var buf bytes.Buffer
	if err := pem.Encode(&buf, block); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// Unmarshal decodes the PrivateKey from a PEM block.
func (k *PrivateKey) Unmarshal(blockBytes []byte) error {
	block, rest := pem.Decode(blockBytes)
	if block == nil || len(bytes.TrimSpace(rest)) != 0 {
		return errBadKeyEncoding
	}
	k.Label = block.Headers["Label"]
	if k.bytes == nil {
		k.bytes = new([32]byte)
	}
	n := copy(k.bytes[:], block.Bytes)
	if n != len(k.bytes) {
		return errBadKeyEncoding
	}
	return nil
}

// GoString doesn't print the private key bytes.
func (k *PrivateKey) GoString() string {
	return fmt.Sprintf("PrivateKey{Label: %q}", k.Label)
}

func base64DecodeKey(key *[32]byte, data string) error {
	n, err := base64.StdEncoding.Decode(key[:], []byte(data))
	if err != nil {
		return err
	}
	if n != len(key) {
		return fmt.Errorf("key too short: %d", n)
	}
	return nil
}
