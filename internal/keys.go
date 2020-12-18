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
	keyType             = "devcrypt-key"
)

var (
	errBadKeyEncoding = errors.New("invalid key encoding")
	errLabelNewline   = errors.New("labels may not contain newlines")
)

// GenerateKeys generates a new PublicKey and PrivateKey pair.
func GenerateKeys(label string) (*PublicKey, *PrivateKey, error) {
	if strings.ContainsRune(label, '\n') {
		return nil, nil, errLabelNewline
	}
	pubKeyBytes, privKeyBytes, err := box.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	pubKey := &PublicKey{
		Label: label,
		key:   pubKeyBytes,
	}
	privKey := &PrivateKey{
		Label: label,
		key:   privKeyBytes,
	}
	return pubKey, privKey, nil
}

// PublicKey stores the public key and label.
type PublicKey struct {
	Label string
	key   *[32]byte
}

// MarshalString encodes the PublicKey into a single line like SSH's authorized_keys.
func (k *PublicKey) MarshalString() string {
	return fmt.Sprintf("%s %s %s",
		keyType,
		base64.StdEncoding.EncodeToString(k.key[:]),
		k.Label,
	)
}

// UnmarshalString decodes the PublicKey from a single line.
func (k *PublicKey) UnmarshalString(data string) error {
	fields, err := splitLineFields(data, keyType, 2)
	if err != nil {
		return fmt.Errorf("key decode: %w", err)
	}

	k.key = new([32]byte)
	if err := decodeBase64Key(k.key, fields[0]); err != nil {
		return fmt.Errorf("decode public key: %w", err)
	}
	k.Label = fields[1]
	return nil
}

// PrivateKey stores the private key and label.
type PrivateKey struct {
	Label string
	key   *[32]byte
}

func (k *PrivateKey) publicKey() *PublicKey {
	// DANGER: this depends on the undocumented internals of golang.org/x/crypto/nacl/box !!!
	pubKey := &PublicKey{Label: k.Label, key: new([32]byte)}
	curve25519.ScalarBaseMult(pubKey.key, k.key)
	return pubKey
}

// Marshal encodes the PrivateKey into a PEM block.
func (k *PrivateKey) Marshal() ([]byte, error) {
	block := &pem.Block{
		Type:    privateKeyBlockType,
		Headers: map[string]string{"Label": k.Label},
		Bytes:   k.key[:],
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
	if k.key == nil {
		k.key = new([32]byte)
	}
	n := copy(k.key[:], block.Bytes)
	if n != len(k.key) {
		return errBadKeyEncoding
	}
	return nil
}

// GoString doesn't print the private key bytes.
func (k *PrivateKey) GoString() string {
	return fmt.Sprintf("PrivateKey{Label: %q}", k.Label)
}
