package internal

import (
	"encoding/base64"
	"fmt"
)

const (
	keyBoxType = "devcrypt-keybox"
)

// KeyBox stores an encryption key encrypted for a PublicKey.
type KeyBox struct {
	box []byte
	*PublicKey
}

// MarshalString encodes the KeyBox into a single line.
func (b *KeyBox) MarshalString() string {
	return fmt.Sprintf("%s %s %s %s",
		keyBoxType,
		base64.StdEncoding.EncodeToString(b.box),
		base64.StdEncoding.EncodeToString(b.key[:]),
		b.Label,
	)
}

// UnmarshalString decodes the KeyBox from a single line.
func (b *KeyBox) UnmarshalString(data string) error {
	fields, err := splitLineFields(data, keyBoxType, 3)
	if err != nil {
		return fmt.Errorf("keybox decode: %w", err)
	}

	b.box, err = base64.StdEncoding.DecodeString(fields[0])
	if err != nil {
		return fmt.Errorf("boxed key decode: %w", err)
	}

	b.key = new([32]byte)
	if err := decodeBase64Key(b.key, fields[1]); err != nil {
		return fmt.Errorf("pubkey decode: %w", err)
	}

	b.Label = fields[2]
	return nil
}
