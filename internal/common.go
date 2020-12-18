package internal

import (
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
)

var (
	errUnexpectedNewline = errors.New("unexpected newline")
)

func decodeBase64Key(key *[32]byte, data string) error {
	n, err := base64.StdEncoding.Decode(key[:], []byte(data))
	if err != nil {
		return err
	}
	if n != len(key) {
		return fmt.Errorf("key too short: %d", n)
	}
	return nil
}

func splitLineFields(line, firstFieldExpect string, fieldCount int) ([]string, error) {
	line = strings.TrimSpace(line)
	if strings.ContainsRune(line, '\n') {
		return nil, errUnexpectedNewline
	}

	fields := strings.SplitN(line, " ", fieldCount+1)
	if len(fields) != fieldCount {
		return nil, fmt.Errorf("expected %d fields, got %d", fieldCount, len(fields))
	}
	if fields[0] != firstFieldExpect {
		return nil, fmt.Errorf("expected %q, got %q", firstFieldExpect, fields[0])
	}
	return fields[1:], nil
}
