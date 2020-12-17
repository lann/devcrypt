package internal

import (
	"bufio"
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"strings"

	"golang.org/x/crypto/nacl/box"
	"golang.org/x/crypto/nacl/secretbox"
)

const (
	encryptedFileBlockType = "DEVCRYPT ENCRYPTED FILE"

	// "16KB is a reasonable chunk size":
	// https://pkg.go.dev/golang.org/x/crypto/nacl/secretbox
	chunkSize = 16 * 1024
)

var (
	// ErrAlreadyAdded means the public key was already added
	ErrAlreadyAdded = errors.New("public key already added")

	errBadKeyBoxEncoding  = errors.New("invalid keybox encoding")
	errBadEncFileEncoding = errors.New("invalid encrypted file encoding")
)

// EncFile stores KeyBoxes and an encrypted file.
type EncFile struct {
	keyBoxes []KeyBox

	Filename   string
	macHex     string
	ciphertext []byte
}

// UnsealedEncFile is an unsealed EncFile.
type UnsealedEncFile struct {
	*EncFile
	fileKey *[32]byte
}

// NewUnsealedEncFile encrypts the given content and returns a new UnsealedEncFile.
func NewUnsealedEncFile(filename string, plaintext []byte) (*UnsealedEncFile, error) {
	var fileKey [32]byte
	if _, err := rand.Read(fileKey[:]); err != nil {
		return nil, err
	}

	mac := hmac.New(sha256.New, fileKey[:])

	var out []byte
	var chunkNum uint64 = 0
	for len(plaintext) > 0 {
		// Get the next chunkSize-sized chunk
		chunk := plaintext
		if len(chunk) > chunkSize {
			chunk = chunk[:chunkSize]
			plaintext = plaintext[chunkSize:]
		} else {
			plaintext = nil
		}

		// Update MAC
		mac.Write(chunk)

		// Since we gnerate a new key each time, we can just use the chunk counter here
		var nonce [24]byte
		binary.LittleEndian.PutUint64(nonce[:], chunkNum)
		chunkNum++

		// Encrypt the chunk
		out = secretbox.Seal(out, chunk, &nonce, &fileKey)
	}

	return &UnsealedEncFile{
		EncFile: &EncFile{
			Filename:   filename,
			macHex:     hex.EncodeToString(mac.Sum(nil)),
			ciphertext: out,
		},
		fileKey: &fileKey,
	}, nil
}

// AddPublicKey adds the given PublicKey to the EncFile.
func (f *UnsealedEncFile) AddPublicKey(pubKey *PublicKey) error {
	if f.getKeyBox(pubKey) != nil {
		return ErrAlreadyAdded
	}
	boxedKey, err := box.SealAnonymous(nil, f.fileKey[:], pubKey.bytes, rand.Reader)
	if err != nil {
		return fmt.Errorf("sealing file key: %w", err)
	}
	f.keyBoxes = append(f.keyBoxes, KeyBox{
		boxedKey: boxedKey,
		pubKey:   pubKey,
	})
	return nil
}

// Decrypt decrypts the file contents.
func (f *UnsealedEncFile) Decrypt() ([]byte, error) {
	ciphertext := f.ciphertext
	var out []byte
	cipherChunkSize := chunkSize + secretbox.Overhead
	var chunkNum uint64 = 0
	for len(ciphertext) > 0 {
		// Get the next chunkSize+overhead-sized chunk
		chunk := ciphertext
		if len(chunk) > cipherChunkSize {
			chunk = chunk[:cipherChunkSize]
			ciphertext = ciphertext[cipherChunkSize:]
		} else {
			ciphertext = nil
		}

		var nonce [24]byte
		binary.LittleEndian.PutUint64(nonce[:], chunkNum)
		chunkNum++

		var ok bool
		out, ok = secretbox.Open(out, chunk, &nonce, f.fileKey)
		if !ok {
			return nil, fmt.Errorf("decrypt failed")
		}
	}
	return out, nil
}

// GoString doesn't print the key bytes.
func (f *UnsealedEncFile) GoString() string {
	return fmt.Sprintf("UnsealedEncFile{EncFile: %#v}", f.EncFile)
}

// Unseal the EncFile with the given PrivateKey.
func (f *EncFile) Unseal(privKey *PrivateKey) (*UnsealedEncFile, error) {
	keyBox := f.getKeyBox(privKey.publicKey())
	if keyBox == nil {
		return nil, fmt.Errorf("no key box found for key labeled %q", privKey.Label)
	}
	var fileKey [32]byte
	out, ok := box.OpenAnonymous(fileKey[:0], keyBox.boxedKey, keyBox.pubKey.bytes, privKey.bytes)
	if !ok || len(out) != len(fileKey) {
		return nil, fmt.Errorf("unboxing key failed with private key %q", privKey.Label)
	}
	return &UnsealedEncFile{EncFile: f, fileKey: &fileKey}, nil
}

func (f *EncFile) getKeyBox(pubKey *PublicKey) *KeyBox {
	for i := range f.keyBoxes {
		pubKeyBytes := f.keyBoxes[i].pubKey.bytes
		if *pubKeyBytes == *pubKey.bytes {
			return &f.keyBoxes[i]
		}
	}
	return nil
}

// WriteTo writes the EncFile to the given Writer.
func (f *EncFile) WriteTo(w io.Writer) (n int64, err error) {
	for i := range f.keyBoxes {
		lineN, err := fmt.Fprintln(w, f.keyBoxes[i].MarshalString())
		n += int64(lineN)
		if err != nil {
			return n, err
		}
	}
	headers := map[string]string{}
	if f.Filename != "" {
		headers["Filename"] = f.Filename
	}
	if f.macHex != "" {
		headers["MAC"] = f.macHex
	}
	blockBytes := pem.EncodeToMemory(&pem.Block{
		Type:    encryptedFileBlockType,
		Headers: headers,
		Bytes:   f.ciphertext,
	})
	blockN, err := w.Write(blockBytes)
	n += int64(blockN)
	return n, err
}

// ReadFrom reads an EncFile from a Reader.
func (f *EncFile) ReadFrom(r io.Reader) (n int64, err error) {
	f.keyBoxes = nil
	br := bufio.NewReader(r)
	lineNum := 0
	for {
		line, err := br.ReadString('\n')
		n += int64(len(line))
		lineNum++
		if err != nil {
			return n, err
		}

		var keyBox KeyBox
		if err := keyBox.UnmarshalString(line); err != nil {
			return n, fmt.Errorf("%w (at line %d)", err, lineNum)
		}
		f.keyBoxes = append(f.keyBoxes, keyBox)

		if nextByte, err := br.Peek(1); err != nil {
			return n, err
		} else if nextByte[0] == '-' {
			break
		}
	}

	rest, err := ioutil.ReadAll(br)
	n += int64(len(rest))
	if err != nil {
		return n, err
	}
	block, rest := pem.Decode(rest)
	if block == nil || len(bytes.TrimSpace(rest)) > 0 {
		return n, errBadEncFileEncoding
	}
	if block.Type != encryptedFileBlockType {
		return n, fmt.Errorf("unknown block type %q", block.Type)
	}
	f.Filename = block.Headers["Filename"]
	f.macHex = block.Headers["MAC"]
	f.ciphertext = block.Bytes

	return n, nil
}

// KeyBox stores an encryption key encrypted for a PublicKey.
type KeyBox struct {
	boxedKey []byte
	pubKey   *PublicKey
}

// MarshalString encodes the KeyBox into a single line.
func (b *KeyBox) MarshalString() string {
	return fmt.Sprintf("devcrypt-keybox %s %s %s",
		base64.StdEncoding.EncodeToString(b.boxedKey),
		b.pubKey.Base64Key(),
		b.pubKey.Label,
	)
}

// UnmarshalString decodes the KeyBox from a single line.
func (b *KeyBox) UnmarshalString(data string) error {
	data = strings.TrimSpace(data)
	if strings.ContainsRune(data, '\n') {
		return errBadKeyBoxEncoding
	}

	fields := strings.SplitN(data, " ", 4)
	if len(fields) != 4 || fields[0] != "devcrypt-keybox" {
		return errBadKeyBoxEncoding
	}

	var err error
	b.boxedKey, err = base64.StdEncoding.DecodeString(fields[1])
	if err != nil {
		return fmt.Errorf("boxed key decode: %w", err)
	}

	if b.pubKey == nil {
		b.pubKey = &PublicKey{bytes: new([32]byte)}
	}
	if err := base64DecodeKey(b.pubKey.bytes, fields[2]); err != nil {
		return fmt.Errorf("pubkey decode: %w", err)
	}

	b.pubKey.Label = fields[3]
	return nil
}
