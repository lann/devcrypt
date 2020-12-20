package internal

import (
	"bufio"
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/ioutil"

	"golang.org/x/crypto/nacl/box"
	"golang.org/x/crypto/nacl/secretbox"
)

const (
	encryptedFileBlockType = "DEVCRYPT ENCRYPTED FILE"

	// "16KB is a reasonable chunk size":
	// https://pkg.go.dev/golang.org/x/crypto/nacl/secretbox
	chunkSize       = 16 * 1024
	cipherChunkSize = chunkSize + secretbox.Overhead
)

var (
	// ErrAlreadyAdded means the public key was already added
	ErrAlreadyAdded = errors.New("public key already added")

	// ErrPublicKeyNotFound means the public key wasn't found
	ErrPublicKeyNotFound = errors.New("public key not found")

	errBadEncFileEncoding = errors.New("invalid encrypted file encoding")
)

// EncFile stores KeyBoxes and an encrypted file.
type EncFile struct {
	keyBoxes []KeyBox

	Filename string
	MAC      []byte

	nonce      []byte
	ciphertext []byte
}

// PublicKeys returns the public keys in this EncFile.
func (f *EncFile) PublicKeys() []*PublicKey {
	pubKeys := make([]*PublicKey, len(f.keyBoxes))
	for i := range f.keyBoxes {
		pubKeys[i] = f.keyBoxes[i].PublicKey
	}
	return pubKeys
}

// RemovePublicKey removes the given public key from the EncFile.
func (f *EncFile) RemovePublicKey(pubKey *PublicKey) error {
	updated := f.keyBoxes[:0]
	var removed bool
	for _, keyBox := range f.keyBoxes {
		if keyBox.PublicKey != pubKey {
			updated = append(updated, keyBox)
		} else {
			removed = true
		}
	}
	if !removed {
		return ErrPublicKeyNotFound
	}
	f.keyBoxes = updated
	return nil
}

// Unseal the EncFile with the given PrivateKey.
func (f *EncFile) Unseal(privKey *PrivateKey) (*UnsealedEncFile, error) {
	keyBox := f.getKeyBox(privKey.publicKey())
	if keyBox == nil {
		return nil, fmt.Errorf("no key box found for key labeled %q", privKey.Label)
	}
	var fileKey [32]byte
	out, ok := box.OpenAnonymous(fileKey[:0], keyBox.box, keyBox.PublicKey.key, privKey.key)
	if !ok || len(out) != len(fileKey) {
		return nil, fmt.Errorf("unboxing key failed with private key %q", privKey.Label)
	}
	return &UnsealedEncFile{EncFile: f, fileKey: &fileKey}, nil
}

// FileSize returns the plaintext file size.
func (f *EncFile) FileSize() int {
	cipherSize := len(f.ciphertext)
	chunks := (cipherSize / cipherChunkSize) + 1
	return cipherSize - (secretbox.Overhead * chunks)
}

func (f *EncFile) getKeyBox(pubKey *PublicKey) *KeyBox {
	for i := range f.keyBoxes {
		pubKeyBytes := f.keyBoxes[i].PublicKey.key
		if *pubKeyBytes == *pubKey.key {
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
	if len(f.MAC) > 0 {
		headers["MAC"] = hex.EncodeToString(f.MAC)
	}
	if len(f.nonce) > 0 {
		headers["Nonce"] = hex.EncodeToString(f.nonce)
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

		keyBox := KeyBox{}
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

	f.MAC, err = hex.DecodeString(block.Headers["MAC"])
	if err != nil {
		return n, fmt.Errorf("decoding MAC: %w", err)
	}

	f.nonce, err = hex.DecodeString(block.Headers["Nonce"])
	if err != nil {
		return n, fmt.Errorf("decoding Nonce: %w", err)
	}

	f.ciphertext = block.Bytes

	return n, nil
}

// UnsealedEncFile is an unsealed EncFile.
type UnsealedEncFile struct {
	*EncFile
	fileKey *[32]byte
}

// NewUnsealedEncFile encrypts the given content and returns a new UnsealedEncFile.
func NewUnsealedEncFile(filename string) (*UnsealedEncFile, error) {
	var fileKey [32]byte
	if _, err := rand.Read(fileKey[:]); err != nil {
		return nil, err
	}
	return &UnsealedEncFile{
		EncFile: &EncFile{Filename: filename},
		fileKey: &fileKey,
	}, nil
}

// AddPublicKey adds the given PublicKey to the EncFile.
func (f *UnsealedEncFile) AddPublicKey(pubKey *PublicKey) error {
	if f.getKeyBox(pubKey) != nil {
		return ErrAlreadyAdded
	}
	boxedKey, err := box.SealAnonymous(nil, f.fileKey[:], pubKey.key, rand.Reader)
	if err != nil {
		return fmt.Errorf("sealing file key: %w", err)
	}
	f.keyBoxes = append(f.keyBoxes, KeyBox{
		box:       boxedKey,
		PublicKey: pubKey,
	})
	return nil
}

// Encrypt encrypts the file contents.
func (f *UnsealedEncFile) Encrypt(plaintext []byte) error {
	mac := hmac.New(sha256.New, f.fileKey[:])

	// Generate a random nonce
	var nonce [24]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return fmt.Errorf("generating nonce: %w", err)
	}

	// Initialize counter from nonce
	counter := binary.LittleEndian.Uint64(nonce[:])
	var counterBytes [24]byte
	copy(counterBytes[:], nonce[:])

	var out []byte
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

		// Update counter
		binary.LittleEndian.PutUint64(counterBytes[:], counter)
		counter++

		// Encrypt the chunk
		out = secretbox.Seal(out, chunk, &counterBytes, f.fileKey)
	}

	f.MAC = mac.Sum(nil)
	f.nonce = nonce[:]
	f.ciphertext = out
	return nil
}

// Decrypt decrypts the file contents.
func (f *UnsealedEncFile) Decrypt() ([]byte, error) {
	ciphertext := f.ciphertext

	// Initialize counter from nonce
	var counter uint64
	if len(f.nonce) > 0 {
		counter = binary.LittleEndian.Uint64(f.nonce[:])
	}
	var counterBytes [24]byte
	copy(counterBytes[:], f.nonce[:])

	var out []byte
	for len(ciphertext) > 0 {
		// Get the next chunkSize+overhead-sized chunk
		chunk := ciphertext
		if len(chunk) > cipherChunkSize {
			chunk = chunk[:cipherChunkSize]
			ciphertext = ciphertext[cipherChunkSize:]
		} else {
			ciphertext = nil
		}

		// Update counter
		binary.LittleEndian.PutUint64(counterBytes[:], counter)
		counter++

		var ok bool
		out, ok = secretbox.Open(out, chunk, &counterBytes, f.fileKey)
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
