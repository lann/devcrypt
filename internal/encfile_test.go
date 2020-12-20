package internal

import (
	"bytes"
	"math/rand"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestEncFile_RoundTrip(t *testing.T) {
	unsealedFile, _, privKey := generateTestUnsealedEncFile(t)

	buf := &bytes.Buffer{}
	_, err := unsealedFile.WriteTo(buf)
	assert.NoError(t, err)

	encFile := &EncFile{}
	_, err = encFile.ReadFrom(buf)
	assert.NoError(t, err)

	unsealedFile, err = encFile.Unseal(privKey)
	assert.NoError(t, err)

	plaintext, err := unsealedFile.Decrypt()
	assert.NoError(t, err)
	assert.Equal(t, []byte("testData"), plaintext)
}

func TestEncFile_PublicKeys(t *testing.T) {
	unsealedFile, pubKey, _ := generateTestUnsealedEncFile(t)
	pubKeys := unsealedFile.PublicKeys()
	assert.Equal(t, []*PublicKey{pubKey}, pubKeys)
}

func TestEncFile_RemovePublicKey(t *testing.T) {
	unsealedFile, pubKey, _ := generateTestUnsealedEncFile(t)

	otherPubKey, _, err := GenerateKeys("otherLabel")
	assert.NoError(t, err)

	err = unsealedFile.AddPublicKey(otherPubKey)
	assert.NoError(t, err)

	err = unsealedFile.RemovePublicKey(pubKey)
	assert.NoError(t, err)

	pubKeys := unsealedFile.PublicKeys()
	assert.Equal(t, []*PublicKey{otherPubKey}, pubKeys)
}

func TestUnsealedEncFile_LargePlaintext(t *testing.T) {
	testDataLen := (chunkSize * 2) + 10
	testData := make([]byte, testDataLen)
	_, err := rand.Read(testData)
	assert.NoError(t, err)

	unsealedFile, err := NewUnsealedEncFile("testFile")
	assert.NoError(t, err)

	err = unsealedFile.Encrypt(testData)
	assert.NoError(t, err)
	assert.Equal(t, testDataLen, unsealedFile.FileSize())

	plaintext, err := unsealedFile.Decrypt()
	assert.NoError(t, err)

	assert.Equal(t, testData, plaintext)
}

func TestUnsealedEncFile_RotateFileKey(t *testing.T) {
	unsealedFile, pubKey, _ := generateTestUnsealedEncFile(t)

	origFileKey := append([]byte{}, unsealedFile.fileKey[:]...)
	origBox := unsealedFile.keyBoxes[0].box

	err := unsealedFile.RotateFileKey()
	assert.NoError(t, err)

	assert.NotEqual(t, origFileKey, unsealedFile.fileKey[:])
	assert.NotEqual(t, origBox, unsealedFile.keyBoxes[0].box)
	assert.Equal(t, pubKey, unsealedFile.keyBoxes[0].PublicKey)

	plaintext, err := unsealedFile.Decrypt()
	assert.NoError(t, err)
	assert.Equal(t, []byte("testData"), plaintext)
}

func generateTestUnsealedEncFile(t *testing.T) (*UnsealedEncFile, *PublicKey, *PrivateKey) {
	t.Helper()

	pubKey, privKey, err := GenerateKeys("testLabel")
	assert.NoError(t, err)

	unsealedFile, err := NewUnsealedEncFile("testFile")
	assert.NoError(t, err)

	err = unsealedFile.Encrypt([]byte("testData"))
	assert.NoError(t, err)

	err = unsealedFile.AddPublicKey(pubKey)
	assert.NoError(t, err)

	return unsealedFile, pubKey, privKey
}
