package internal

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

var (
	testKey = &[32]byte{
		1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
		17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32}

	testKeyBase64 = "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA="
)

func TestGenerateKeys(t *testing.T) {
	pubKey, privKey, err := GenerateKeys("testLabel")
	assert.NoError(t, err)
	assert.Equal(t, "testLabel", pubKey.Label)
	assert.Equal(t, "testLabel", privKey.Label)
}

func TestPublicKey_MarshalString(t *testing.T) {
	pubKey := &PublicKey{
		Label: "testLabel",
		key:   testKey,
	}
	expected := "devcrypt-key " + testKeyBase64 + " testLabel"
	assert.Equal(t, expected, pubKey.MarshalString())
}

func TestPublicKey_UnmarshalString(t *testing.T) {
	pubKey := &PublicKey{}
	data := "devcrypt-key " + testKeyBase64 + " testLabel"
	err := pubKey.UnmarshalString(data)
	assert.NoError(t, err)
	assert.Equal(t, "testLabel", pubKey.Label)
	assert.Equal(t, testKey, pubKey.key)
}

func TestPrivateKey_Marshal(t *testing.T) {
	privKey := &PrivateKey{
		Label: "testLabel",
		key:   testKey,
	}
	expected := []byte(
		"-----BEGIN DEVCRYPT PRIVATE KEY-----\n" +
			"Label: testLabel\n\n" +
			testKeyBase64 + "\n" +
			"-----END DEVCRYPT PRIVATE KEY-----\n")
	actual, err := privKey.Marshal()
	assert.NoError(t, err)
	assert.Equal(t, expected, actual)
}

func TestPrivateKey_Unmarshal(t *testing.T) {
	data := []byte(
		"-----BEGIN DEVCRYPT PRIVATE KEY-----\n" +
			"Label: testLabel\n\n" +
			testKeyBase64 + "\n" +
			"-----END DEVCRYPT PRIVATE KEY-----\n")
	privKey := &PrivateKey{}
	err := privKey.Unmarshal(data)
	assert.NoError(t, err)
	assert.Equal(t, "testLabel", privKey.Label)
	assert.Equal(t, testKey, privKey.key)
}
