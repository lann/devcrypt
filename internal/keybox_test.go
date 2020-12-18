package internal

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

var (
	testBox       = []byte{1, 2, 3, 4}
	testBoxBase64 = "AQIDBA=="
)

func TestKeyBox_MarshalString(t *testing.T) {
	box := &KeyBox{
		PublicKey: &PublicKey{
			Label: "testLabel",
			key:   testKey,
		},
		box: testBox,
	}
	expected := "devcrypt-keybox " + testBoxBase64 + " " + testKeyBase64 + " testLabel"
	assert.Equal(t, expected, box.MarshalString())
}

func TestKeyBox_UnmarshalString(t *testing.T) {
	box := &KeyBox{}
	data := "devcrypt-keybox " + testBoxBase64 + " " + testKeyBase64 + " testLabel"
	err := box.UnmarshalString(data)
	assert.NoError(t, err)
	assert.Equal(t, "testLabel", box.Label)
	assert.Equal(t, testKey, box.key)
	assert.Equal(t, testBox, box.box)
}
