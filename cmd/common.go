package cmd

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"

	"github.com/lann/devcrypt/internal"
)

func unsealFile(path string) (*internal.UnsealedEncFile, error) {
	privKey, err := readPrivateKey()
	if err != nil {
		return nil, fmt.Errorf("reading private key: %w", err)
	}

	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("opening encrypted file: %w", err)
	}
	defer f.Close()

	encFile := &internal.EncFile{}
	if _, err := encFile.ReadFrom(f); err != nil {
		return nil, fmt.Errorf("reading encrypted file: %w", err)
	}

	unsealedFile, err := encFile.Unseal(privKey)
	if err != nil {
		return nil, fmt.Errorf("unsealing file: %w", err)
	}
	return unsealedFile, nil
}

func defaultConfigDir() string {
	// e.g. ~/.config/devcrypt/
	if userConfigDir, err := os.UserConfigDir(); err == nil {
		return filepath.Join(userConfigDir, "devcrypt")
	}
	// e.g. ~/.devcrypt
	if homeDir, err := os.UserHomeDir(); err == nil {
		return filepath.Join(homeDir, ".devcrypt")
	}
	return ""
}

func getKeyPaths() (pubKeyPath, privKeyPath string, err error) {
	if keyFlag != "" {
		privKeyPath = keyFlag
	} else if configDir == "" {
		err = fmt.Errorf("couldn't find a good home for your key; specify --key or --configDir")
		return
	} else {
		privKeyPath = filepath.Join(configDir, defaultKeyFileName)
	}

	if pubkeyFlag != "" {
		pubKeyPath = pubkeyFlag
	} else {
		pubKeyPath = privKeyPath + ".pub"
	}

	return pubKeyPath, privKeyPath, nil
}

func readPublicKey() (*internal.PublicKey, error) {
	path, _, err := getKeyPaths()
	if err != nil {
		return nil, err
	}

	data, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}

	pubKey := &internal.PublicKey{}
	if err := pubKey.UnmarshalString(string(data)); err != nil {
		return nil, err
	}
	return pubKey, nil
}

func readPrivateKey() (*internal.PrivateKey, error) {
	_, path, err := getKeyPaths()
	if err != nil {
		return nil, err
	}

	data, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}

	privKey := &internal.PrivateKey{}
	if err := privKey.Unmarshal(data); err != nil {
		return nil, err
	}
	return privKey, nil
}
