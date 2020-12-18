package cmd

import (
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"

	"github.com/lann/devcrypt/internal"
)

func readEncFile(path string) (*internal.EncFile, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("opening encrypted file: %w", err)
	}
	defer f.Close()

	encFile := &internal.EncFile{}
	if _, err := encFile.ReadFrom(f); err != nil {
		return nil, fmt.Errorf("reading encrypted file: %w", err)
	}
	return encFile, err
}

func unsealFile(path string) (*internal.UnsealedEncFile, error) {
	privKey, err := readUserPrivateKey()
	if err != nil {
		return nil, fmt.Errorf("reading private key: %w", err)
	}

	encFile, err := readEncFile(path)
	if err != nil {
		return nil, err
	}

	unsealedFile, err := encFile.Unseal(privKey)
	if err != nil {
		return nil, fmt.Errorf("unsealing file: %w", err)
	}
	return unsealedFile, nil
}

func rewriteFile(path string, wt io.WriterTo) error {
	base := filepath.Base(path)
	tmpPattern := fmt.Sprintf(".%s.*.tmp", base)
	f, err := ioutil.TempFile(filepath.Dir(path), tmpPattern)
	if err != nil {
		return fmt.Errorf("opening tempfile: %w", err)
	}
	defer f.Close()

	if _, err := wt.WriteTo(f); err != nil {
		return fmt.Errorf("writing tempfile: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("closing tempfile: %w", err)
	}
	if err := os.Rename(f.Name(), path); err != nil {
		return fmt.Errorf("error moving tempfile %q: %w", f.Name(), err)
	}
	return nil
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

func getUserKeyPaths() (pubKeyPath, privKeyPath string, err error) {
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

func readUserPublicKey() (*internal.PublicKey, error) {
	path, _, err := getUserKeyPaths()
	if err != nil {
		return nil, err
	}
	return readPublicKey(path)
}

func readPublicKey(path string) (*internal.PublicKey, error) {
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

func readUserPrivateKey() (*internal.PrivateKey, error) {
	_, path, err := getUserKeyPaths()
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
