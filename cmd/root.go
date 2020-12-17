package cmd

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"

	"github.com/lann/devcrypt/internal"
	"github.com/spf13/cobra"
)

var (
	configDir  string
	label      string
	keyFlag    string
	pubkeyFlag string
)

var rootCmd = &cobra.Command{
	Use:   "devcrypt",
	Short: "Devcrypt encrypts your development secrets",
}

func init() {
	flags := rootCmd.PersistentFlags()
	flags.StringVarP(&configDir, "configDir", "C", defaultConfigDir(), "config dir")

	flags.StringVarP(&label, "label", "l", defaultLabel(), "label for key")

	flags.StringVarP(&keyFlag, "key", "k", "", "path to private key")
	flags.Lookup("key").DefValue = "<configDir>/devcrypt_key"

	flags.StringVarP(&pubkeyFlag, "pubkey", "K", "", "path to public key")
	flags.Lookup("pubkey").DefValue = "<key>.pub"

	rootCmd.AddCommand(decryptCmd)
	rootCmd.AddCommand(encryptCmd)
	rootCmd.AddCommand(keygenCmd)
}

// Execute executes.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
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
