package cmd

import (
	"fmt"
	"io/ioutil"
	"os"
	"os/user"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/lann/devcrypt/internal"
)

const (
	defaultKeyFileName = "devcrypt_key"
)

var (
	keygenForce bool
)

func init() {
	flags := keygenCmd.Flags()

	flags.BoolVarP(&keygenForce, "force", "f", false, "overwrite existing key")
}

var keygenCmd = &cobra.Command{
	Use:   "keygen",
	Short: "Generate a new key",
	RunE: func(cmd *cobra.Command, args []string) error {
		pubKeyPath, privKeyPath, err := getKeyPaths()
		if err != nil {
			return err
		}

		if !keygenForce {
			if _, err := os.Stat(privKeyPath); !os.IsNotExist(err) {
				return fmt.Errorf("key file %q already exists; --force to replace it", privKeyPath)
			}
		}

		// Create configDir if needed.
		keyDir := filepath.Dir(privKeyPath)
		if _, err := os.Stat(keyDir); os.IsNotExist(err) {
			if keyDir == defaultConfigDir() {
				if err := os.Mkdir(keyDir, 0700); err != nil {
					return fmt.Errorf("creating config dir %q failed: %w", keyDir, err)
				}
			}
		}

		fmt.Printf("Generating key with label %q...\n", label)
		pubKey, privKey, err := internal.GenerateKeys(label)
		if err != nil {
			return fmt.Errorf("key generation failed: %w", err)
		}

		// Write private key
		privKeyEnc, err := privKey.Marshal()
		if err != nil {
			return fmt.Errorf("private key encoding failed: %w", err)
		}
		if err := ioutil.WriteFile(privKeyPath, privKeyEnc, 0600); err != nil {
			return fmt.Errorf("private key writing failed: %w", err)
		}
		fmt.Printf("Wrote private key to %q\n", privKeyPath)

		// Write public key
		pubKeyEnc := pubKey.MarshalString()
		if err := ioutil.WriteFile(pubKeyPath, []byte(pubKeyEnc), 0644); err != nil {
			return fmt.Errorf("public key writing failed: %w", err)
		}
		fmt.Printf("Wrote public key to %q\n", pubKeyPath)
		fmt.Printf("Public key:\n%s\n", pubKeyEnc)
		return nil
	},
}

func defaultLabel() string {
	label := ""
	if u, err := user.Current(); err == nil {
		label += u.Username
		if hostname, err := os.Hostname(); err == nil {
			label += "@" + hostname
		}
	}
	return label
}
