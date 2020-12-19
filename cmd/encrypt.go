package cmd

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"os"

	"github.com/lann/devcrypt/internal"
	"github.com/spf13/cobra"
)

var (
	encryptOutput string
)

func init() {
	flags := encryptCmd.Flags()
	flags.StringVarP(&encryptOutput, "output", "o", "", "encrypted file output path")
	flags.Lookup("output").DefValue = "<input file>.devcrypt"
}

var encryptCmd = &cobra.Command{
	Use:   "encrypt",
	Short: "Encrypt a file",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		// Get user keys
		pubKey, err := readUserPublicKey()
		if err != nil {
			return fmt.Errorf("reading public key: %w", err)
		}

		// Check for existing encrypted file
		input := args[0]
		output := encryptOutput
		if output == "" {
			output = input + ".devcrypt"
		}

		unsealedFile, err := unsealFile(output)
		if os.IsNotExist(err) {
			// Initialize new encrypted file
			unsealedFile, err = internal.NewUnsealedEncFile(input)
			if err != nil {
				return fmt.Errorf("initing unsealed file: %w", err)
			}
			// Add user's pubkey to the encrypted file
			if err := unsealedFile.AddPublicKey(pubKey); err != nil {
				return fmt.Errorf("adding public key: %w", err)
			}
		} else if err != nil {
			return fmt.Errorf("unsealing existing file: %w", err)
		}
		existingMAC := unsealedFile.MAC

		// Read plaintext
		data, err := ioutil.ReadFile(input)
		if err != nil {
			return fmt.Errorf("reading file: %w", err)
		}

		// Encrypt file
		unsealedFile.Encrypt(data)
		if err != nil {
			return fmt.Errorf("encrypting file: %w", err)
		}

		if bytes.Equal(unsealedFile.MAC, existingMAC) {
			fmt.Printf("No change to %q\n", output)
			return nil
		}

		// Write encrypted file
		f, err := os.Create(output)
		if err != nil {
			return fmt.Errorf("creating output file: %w", err)
		}
		defer f.Close()
		if _, err := unsealedFile.WriteTo(f); err != nil {
			return fmt.Errorf("writing outout: %w", err)
		}

		fmt.Printf("Encrypted to %q\n", output)

		return nil
	},
}
