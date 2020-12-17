package cmd

import (
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
		pubKey, err := readPublicKey()
		if err != nil {
			return fmt.Errorf("reading public key: %w", err)
		}

		// Read plaintext
		input := args[0]
		data, err := ioutil.ReadFile(input)
		if err != nil {
			return fmt.Errorf("reading file: %w", err)
		}

		// Encrypt file
		encFile, err := internal.NewUnsealedEncFile(input, data)
		if err != nil {
			return fmt.Errorf("encrypting file: %w", err)
		}

		// Add user's pubkey to the encrypted file
		if err := encFile.AddPublicKey(pubKey); err != nil {
			return fmt.Errorf("adding public key: %w", err)
		}

		// Write encrypted file
		output := encryptOutput
		if output == "" {
			output = input + ".devcrypt"
		}
		f, err := os.Create(output)
		if err != nil {
			return fmt.Errorf("creating output file: %w", err)
		}
		defer f.Close()
		if _, err := encFile.WriteTo(f); err != nil {
			return fmt.Errorf("writing outout: %w", err)
		}

		return nil
	},
}
