package cmd

import (
	"fmt"
	"io/ioutil"
	"os"
	"strings"

	"github.com/lann/devcrypt/internal"
	"github.com/spf13/cobra"
)

var (
	decryptOutput string
)

func init() {
	flags := decryptCmd.Flags()
	flags.StringVarP(&decryptOutput, "output", "o", "", "decrypted file output path")
	flags.Lookup("output").DefValue = "<input file without .devcrypt>"
}

var decryptCmd = &cobra.Command{
	Use:   "decrypt",
	Short: "Decrypt a file",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		input := args[0]
		output := decryptOutput
		if output == "" {
			suffix := ".devcrypt"
			if strings.HasSuffix(input, suffix) {
				output = strings.TrimSuffix(input, suffix)
			} else {
				return fmt.Errorf("encrypted file %q has no %s suffix; specify an --output instead", input, suffix)
			}
		}

		inFile, err := os.Open(input)
		if err != nil {
			return fmt.Errorf("opening encrypted file: %w", err)
		}
		defer inFile.Close()

		// Get user key
		privKey, err := readPrivateKey()
		if err != nil {
			return fmt.Errorf("reading private key: %w", err)
		}

		encFile := &internal.EncFile{}
		if _, err := encFile.ReadFrom(inFile); err != nil {
			return fmt.Errorf("reading encrypted file: %w", err)
		}

		unsealedFile, err := encFile.Unseal(privKey)
		if err != nil {
			return fmt.Errorf("unsealing file: %w", err)
		}

		plaintext, err := unsealedFile.Decrypt()
		if err != nil {
			return fmt.Errorf("decrypting file: %w", err)
		}

		if err := ioutil.WriteFile(output, plaintext, 0600); err != nil {
			return fmt.Errorf("writing output: %w", err)
		}

		fmt.Printf("Wrote to %q\n", output)

		return nil
	},
}
