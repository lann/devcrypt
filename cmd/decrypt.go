package cmd

import (
	"fmt"
	"io/ioutil"
	"strings"

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

		// Read and unseal encryped file
		unsealedFile, err := unsealFile(input)
		if err != nil {
			return err
		}

		// Get user key
		plaintext, err := unsealedFile.Decrypt()
		if err != nil {
			return fmt.Errorf("decrypting file: %w", err)
		}

		// Write decrypted file
		if err := ioutil.WriteFile(output, plaintext, 0600); err != nil {
			return fmt.Errorf("writing output: %w", err)
		}

		fmt.Printf("Decrypted to %q\n", output)

		return nil
	},
}
