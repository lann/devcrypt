package cmd

import (
	"fmt"

	"github.com/lann/devcrypt/internal"
	"github.com/spf13/cobra"
)

var addCmd = &cobra.Command{
	Use:   "add",
	Short: "Add a public key to an encrypted file",
	Args:  cobra.MinimumNArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		input := args[0]

		unsealedFile, err := unsealFile(input)
		if err != nil {
			return err
		}

		pubKeyPaths := args[1:]
		pubKeys := make([]*internal.PublicKey, len(pubKeyPaths))
		for i, pubKeyPath := range pubKeyPaths {
			pubKeys[i], err = readPublicKey(pubKeyPath)
			if err != nil {
				return fmt.Errorf("reading public key %q: %w", pubKeyPath, err)
			}
		}

		for i := range pubKeys {
			pubKey := pubKeys[i]
			fmt.Printf("Adding public key labeled %q\n", pubKey.Label)
			if err := unsealedFile.AddPublicKey(pubKey); err != nil {
				return err
			}
		}

		if err := rewriteFile(input, unsealedFile); err != nil {
			return err
		}

		fmt.Printf("Updated %q\n", input)

		return nil
	},
}
