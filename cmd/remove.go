package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

var removeCmd = &cobra.Command{
	Use:   "remove",
	Short: "Remove a public key from an encrypted file",
	Args:  cobra.MinimumNArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		input := args[0]

		encFile, err := readEncFile(input)
		if err != nil {
			return err
		}

		pubKeys := encFile.PublicKeys()
		removals := args[1:]
		for _, removal := range removals {
			var removed bool
			for _, pubKey := range pubKeys {
				var remove bool
				// TODO: add more removal formats (partial base64 key, fingerprint, index, etc)
				if b64 := pubKey.KeyBase64(); b64 == removal {
					fmt.Printf("Removing public key %q\n", b64)
					remove = true
				} else if pubKey.Label == removal {
					fmt.Printf("Removing public key by label %q:\n", pubKey.Label)
					remove = true
				}
				if remove {
					fmt.Println(pubKey.MarshalString())
					if err := encFile.RemovePublicKey(pubKey); err != nil {
						return err
					}
					fmt.Println()
					removed = true
				}
			}
			if !removed {
				return fmt.Errorf("couldn't find public key for %q", removal)
			}
		}

		if len(encFile.PublicKeys()) == 0 {
			return fmt.Errorf("refusing to remove all public keys")
		}

		if err := rewriteFile(input, encFile); err != nil {
			return err
		}

		fmt.Printf("Updated %q\n", input)

		return nil
	},
}
