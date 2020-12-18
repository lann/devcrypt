package cmd

import (
	"fmt"
	"path/filepath"

	"github.com/spf13/cobra"
)

var infoCmd = &cobra.Command{
	Use:   "info",
	Short: "Show information about an encrypted file",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		input := args[0]

		encFile, err := readEncFile(input)
		if err != nil {
			return err
		}

		fmt.Printf("File %q:\n", filepath.Base(input))
		fmt.Printf("  Original filename: %q\n", encFile.Filename)
		fmt.Printf("  Plaintext size: %d\n", encFile.FileSize())
		fmt.Println()

		fmt.Println("Public Keys:")
		for _, pubKey := range encFile.PublicKeys() {
			fmt.Println(pubKey.MarshalString())
		}

		return nil
	},
}
