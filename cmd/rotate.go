package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

var rotateCmd = &cobra.Command{
	Use:   "rotate",
	Short: "Rotate an encrypted file's file key",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		input := args[0]

		// Read and unseal encryped file
		unsealedFile, err := unsealFile(input)
		if err != nil {
			return err
		}

		if err := unsealedFile.RotateFileKey(); err != nil {
			return fmt.Errorf("rotating file key: %w", err)
		}

		if err := rewriteFile(input, unsealedFile); err != nil {
			return err
		}

		fmt.Printf("Updated %q\n", input)

		return nil
	},
}
