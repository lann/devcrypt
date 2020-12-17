package cmd

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"

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

		pubKeyFiles := args[1:]
		pubKeys := make([]internal.PublicKey, len(pubKeyFiles))
		for i, pubKeyFile := range pubKeyFiles {
			data, err := ioutil.ReadFile(pubKeyFile)
			if err != nil {
				return fmt.Errorf("reading %q: %w", pubKeyFile, err)
			}
			if err := pubKeys[i].UnmarshalString(string(data)); err != nil {
				return fmt.Errorf("decoding public key from %q: %w", pubKeyFile, err)
			}
		}

		for i := range pubKeyFiles {
			pubKey := &pubKeys[i]
			fmt.Printf("Adding public key labeled %q\n", pubKey.Label)
			if err := unsealedFile.AddPublicKey(pubKey); err != nil {
				return err
			}
		}

		f, err := ioutil.TempFile(filepath.Dir(input), ".devcrypt.tmp.")
		if err != nil {
			return fmt.Errorf("opening tempfile: %w", err)
		}
		defer f.Close()

		if _, err := unsealedFile.WriteTo(f); err != nil {
			return fmt.Errorf("writing tempfile: %w", err)
		}
		if err := f.Close(); err != nil {
			return fmt.Errorf("closing tempfile: %w", err)
		}
		if err := os.Rename(f.Name(), input); err != nil {
			return fmt.Errorf("error moving tempfile %q: %w", f.Name(), err)
		}

		fmt.Printf("Updated %q\n", input)

		return nil
	},
}
