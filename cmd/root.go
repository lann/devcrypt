package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var (
	configDir  string
	label      string
	keyFlag    string
	pubkeyFlag string
)

var rootCmd = &cobra.Command{
	Use:   "devcrypt",
	Short: "Devcrypt encrypts your development secrets",
}

func init() {
	flags := rootCmd.PersistentFlags()
	flags.StringVarP(&configDir, "configDir", "C", defaultConfigDir(), "config dir")

	flags.StringVarP(&label, "label", "l", defaultLabel(), "label for key")

	flags.StringVarP(&keyFlag, "key", "k", "", "path to private key")
	flags.Lookup("key").DefValue = "<configDir>/devcrypt_key"

	flags.StringVarP(&pubkeyFlag, "pubkey", "K", "", "path to public key")
	flags.Lookup("pubkey").DefValue = "<key>.pub"

	rootCmd.AddCommand(addCmd)
	rootCmd.AddCommand(decryptCmd)
	rootCmd.AddCommand(encryptCmd)
	rootCmd.AddCommand(infoCmd)
	rootCmd.AddCommand(keygenCmd)
	rootCmd.AddCommand(removeCmd)
}

// Execute executes.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
