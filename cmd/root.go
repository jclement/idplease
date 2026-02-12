package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var cfgFile string

var rootCmd = &cobra.Command{
	Use:   "idplease",
	Short: "🪪 IDPlease — A tiny OIDC Identity Provider",
	Long:  "IDPlease is a lightweight, single-binary OIDC Identity Provider for development and pilot deployments.",
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func init() {
	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "idplease.json", "config file path")
}
