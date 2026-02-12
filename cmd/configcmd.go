package cmd

import (
	"fmt"

	"github.com/jclement/idplease/internal/config"
	"github.com/jclement/idplease/internal/store"
	"github.com/spf13/cobra"
)

var configCmd = &cobra.Command{
	Use:   "config",
	Short: "Manage configuration",
}

var configSetCmd = &cobra.Command{
	Use:   "set [key] [value]",
	Short: "Set a configuration value",
	Args:  cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := config.Load(cfgFile)
		if err != nil {
			return err
		}
		s, err := store.New(cfg.DBFile)
		if err != nil {
			return err
		}
		defer func() { _ = s.Close() }()
		if err := s.SetConfig(args[0], args[1]); err != nil {
			return err
		}
		fmt.Printf("Config %q set to %q\n", args[0], args[1])
		return nil
	},
}

var configGetCmd = &cobra.Command{
	Use:   "get [key]",
	Short: "Get a configuration value",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := config.Load(cfgFile)
		if err != nil {
			return err
		}
		s, err := store.New(cfg.DBFile)
		if err != nil {
			return err
		}
		defer func() { _ = s.Close() }()
		val, err := s.GetConfig(args[0])
		if err != nil {
			return fmt.Errorf("key %q not found", args[0])
		}
		fmt.Println(val)
		return nil
	},
}

var configListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all configuration values",
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := config.Load(cfgFile)
		if err != nil {
			return err
		}
		s, err := store.New(cfg.DBFile)
		if err != nil {
			return err
		}
		defer func() { _ = s.Close() }()
		all, err := s.GetAllConfig()
		if err != nil {
			return err
		}
		if len(all) == 0 {
			fmt.Println("No configuration values set")
			return nil
		}
		for k, v := range all {
			fmt.Printf("%-20s %s\n", k, v)
		}
		return nil
	},
}

func init() {
	configCmd.AddCommand(configSetCmd, configGetCmd, configListCmd)
	rootCmd.AddCommand(configCmd)
}
