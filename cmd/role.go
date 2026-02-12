package cmd

import (
	"fmt"

	"github.com/jclement/idplease/internal/config"
	"github.com/jclement/idplease/internal/store"
	"github.com/spf13/cobra"
)

var roleCmd = &cobra.Command{
	Use:   "role",
	Short: "Manage user roles",
}

var roleAddCmd = &cobra.Command{
	Use:   "add [username] [role]",
	Short: "Add a role to a user",
	Args:  cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := config.Load(cfgFile)
		if err != nil {
			return err
		}
		s, err := store.New(cfg.UsersFile)
		if err != nil {
			return err
		}
		if err := s.AddRole(args[0], args[1]); err != nil {
			return err
		}
		fmt.Printf("Role %q added to %q\n", args[1], args[0])
		return nil
	},
}

var roleRemoveCmd = &cobra.Command{
	Use:   "remove [username] [role]",
	Short: "Remove a role from a user",
	Args:  cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := config.Load(cfgFile)
		if err != nil {
			return err
		}
		s, err := store.New(cfg.UsersFile)
		if err != nil {
			return err
		}
		if err := s.RemoveRole(args[0], args[1]); err != nil {
			return err
		}
		fmt.Printf("Role %q removed from %q\n", args[1], args[0])
		return nil
	},
}

var roleListCmd = &cobra.Command{
	Use:   "list [username]",
	Short: "List roles for a user",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := config.Load(cfgFile)
		if err != nil {
			return err
		}
		s, err := store.New(cfg.UsersFile)
		if err != nil {
			return err
		}
		roles, err := s.ListRoles(args[0])
		if err != nil {
			return err
		}
		if len(roles) == 0 {
			fmt.Printf("No roles for %q\n", args[0])
			return nil
		}
		for _, r := range roles {
			fmt.Println(r)
		}
		return nil
	},
}

func init() {
	roleCmd.AddCommand(roleAddCmd, roleRemoveCmd, roleListCmd)
	rootCmd.AddCommand(roleCmd)
}
