package cmd

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"syscall"

	"github.com/jclement/idplease/internal/config"
	"github.com/jclement/idplease/internal/store"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

var userCmd = &cobra.Command{
	Use:   "user",
	Short: "Manage users",
}

var userAddCmd = &cobra.Command{
	Use:   "add [username]",
	Short: "Add a new user",
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

		username := args[0]
		reader := bufio.NewReader(os.Stdin)

		fmt.Print("Email: ")
		email, _ := reader.ReadString('\n')
		email = strings.TrimSpace(email)

		fmt.Print("Display Name: ")
		displayName, _ := reader.ReadString('\n')
		displayName = strings.TrimSpace(displayName)

		fmt.Print("Password: ")
		passwordBytes, err := term.ReadPassword(int(syscall.Stdin))
		fmt.Println()
		if err != nil {
			return fmt.Errorf("read password: %w", err)
		}

		if err := s.AddUser(username, string(passwordBytes), email, displayName); err != nil {
			return err
		}
		fmt.Printf("User %q added successfully\n", username)
		return nil
	},
}

var userListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all users",
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := config.Load(cfgFile)
		if err != nil {
			return err
		}
		s, err := store.New(cfg.UsersFile)
		if err != nil {
			return err
		}

		users := s.ListUsers()
		if len(users) == 0 {
			fmt.Println("No users found")
			return nil
		}
		for _, u := range users {
			fmt.Printf("%-20s %-30s %s\n", u.Username, u.Email, u.DisplayName)
		}
		return nil
	},
}

var userDeleteCmd = &cobra.Command{
	Use:   "delete [username]",
	Short: "Delete a user",
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

		if err := s.DeleteUser(args[0]); err != nil {
			return err
		}
		fmt.Printf("User %q deleted\n", args[0])
		return nil
	},
}

var userResetCmd = &cobra.Command{
	Use:   "reset [username]",
	Short: "Reset user password",
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

		fmt.Print("New Password: ")
		passwordBytes, err := term.ReadPassword(int(syscall.Stdin))
		fmt.Println()
		if err != nil {
			return fmt.Errorf("read password: %w", err)
		}

		if err := s.ResetPassword(args[0], string(passwordBytes)); err != nil {
			return err
		}
		fmt.Printf("Password reset for %q\n", args[0])
		return nil
	},
}

func init() {
	userCmd.AddCommand(userAddCmd, userListCmd, userDeleteCmd, userResetCmd)
	rootCmd.AddCommand(userCmd)
}
