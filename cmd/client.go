package cmd

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/jclement/idplease/internal/config"
	"github.com/jclement/idplease/internal/store"
	"github.com/spf13/cobra"
)

var clientCmd = &cobra.Command{
	Use:   "client",
	Short: "Manage OAuth clients",
}

var clientAddCmd = &cobra.Command{
	Use:   "add [client_id]",
	Short: "Add a new OAuth client",
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

		clientID := args[0]
		reader := bufio.NewReader(os.Stdin)

		fmt.Print("Client Name: ")
		name, _ := reader.ReadString('\n')
		name = strings.TrimSpace(name)

		fmt.Print("Confidential client? (y/n): ")
		confStr, _ := reader.ReadString('\n')
		confidential := strings.TrimSpace(strings.ToLower(confStr)) == "y"

		var secret string
		if confidential {
			fmt.Print("Client Secret: ")
			secStr, _ := reader.ReadString('\n')
			secret = strings.TrimSpace(secStr)
		}

		fmt.Print("Redirect URIs (comma-separated, or * for any): ")
		ruStr, _ := reader.ReadString('\n')
		redirectURIs := splitCSV(strings.TrimSpace(ruStr))

		fmt.Print("Allowed CORS Origins (comma-separated, leave blank for none): ")
		originStr, _ := reader.ReadString('\n')
		origins := splitCSV(strings.TrimSpace(originStr))

		grantTypes := []string{"authorization_code", "refresh_token"}
		if confidential {
			fmt.Print("Allow client_credentials? (y/n): ")
			ccStr, _ := reader.ReadString('\n')
			if strings.TrimSpace(strings.ToLower(ccStr)) == "y" {
				grantTypes = append(grantTypes, "client_credentials")
			}
		}

		if err := s.AddClient(clientID, name, secret, confidential, redirectURIs, origins, grantTypes); err != nil {
			return err
		}
		fmt.Printf("Client %q added successfully\n", clientID)
		return nil
	},
}

var clientListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all clients",
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

		clients := s.ListClients()
		if len(clients) == 0 {
			fmt.Println("No clients found")
			return nil
		}
		for _, c := range clients {
			clientType := "public"
			if c.Confidential {
				clientType = "confidential"
			}
			fmt.Printf("%-25s %-20s %-15s %-30s %s\n", c.ClientID, c.ClientName, clientType, strings.Join(c.AllowedOrigins, ","), strings.Join(c.AllowedGrantTypes, ","))
		}
		return nil
	},
}

var clientDeleteCmd = &cobra.Command{
	Use:   "delete [client_id]",
	Short: "Delete a client",
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

		if err := s.DeleteClient(args[0]); err != nil {
			return err
		}
		fmt.Printf("Client %q deleted\n", args[0])
		return nil
	},
}

func splitCSV(s string) []string {
	var result []string
	for _, p := range strings.Split(s, ",") {
		p = strings.TrimSpace(p)
		if p != "" {
			result = append(result, p)
		}
	}
	return result
}

func init() {
	clientCmd.AddCommand(clientAddCmd, clientListCmd, clientDeleteCmd)
	rootCmd.AddCommand(clientCmd)
}
