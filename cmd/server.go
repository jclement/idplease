package cmd

import (
	"embed"
	"fmt"
	"log/slog"
	"net/http"
	"os"

	"github.com/jclement/idplease/internal/config"
	cryptopkg "github.com/jclement/idplease/internal/crypto"
	"github.com/jclement/idplease/internal/oidc"
	"github.com/jclement/idplease/internal/server"
	"github.com/jclement/idplease/internal/store"
	"github.com/spf13/cobra"
)

var templates embed.FS

func SetTemplates(t embed.FS) {
	templates = t
}

var adminKeyFlag string
var adminUserFlag string
var adminPasswordFlag string

var serverCmd = &cobra.Command{
	Use:   "server",
	Short: "Run the OIDC server",
	RunE: func(cmd *cobra.Command, args []string) error {
		slog.SetDefault(slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo})))

		cfg, err := config.Load(cfgFile)
		if err != nil {
			return fmt.Errorf("load config: %w", err)
		}

		slog.Info("configuration loaded",
			"config_file", cfgFile,
			"port", cfg.Port,
			"db_file", cfg.DBFile,
			"key_file", cfg.KeyFile,
		)

		keys, err := cryptopkg.LoadOrGenerate(cfg.KeyFile)
		if err != nil {
			return fmt.Errorf("load keys: %w", err)
		}
		slog.Info("signing key loaded", "kid", keys.KeyID, "key_file", cfg.KeyFile)

		s, err := store.New(cfg.DBFile)
		if err != nil {
			return fmt.Errorf("open database: %w", err)
		}
		defer func() { _ = s.Close() }()
		slog.Info("database opened", "db_file", cfg.DBFile)

		// Load OIDC config from store (falls back to config file defaults)
		cfg.LoadFromStore(s.GetConfig, s.GetConfigStringSlice, s.GetConfigMap)

		// Bootstrap user if no users exist
		if err := bootstrapUser(s); err != nil {
			slog.Warn("bootstrap user failed", "error", err)
		}

		provider := oidc.NewProvider(cfg, keys, s)

		// Determine admin key and its source
		adminKey := adminKeyFlag
		adminKeySource := "flag"
		if adminKey == "" {
			adminKey = os.Getenv("IDPLEASE_ADMIN_KEY")
			adminKeySource = "env"
		}
		if adminKey == "" {
			adminKey = cfg.AdminKey
			adminKeySource = "config"
		}
		if adminKey == "" {
			adminKey = config.GenerateSecret()[:16]
			adminKeySource = "generated"
			slog.Info("generated admin key (use --admin-key to set a persistent one)", "key", adminKey)
		}

		srv, err := server.NewWithAdminKey(cfg, provider, s, templates, adminKey)
		if err != nil {
			return fmt.Errorf("create server: %w", err)
		}

		userCount, _ := s.UserCount()

		addr := fmt.Sprintf(":%d", cfg.Port)
		slog.Info("starting IDPlease server",
			"addr", addr,
			"issuer", cfg.Issuer,
			"base_path", cfg.NormalizedBasePath(),
			"client_ids", cfg.GetClientIDs(),
			"access_token_lifetime", cfg.GetAccessTokenLifetime(),
			"refresh_token_lifetime", cfg.GetRefreshTokenLifetime(),
			"admin_key_source", adminKeySource,
			"admin_url", cfg.Issuer+cfg.NormalizedBasePath()+"admin",
			"user_count", userCount,
		)
		return http.ListenAndServe(addr, srv.Handler())
	},
}

func bootstrapUser(s *store.Store) error {
	count, err := s.UserCount()
	if err != nil {
		return err
	}
	if count > 0 {
		return nil // users exist, skip bootstrap
	}

	username := os.Getenv("IDPLEASE_ADMIN_USER")
	if username == "" {
		username = "admin"
	}
	password := os.Getenv("IDPLEASE_ADMIN_PASSWORD")
	generated := password == ""
	if generated {
		password = config.GenerateSecret()[:16]
	}

	if err := s.AddUser(username, password, "", "Administrator"); err != nil {
		return err
	}
	if err := s.AddRole(username, "IDPlease.Admin"); err != nil {
		return err
	}

	slog.Info("bootstrap user created", "username", username)
	fmt.Println()
	fmt.Println("╔══════════════════════════════════════════════════╗")
	fmt.Println("║  First run detected! Admin user created:         ║")
	fmt.Println("╠══════════════════════════════════════════════════╣")
	fmt.Printf("║  Username: %-37s ║\n", username)
	fmt.Printf("║  Password: %-37s ║\n", password)
	fmt.Println("║  Role:     IDPlease.Admin                        ║")
	if generated {
		fmt.Println("║                                                  ║")
		fmt.Println("║  ⚠  Change this password immediately!            ║")
	}
	fmt.Println("╚══════════════════════════════════════════════════╝")
	fmt.Println()
	return nil
}

func init() {
	serverCmd.Flags().StringVar(&adminKeyFlag, "admin-key", "", "Admin key for the admin UI")
	serverCmd.Flags().StringVar(&adminUserFlag, "admin-user", "", "Bootstrap admin username (first run only)")
	serverCmd.Flags().StringVar(&adminPasswordFlag, "admin-password", "", "Bootstrap admin password (first run only)")
	rootCmd.AddCommand(serverCmd)
}
