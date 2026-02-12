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

var serverCmd = &cobra.Command{
	Use:   "server",
	Short: "Run the OIDC server",
	RunE: func(cmd *cobra.Command, args []string) error {
		slog.SetDefault(slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo})))

		cfg, err := config.Load(cfgFile)
		if err != nil {
			return fmt.Errorf("load config: %w", err)
		}

		keys, err := cryptopkg.LoadOrGenerate(cfg.KeyFile)
		if err != nil {
			return fmt.Errorf("load keys: %w", err)
		}

		s, err := store.New(cfg.DBFile)
		if err != nil {
			return fmt.Errorf("open database: %w", err)
		}
		defer func() { _ = s.Close() }()

		// Load OIDC config from store (falls back to config file defaults)
		cfg.LoadFromStore(s.GetConfig, s.GetConfigStringSlice, s.GetConfigMap)

		provider := oidc.NewProvider(cfg, keys, s)

		// Determine admin key
		adminKey := adminKeyFlag
		if adminKey == "" {
			adminKey = os.Getenv("IDPLEASE_ADMIN_KEY")
		}
		if adminKey == "" {
			adminKey = cfg.AdminKey
		}
		if adminKey == "" {
			adminKey = config.GenerateSecret()[:16]
			slog.Info("generated admin key (use --admin-key to set a persistent one)", "key", adminKey)
		}

		srv, err := server.NewWithAdminKey(cfg, provider, s, templates, adminKey)
		if err != nil {
			return fmt.Errorf("create server: %w", err)
		}

		addr := fmt.Sprintf(":%d", cfg.Port)
		slog.Info("starting IDPlease server", "addr", addr, "issuer", cfg.Issuer, "basePath", cfg.NormalizedBasePath())
		slog.Info("admin UI available", "url", cfg.Issuer+cfg.NormalizedBasePath()+"admin")
		return http.ListenAndServe(addr, srv.Handler())
	},
}

func init() {
	serverCmd.Flags().StringVar(&adminKeyFlag, "admin-key", "", "Admin key for the admin UI")
	rootCmd.AddCommand(serverCmd)
}
