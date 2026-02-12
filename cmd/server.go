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

		s, err := store.New(cfg.UsersFile)
		if err != nil {
			return fmt.Errorf("load users: %w", err)
		}

		provider := oidc.NewProvider(cfg, keys, s)

		srv, err := server.New(cfg, provider, s, templates)
		if err != nil {
			return fmt.Errorf("create server: %w", err)
		}

		addr := fmt.Sprintf(":%d", cfg.Port)
		slog.Info("starting IDPlease server", "addr", addr, "issuer", cfg.Issuer, "basePath", cfg.NormalizedBasePath())
		return http.ListenAndServe(addr, srv.Handler())
	},
}

func init() {
	rootCmd.AddCommand(serverCmd)
}
