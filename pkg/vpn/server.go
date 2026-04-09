// pkg/vpn/server.go
package vpn

import (
	"github.com/PypNetty/govpn/internal/config"
	"github.com/PypNetty/govpn/internal/node"
	"github.com/spf13/cobra"
)

type serverOptions struct{ configFile string }

func ServerCmd() *cobra.Command {
	o := &serverOptions{}
	cmd := &cobra.Command{
		Use:   "server",
		Short: "Lance le serveur VPN",
		RunE:  o.run,
	}
	cmd.Flags().StringVarP(&o.configFile, "config", "c", "govpn.yaml", "fichier de config")
	return cmd
}

func (o *serverOptions) run(cmd *cobra.Command, args []string) error {
	cfg, err := config.Load(o.configFile)
	if err != nil {
		return err
	}
	n, err := node.New(cfg)
	if err != nil {
		return err
	}
	defer n.Close()
	return n.RunServer()
}
