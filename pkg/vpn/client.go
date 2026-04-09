// pkg/vpn/client.go
package vpn

import (
	"github.com/PypNetty/govpn/internal/config"
	"github.com/PypNetty/govpn/internal/node"
	"github.com/spf13/cobra"
)

type clientOptions struct{ configFile string }

func ClientCmd() *cobra.Command {
	o := &clientOptions{}
	cmd := &cobra.Command{
		Use:   "client",
		Short: "Connecte au serveur VPN",
		RunE:  o.run,
	}
	cmd.Flags().StringVarP(&o.configFile, "config", "c", "govpn.yaml", "fichier de config")
	return cmd
}

func (o *clientOptions) run(cmd *cobra.Command, args []string) error {
	cfg, err := config.Load(o.configFile)
	if err != nil {
		return err
	}
	n, err := node.New(cfg)
	if err != nil {
		return err
	}
	defer n.Close()
	return n.RunClient()
}
