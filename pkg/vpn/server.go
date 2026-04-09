package vpn

import (
	"encoding/hex"
	"fmt"
	"log"
	"net"

	"github.com/spf13/cobra"

	"github.com/PypNetty/govpn/internal/config"
	"github.com/PypNetty/govpn/internal/handshake"
	"github.com/PypNetty/govpn/internal/tun"
	"github.com/PypNetty/govpn/internal/tunnel"
)

type serverOptions struct {
	configFile string
}

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

	kp, err := keypairFromConfig(cfg)
	if err != nil {
		return err
	}
	log.Printf("Clé publique: %s", hex.EncodeToString(kp.Public[:]))

	tunIface, err := tun.New(cfg.TUN.Name)
	if err != nil {
		return fmt.Errorf("TUN: %w", err)
	}
	defer tunIface.Close()
	log.Printf("TUN prête: %s", tunIface.Name)
	log.Printf(">>> sudo ip addr add %s dev %s && sudo ip link set %s up",
		cfg.TUN.Address, tunIface.Name, tunIface.Name)

	udpAddr, _ := net.ResolveUDPAddr("udp4", cfg.Listen)
	conn, err := net.ListenUDP("udp4", udpAddr)
	if err != nil {
		return fmt.Errorf("UDP: %w", err)
	}
	defer conn.Close()
	log.Printf("UDP en écoute: %s", cfg.Listen)

	var sharedKey []byte
	var peerAddr *net.UDPAddr
	for {
		log.Println("Attente du handshake client...")
		sharedKey, peerAddr, err = handshake.ServerHandshake(conn, kp)
		if err != nil {
			log.Printf("Handshake échoué (%v), retry...", err)
			continue
		}
		log.Printf("Handshake OK — peer: %s", peerAddr)
		break
	}

	return tunnel.Run(tunIface, conn, peerAddr, sharedKey)
}
