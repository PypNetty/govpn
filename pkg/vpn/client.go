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

type clientOptions struct {
	configFile string
}

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
	if len(cfg.Peers) == 0 {
		return fmt.Errorf("aucun peer dans la config")
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

	peer := cfg.Peers[0]
	serverAddr, err := net.ResolveUDPAddr("udp4", peer.Endpoint)
	if err != nil {
		return fmt.Errorf("endpoint invalide: %w", err)
	}

	log.Printf("Handshake vers %s (%s)...", peer.Name, peer.Endpoint)
	sharedKey, err := handshake.ClientHandshake(conn, serverAddr, kp)
	if err != nil {
		return fmt.Errorf("handshake: %w", err)
	}
	log.Println("Handshake OK")

	return tunnel.Run(tunIface, conn, serverAddr, sharedKey)
}
