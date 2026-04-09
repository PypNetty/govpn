package node

import (
	"encoding/hex"
	"fmt"
	"log"
	"net"

	"golang.org/x/crypto/curve25519"

	"github.com/PypNetty/govpn/internal/config"
	"github.com/PypNetty/govpn/internal/handshake"
	"github.com/PypNetty/govpn/internal/routing"
	"github.com/PypNetty/govpn/internal/tun"
	"github.com/PypNetty/govpn/internal/tunnel"
)

type Node struct {
	cfg      *config.Config
	kp       *handshake.KeyPair
	tunIface *tun.Interface
	conn     *net.UDPConn
}

func New(cfg *config.Config) (*Node, error) {
	kp, err := keypairFromHex(cfg.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("keypair: %w", err)
	}
	log.Printf("Clé publique: %s", hex.EncodeToString(kp.Public[:]))

	tunIface, err := tun.New(cfg.TUN.Name)
	if err != nil {
		return nil, fmt.Errorf("TUN: %w", err)
	}
	log.Printf("TUN prête: %s", tunIface.Name)

	if err := routing.AddAddr(tunIface.Name, cfg.TUN.Address); err != nil {
		tunIface.Close()
		return nil, fmt.Errorf("configuration TUN: %w", err)
	}

	udpAddr, err := net.ResolveUDPAddr("udp4", cfg.Listen)
	if err != nil {
		tunIface.Close()
		return nil, fmt.Errorf("resolve UDP: %w", err)
	}
	conn, err := net.ListenUDP("udp4", udpAddr)
	if err != nil {
		tunIface.Close()
		return nil, fmt.Errorf("UDP listen: %w", err)
	}
	log.Printf("UDP en écoute: %s", cfg.Listen)

	return &Node{
		cfg:      cfg,
		kp:       kp,
		tunIface: tunIface,
		conn:     conn,
	}, nil
}

func (n *Node) Close() {
	if n.tunIface != nil {
		n.tunIface.Close()
	}
	if n.conn != nil {
		n.conn.Close()
	}
}

func (n *Node) RunServer() error {
	if n.cfg.OutIface != "" {
		cleanup, err := routing.SetupServer(routing.ServerConfig{
			TUNName:  n.cfg.TUN.Name,
			OutIface: n.cfg.OutIface,
		})
		if err != nil {
			return fmt.Errorf("routing serveur: %w", err)
		}
		defer cleanup()
		log.Printf("NAT activé via %s", n.cfg.OutIface)
	} else {
		log.Println("Mode sans NAT")
	}

	var (
		sharedKey []byte
		peerAddr  *net.UDPAddr
		err       error
	)
	for {
		log.Println("Attente du handshake client...")
		sharedKey, peerAddr, err = handshake.ServerHandshake(n.conn, n.kp)
		if err != nil {
			log.Printf("Handshake échoué (%v), retry...", err)
			continue
		}
		log.Printf("Handshake OK — peer: %s", peerAddr)
		break
	}
	return tunnel.Run(n.tunIface, n.conn, peerAddr, sharedKey)
}

func (n *Node) RunClient() error {
	if len(n.cfg.Peers) == 0 {
		return fmt.Errorf("aucun peer dans la config")
	}
	peer := n.cfg.Peers[0]

	serverAddr, err := net.ResolveUDPAddr("udp4", peer.Endpoint)
	if err != nil {
		return fmt.Errorf("endpoint invalide: %w", err)
	}

	defaultGW, defaultIface, err := routing.GetDefaultRoute()
	if err != nil {
		log.Println("Pas de route par défaut — mode test, routing ignoré")
	} else {
		cleanup, err := routing.SetupClient(routing.ClientConfig{
			TUNName:      n.cfg.TUN.Name,
			ServerReal:   serverAddr.IP.String(),
			DefaultGW:    defaultGW,
			DefaultIface: defaultIface,
		})
		if err != nil {
			log.Printf("Warning routing client: %v — on continue sans", err)
		} else {
			defer cleanup()
		}
	}

	log.Printf("Handshake vers %s (%s)...", peer.Name, peer.Endpoint)
	sharedKey, err := handshake.ClientHandshake(n.conn, serverAddr, n.kp)
	if err != nil {
		return fmt.Errorf("handshake: %w", err)
	}
	log.Println("Handshake OK")

	return tunnel.Run(n.tunIface, n.conn, serverAddr, sharedKey)
}

func keypairFromHex(privHex string) (*handshake.KeyPair, error) {
	privBytes, err := hex.DecodeString(privHex)
	if err != nil || len(privBytes) != 32 {
		return nil, fmt.Errorf("private_key invalide")
	}
	kp := &handshake.KeyPair{}
	copy(kp.Private[:], privBytes)

	pub, err := curve25519.X25519(kp.Private[:], curve25519.Basepoint)
	if err != nil {
		return nil, fmt.Errorf("dérivation clé publique: %w", err)
	}
	copy(kp.Public[:], pub)
	return kp, nil
}
