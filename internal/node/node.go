package node

import (
	"encoding/hex"
	"fmt"
	"log"
	"net"

	"golang.org/x/crypto/curve25519"

	"github.com/PypNetty/govpn/internal/config"
	"github.com/PypNetty/govpn/internal/handshake"
	"github.com/PypNetty/govpn/internal/tun"
	"github.com/PypNetty/govpn/internal/tunnel"
)

// Node représente une instance GoVPN — server ou client.
// Il possède toutes les ressources réseau et les libère à Close().
type Node struct {
	cfg      *config.Config
	kp       *handshake.KeyPair
	tunIface *tun.Interface
	conn     *net.UDPConn
}

// New crée un Node à partir d'une config validée.
// Ouvre l'interface TUN et le socket UDP.
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
	log.Printf(">>> sudo ip addr add %s dev %s && sudo ip link set %s up",
		cfg.TUN.Address, tunIface.Name, tunIface.Name)

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

// Close libère toutes les ressources du Node.
func (n *Node) Close() {
	if n.tunIface != nil {
		n.tunIface.Close()
	}
	if n.conn != nil {
		n.conn.Close()
	}
}

// RunServer attend un handshake client puis démarre le tunnel.
func (n *Node) RunServer() error {
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

// RunClient effectue le handshake vers le serveur puis démarre le tunnel.
func (n *Node) RunClient() error {
	if len(n.cfg.Peers) == 0 {
		return fmt.Errorf("aucun peer dans la config")
	}
	peer := n.cfg.Peers[0]

	serverAddr, err := net.ResolveUDPAddr("udp4", peer.Endpoint)
	if err != nil {
		return fmt.Errorf("endpoint invalide: %w", err)
	}

	log.Printf("Handshake vers %s (%s)...", peer.Name, peer.Endpoint)
	sharedKey, err := handshake.ClientHandshake(n.conn, serverAddr, n.kp)
	if err != nil {
		return fmt.Errorf("handshake: %w", err)
	}
	log.Println("Handshake OK")

	return tunnel.Run(n.tunIface, n.conn, serverAddr, sharedKey)
}

// keypairFromHex reconstruit une KeyPair depuis la clé privée en hex.
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
