package tunnel

import (
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

	gocrypto "github.com/PypNetty/govpn/internal/crypto"
	"github.com/PypNetty/govpn/internal/transport"
	"github.com/PypNetty/govpn/internal/tun"
)

const MTU = 1500

// Run est la boucle principale TUN↔UDP chiffrée.
// Bloque jusqu'à SIGINT/SIGTERM.
func Run(tunIface *tun.Interface, conn *net.UDPConn, peerAddr *net.UDPAddr, sharedKey []byte) error {
	log.Printf("Clé de session: %s", hex.EncodeToString(sharedKey))

	cipher, err := gocrypto.NewCipher(sharedKey)
	if err != nil {
		return fmt.Errorf("cipher: %w", err)
	}

	udpTransport, err := transport.NewUDPTransportFromConn(conn, peerAddr)
	if err != nil {
		return fmt.Errorf("transport: %w", err)
	}

	go tunToUDP(tunIface, udpTransport, cipher)
	go udpToTun(tunIface, udpTransport, cipher)

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	log.Println("Arrêt propre.")
	return nil
}

func tunToUDP(tunIface *tun.Interface, udpTransport *transport.UDPTransport, cipher *gocrypto.Cipher) {
	buf := make([]byte, MTU)
	for {
		n, err := tunIface.Read(buf)
		if err != nil {
			log.Printf("TUN read: %v", err)
			continue
		}
		pkt := buf[:n]

		encrypted, err := cipher.Encrypt(pkt)
		if err != nil {
			log.Printf("Encrypt: %v", err)
			continue
		}

		log.Printf("TUN → UDP | %s", tun.ParsePacket(pkt))
		if err := udpTransport.Send(encrypted); err != nil {
			log.Printf("UDP send: %v", err)
		}
	}
}

func udpToTun(tunIface *tun.Interface, udpTransport *transport.UDPTransport, cipher *gocrypto.Cipher) {
	buf := make([]byte, MTU+64)
	for {
		n, addr, err := udpTransport.Recv(buf)
		if err != nil {
			log.Printf("UDP recv: %v", err)
			continue
		}

		decrypted, err := cipher.Decrypt(buf[:n])
		if err != nil {
			log.Printf("Decrypt FAILED from %s: %v", addr, err)
			continue
		}

		log.Printf("UDP → TUN | from=%s | %s", addr, tun.ParsePacket(decrypted))
		if _, err := tunIface.Write(decrypted); err != nil {
			log.Printf("TUN write: %v", err)
		}
	}
}
