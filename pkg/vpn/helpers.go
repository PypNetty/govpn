package vpn

import (
	"encoding/hex"
	"fmt"

	"golang.org/x/crypto/curve25519"

	"github.com/PypNetty/govpn/internal/config"
	"github.com/PypNetty/govpn/internal/handshake"
)

func keypairFromConfig(cfg *config.Config) (*handshake.KeyPair, error) {
	privBytes, err := hex.DecodeString(cfg.PrivateKey)
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
