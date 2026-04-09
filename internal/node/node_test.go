package node

import (
	"encoding/hex"
	"testing"

	"github.com/PypNetty/govpn/internal/config"
	"github.com/PypNetty/govpn/internal/handshake"
)

func TestKeypairFromHex(t *testing.T) {
	kp, err := handshake.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	hexPriv := hex.EncodeToString(kp.Private[:])

	recovered, err := keypairFromHex(hexPriv)
	if err != nil {
		t.Fatalf("keypairFromHex: %v", err)
	}
	if recovered.Private != kp.Private {
		t.Fatal("clé privée différente après aller-retour hex")
	}
	if recovered.Public != kp.Public {
		t.Fatal("clé publique différente après aller-retour hex")
	}
}

func TestNewNodeInvalidKey(t *testing.T) {
	cfg := &config.Config{
		PrivateKey: "invalide",
		Listen:     "0.0.0.0:59999",
	}
	cfg.TUN.Name = "govpn-test"
	cfg.TUN.Address = "10.99.0.1/24"

	_, err := New(cfg)
	if err == nil {
		t.Fatal("aurait dû échouer avec une clé invalide")
	}
}
