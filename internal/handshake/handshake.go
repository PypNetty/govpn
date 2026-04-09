package handshake

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"net"
	"time"

	"golang.org/x/crypto/curve25519"
)

const (
	// Types de messages
	MsgTypeHello = uint8(1) // client → serveur : "voici ma clé publique"
	MsgTypeAck   = uint8(2) // serveur → client : "voici la mienne"

	// Format wire : [type(1)] [pubkey(32)] [timestamp(8)]
	MsgSize = 1 + 32 + 8
)

type KeyPair struct {
	Private [32]byte
	Public  [32]byte
}

// GenerateKeyPair génère une paire de clés X25519
func GenerateKeyPair() (*KeyPair, error) {
	kp := &KeyPair{}
	if _, err := rand.Read(kp.Private[:]); err != nil {
		return nil, fmt.Errorf("génération clé privée: %w", err)
	}
	// Clamp requis par la spec Curve25519
	kp.Private[0] &= 248
	kp.Private[31] &= 127
	kp.Private[31] |= 64

	pub, err := curve25519.X25519(kp.Private[:], curve25519.Basepoint)
	if err != nil {
		return nil, fmt.Errorf("dérivation clé publique: %w", err)
	}
	copy(kp.Public[:], pub)
	return kp, nil
}

// DeriveSharedKey calcule la clé partagée ECDH puis la hash avec SHA-256
// Le hash garantit une clé uniforme utilisable directement par ChaCha20
func DeriveSharedKey(localPriv, remotePub [32]byte) ([]byte, error) {
	shared, err := curve25519.X25519(localPriv[:], remotePub[:])
	if err != nil {
		return nil, fmt.Errorf("ECDH: %w", err)
	}
	// SHA-256 pour "étirer" le secret ECDH en clé symétrique propre
	hashed := sha256.Sum256(shared)
	return hashed[:], nil
}

// Message wire pour le handshake
type HandshakeMsg struct {
	Type      uint8
	PublicKey [32]byte
	Timestamp int64 // unix nano — protection replay basique
}

func EncodeMsg(msg *HandshakeMsg) []byte {
	buf := make([]byte, MsgSize)
	buf[0] = msg.Type
	copy(buf[1:33], msg.PublicKey[:])
	binary.BigEndian.PutUint64(buf[33:], uint64(msg.Timestamp))
	return buf
}

func DecodeMsg(buf []byte) (*HandshakeMsg, error) {
	if len(buf) < MsgSize {
		return nil, fmt.Errorf("message trop court: %d bytes", len(buf))
	}
	msg := &HandshakeMsg{}
	msg.Type = buf[0]
	copy(msg.PublicKey[:], buf[1:33])
	msg.Timestamp = int64(binary.BigEndian.Uint64(buf[33:]))
	return msg, nil
}

// ServerHandshake attend un Hello, répond avec Ack, retourne la clé partagée
func ServerHandshake(conn *net.UDPConn, serverKP *KeyPair) ([]byte, *net.UDPAddr, error) {
	buf := make([]byte, MsgSize)
	conn.SetDeadline(time.Now().Add(30 * time.Second))
	defer conn.SetDeadline(time.Time{})

	n, clientAddr, err := conn.ReadFromUDP(buf)
	if err != nil {
		return nil, nil, fmt.Errorf("lecture Hello: %w", err)
	}

	msg, err := DecodeMsg(buf[:n])
	if err != nil || msg.Type != MsgTypeHello {
		return nil, nil, fmt.Errorf("Hello invalide")
	}

	// Répond avec la clé publique du serveur
	ack := &HandshakeMsg{
		Type:      MsgTypeAck,
		PublicKey: serverKP.Public,
		Timestamp: time.Now().UnixNano(),
	}
	if _, err := conn.WriteToUDP(EncodeMsg(ack), clientAddr); err != nil {
		return nil, nil, fmt.Errorf("envoi Ack: %w", err)
	}

	sharedKey, err := DeriveSharedKey(serverKP.Private, msg.PublicKey)
	if err != nil {
		return nil, nil, err
	}

	return sharedKey, clientAddr, nil
}

// ClientHandshake envoie Hello, attend Ack, retourne la clé partagée
func ClientHandshake(conn *net.UDPConn, serverAddr *net.UDPAddr, clientKP *KeyPair) ([]byte, error) {
	hello := &HandshakeMsg{
		Type:      MsgTypeHello,
		PublicKey: clientKP.Public,
		Timestamp: time.Now().UnixNano(),
	}
	if _, err := conn.WriteToUDP(EncodeMsg(hello), serverAddr); err != nil {
		return nil, fmt.Errorf("envoi Hello: %w", err)
	}

	buf := make([]byte, MsgSize)
	conn.SetDeadline(time.Now().Add(10 * time.Second))
	defer conn.SetDeadline(time.Time{})

	n, _, err := conn.ReadFromUDP(buf)
	if err != nil {
		return nil, fmt.Errorf("lecture Ack: %w", err)
	}

	msg, err := DecodeMsg(buf[:n])
	if err != nil || msg.Type != MsgTypeAck {
		return nil, fmt.Errorf("Ack invalide")
	}

	return DeriveSharedKey(clientKP.Private, msg.PublicKey)
}
