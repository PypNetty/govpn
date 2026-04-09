package crypto

import (
	"crypto/rand"
	"fmt"

	"golang.org/x/crypto/chacha20poly1305"
)

const KeySize = chacha20poly1305.KeySize // 32 bytes

type Cipher struct {
	aead interface {
		Seal(dst, nonce, plaintext, additionalData []byte) []byte
		Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error)
		NonceSize() int
		Overhead() int
	}
}

func NewCipher(key []byte) (*Cipher, error) {
	if len(key) != KeySize {
		return nil, fmt.Errorf("clé invalide: %d bytes, attendu %d", len(key), KeySize)
	}
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, fmt.Errorf("init ChaCha20-Poly1305: %w", err)
	}
	return &Cipher{aead: aead}, nil
}

// GenerateKey génère une clé aléatoire 32 bytes
func GenerateKey() ([]byte, error) {
	key := make([]byte, KeySize)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("génération clé: %w", err)
	}
	return key, nil
}

// Encrypt chiffre plaintext et préfixe le nonce dans le résultat
// Format: [nonce (12 bytes)] [ciphertext + tag (len+16 bytes)]
func (c *Cipher) Encrypt(plaintext []byte) ([]byte, error) {
	nonce := make([]byte, c.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("génération nonce: %w", err)
	}

	// Seal appende le ciphertext à dst — on passe nonce comme dst
	// pour avoir [nonce | ciphertext | tag] contigu en mémoire
	ciphertext := c.aead.Seal(nonce, nonce, plaintext, nil)
	return ciphertext, nil
}

// Decrypt extrait le nonce et déchiffre
func (c *Cipher) Decrypt(data []byte) ([]byte, error) {
	nonceSize := c.aead.NonceSize()
	if len(data) < nonceSize+c.aead.Overhead() {
		return nil, fmt.Errorf("données trop courtes: %d bytes", len(data))
	}

	nonce := data[:nonceSize]
	ciphertext := data[nonceSize:]

	plaintext, err := c.aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("déchiffrement: %w", err)
	}
	return plaintext, nil
}
