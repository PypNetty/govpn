package crypto

import (
	"bytes"
	"testing"
)

func TestEncryptDecrypt(t *testing.T) {
	key, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}

	cipher, err := NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}

	// Simule un paquet IP ICMP minimal
	original := []byte{
		0x45, 0x00, 0x00, 0x54, // IPv4, IHL=20, len=84
		0x00, 0x00, 0x40, 0x00, // flags, TTL=64
		0x01,        // proto ICMP
		0x00,        // checksum placeholder
		10, 0, 0, 1, // src 10.0.0.1
		10, 0, 0, 2, // dst 10.0.0.2
	}

	encrypted, err := cipher.Encrypt(original)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	// Deux chiffrements du même plaintext → résultats différents (nonce aléatoire)
	encrypted2, _ := cipher.Encrypt(original)
	if bytes.Equal(encrypted, encrypted2) {
		t.Fatal("Nonces identiques — problème de randomness")
	}

	decrypted, err := cipher.Decrypt(encrypted)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}

	if !bytes.Equal(original, decrypted) {
		t.Fatalf("Données corrompues\noriginal:  %x\ndécrypté: %x", original, decrypted)
	}
}

func TestDecryptTamperedData(t *testing.T) {
	key, _ := GenerateKey()
	cipher, _ := NewCipher(key)

	encrypted, _ := cipher.Encrypt([]byte("paquet test"))

	// Altère un byte au milieu
	encrypted[len(encrypted)/2] ^= 0xFF

	_, err := cipher.Decrypt(encrypted)
	if err == nil {
		t.Fatal("Aurait dû rejeter les données altérées")
	}
}
