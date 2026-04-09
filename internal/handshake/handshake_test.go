package handshake

import (
    "bytes"
    "net"
    "testing"
)

func TestKeyPairGeneration(t *testing.T) {
    kp1, err := GenerateKeyPair()
    if err != nil {
        t.Fatal(err)
    }
    kp2, err := GenerateKeyPair()
    if err != nil {
        t.Fatal(err)
    }
    // Deux paires différentes
    if bytes.Equal(kp1.Public[:], kp2.Public[:]) {
        t.Fatal("clés publiques identiques")
    }
}

func TestSharedKeySymmetry(t *testing.T) {
    alice, _ := GenerateKeyPair()
    bob, _ := GenerateKeyPair()

    // Alice calcule avec sa privée + pubkey de Bob
    sharedA, err := DeriveSharedKey(alice.Private, bob.Public)
    if err != nil {
        t.Fatal(err)
    }

    // Bob calcule avec sa privée + pubkey d'Alice
    sharedB, err := DeriveSharedKey(bob.Private, alice.Public)
    if err != nil {
        t.Fatal(err)
    }

    // Les deux clés doivent être identiques — c'est la magie ECDH
    if !bytes.Equal(sharedA, sharedB) {
        t.Fatalf("clés divergentes\nAlice: %x\nBob:   %x", sharedA, sharedB)
    }
}

func TestFullHandshake(t *testing.T) {
    serverKP, _ := GenerateKeyPair()
    clientKP, _ := GenerateKeyPair()

    // Deux sockets UDP locaux pour simuler client/serveur
    serverConn, _ := net.ListenUDP("udp4", &net.UDPAddr{Port: 0})
    clientConn, _ := net.ListenUDP("udp4", &net.UDPAddr{Port: 0})
    defer serverConn.Close()
    defer clientConn.Close()

    serverAddr := serverConn.LocalAddr().(*net.UDPAddr)

    errCh := make(chan error, 2)
    serverKeyCh := make(chan []byte, 1)
    clientKeyCh := make(chan []byte, 1)

    go func() {
        key, _, err := ServerHandshake(serverConn, serverKP)
        if err != nil {
            errCh <- err
            return
        }
        serverKeyCh <- key
    }()

    go func() {
        key, err := ClientHandshake(clientConn, serverAddr, clientKP)
        if err != nil {
            errCh <- err
            return
        }
        clientKeyCh <- key
    }()

    var serverKey, clientKey []byte
    for i := 0; i < 2; i++ {
        select {
        case err := <-errCh:
            t.Fatal(err)
        case k := <-serverKeyCh:
            serverKey = k
        case k := <-clientKeyCh:
            clientKey = k
        }
    }

    if !bytes.Equal(serverKey, clientKey) {
        t.Fatalf("clés de session divergentes\nServeur: %x\nClient:  %x", serverKey, clientKey)
    }
}

func TestMsgEncodeDecode(t *testing.T) {
    kp, _ := GenerateKeyPair()
    original := &HandshakeMsg{
        Type:      MsgTypeHello,
        PublicKey: kp.Public,
        Timestamp: 1234567890,
    }
    encoded := EncodeMsg(original)
    decoded, err := DecodeMsg(encoded)
    if err != nil {
        t.Fatal(err)
    }
    if decoded.Type != original.Type ||
        decoded.PublicKey != original.PublicKey ||
        decoded.Timestamp != original.Timestamp {
        t.Fatal("encode/decode mismatch")
    }
}