package transport

import (
	"fmt"
	"net"
)

// Peer représente un endpoint distant
type Peer struct {
	Addr *net.UDPAddr
}

type UDPTransport struct {
	conn  *net.UDPConn
	peers map[string]*Peer // clé : "ip:port"
}

func NewUDPTransport(listenAddr string) (*UDPTransport, error) {
	addr, err := net.ResolveUDPAddr("udp4", listenAddr)
	if err != nil {
		return nil, fmt.Errorf("résolution adresse: %w", err)
	}

	conn, err := net.ListenUDP("udp4", addr)
	if err != nil {
		return nil, fmt.Errorf("listen UDP: %w", err)
	}

	return &UDPTransport{
		conn:  conn,
		peers: make(map[string]*Peer),
	}, nil
}

func (t *UDPTransport) AddPeer(addr string) error {
	udpAddr, err := net.ResolveUDPAddr("udp4", addr)
	if err != nil {
		return fmt.Errorf("résolution peer: %w", err)
	}
	t.peers[addr] = &Peer{Addr: udpAddr}
	return nil
}

// Send envoie des données brutes à tous les peers connus
func (t *UDPTransport) Send(data []byte) error {
	for _, peer := range t.peers {
		_, err := t.conn.WriteToUDP(data, peer.Addr)
		if err != nil {
			return fmt.Errorf("envoi vers %s: %w", peer.Addr, err)
		}
	}
	return nil
}

// Recv bloque jusqu'à réception d'un paquet UDP
// Retourne les données et l'adresse source
func (t *UDPTransport) Recv(buf []byte) (int, *net.UDPAddr, error) {
	n, addr, err := t.conn.ReadFromUDP(buf)
	if err != nil {
		return 0, nil, fmt.Errorf("réception UDP: %w", err)
	}
	return n, addr, nil
}

func (t *UDPTransport) Close() error {
	return t.conn.Close()
}

func (t *UDPTransport) LocalAddr() string {
	return t.conn.LocalAddr().String()
}

// internal/transport/udp.go — ajoute cette fonction
func NewUDPTransportFromConn(conn *net.UDPConn, peer *net.UDPAddr) (*UDPTransport, error) {
	t := &UDPTransport{
		conn:  conn,
		peers: make(map[string]*Peer),
	}
	t.peers[peer.String()] = &Peer{Addr: peer}
	return t, nil
}
