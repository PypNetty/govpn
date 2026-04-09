package tun

import (
	"encoding/binary"
	"fmt"
	"net"

	"github.com/songgao/water"
)

type Interface struct {
	iface *water.Interface
	Name  string
}

func New(name string) (*Interface, error) {
	cfg := water.Config{
		DeviceType: water.TUN,
		PlatformSpecificParams: water.PlatformSpecificParams{
			Name: name,
		},
	}
	iface, err := water.New(cfg)
	if err != nil {
		return nil, fmt.Errorf("création TUN: %w", err)
	}
	return &Interface{iface: iface, Name: iface.Name()}, nil
}

func (t *Interface) Read(buf []byte) (int, error) {
	return t.iface.Read(buf)
}

func (t *Interface) Write(buf []byte) (int, error) {
	return t.iface.Write(buf)
}

func (t *Interface) Close() error {
	return t.iface.Close()
}

// ParsePacket extrait les infos lisibles d'un paquet IP brut
func ParsePacket(pkt []byte) string {
	if len(pkt) < 20 {
		return fmt.Sprintf("[???] trop court (%d bytes)", len(pkt))
	}
	switch pkt[0] >> 4 {
	case 4:
		src := net.IP(pkt[12:16])
		dst := net.IP(pkt[16:20])
		totalLen := binary.BigEndian.Uint16(pkt[2:4])
		return fmt.Sprintf("[IPv4] %s → %s | proto=%s | len=%d",
			src, dst, protoString(pkt[9]), totalLen)
	case 6:
		src := net.IP(pkt[8:24])
		dst := net.IP(pkt[24:40])
		return fmt.Sprintf("[IPv6] %s → %s", src, dst)
	default:
		return fmt.Sprintf("[???] version=%d", pkt[0]>>4)
	}
}

func protoString(p byte) string {
	switch p {
	case 1:
		return "ICMP"
	case 6:
		return "TCP"
	case 17:
		return "UDP"
	default:
		return fmt.Sprintf("proto(%d)", p)
	}
}
