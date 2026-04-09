package routing

import (
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"

	"github.com/vishvananda/netlink"
)

type ServerConfig struct {
	TUNName  string
	TUNAddr  string
	OutIface string
}

type ClientConfig struct {
	TUNName    string
	TUNAddr    string
	ServerReal string
}

// SetupServer active l'IP forwarding et configure le NAT.
// AddAddr est appelé dans node.New() — pas ici.
func SetupServer(cfg ServerConfig) (func(), error) {
	if err := enableForwarding(); err != nil {
		return nil, fmt.Errorf("ip forwarding: %w", err)
	}
	log.Println("IP forwarding activé")

	if err := addNAT(cfg.TUNName, cfg.OutIface); err != nil {
		return nil, fmt.Errorf("NAT: %w", err)
	}
	log.Printf("NAT activé: %s → %s", cfg.TUNName, cfg.OutIface)

	cleanup := func() {
		removeNAT(cfg.TUNName, cfg.OutIface)
		log.Println("NAT supprimé")
	}
	return cleanup, nil
}

// SetupClient route tout le trafic via le TUN.
// AddAddr est appelé dans node.New() — pas ici.
func SetupClient(cfg ClientConfig) (func(), error) {
	defaultGW, defaultIface, err := getDefaultRoute()
	if err != nil {
		return nil, fmt.Errorf("lecture route défaut: %w", err)
	}
	log.Printf("Route défaut sauvegardée: via %s dev %s", defaultGW, defaultIface)

	if cfg.ServerReal != "" {
		if err := addHostRoute(cfg.ServerReal, defaultGW, defaultIface); err != nil {
			log.Printf("Warning: route serveur réel: %v", err)
		}
	}

	if err := addDefaultRoute(cfg.TUNName); err != nil {
		return nil, fmt.Errorf("route défaut via TUN: %w", err)
	}
	log.Printf("Tout le trafic routé via %s", cfg.TUNName)

	cleanup := func() {
		removeDefaultRoute(cfg.TUNName)
		if defaultGW != "" {
			restoreDefaultRoute(defaultGW, defaultIface)
			log.Printf("Route défaut restaurée: via %s dev %s", defaultGW, defaultIface)
		}
		if cfg.ServerReal != "" {
			removeHostRoute(cfg.ServerReal)
		}
	}
	return cleanup, nil
}

// AddAddr configure l'IP et monte l'interface TUN.
// Exporté — appelé par node.New() dès la création du TUN.
func AddAddr(ifaceName, cidr string) error {
	link, err := netlink.LinkByName(ifaceName)
	if err != nil {
		return fmt.Errorf("interface %s introuvable: %w", ifaceName, err)
	}

	addr, err := netlink.ParseAddr(cidr)
	if err != nil {
		return fmt.Errorf("adresse invalide %s: %w", cidr, err)
	}

	if err := netlink.AddrAdd(link, addr); err != nil {
		if err.Error() != "file exists" {
			return fmt.Errorf("AddrAdd %s sur %s: %w", cidr, ifaceName, err)
		}
		log.Printf("Adresse %s déjà présente sur %s", cidr, ifaceName)
	}

	if err := netlink.LinkSetUp(link); err != nil {
		return fmt.Errorf("LinkSetUp %s: %w", ifaceName, err)
	}

	log.Printf("Interface %s configurée: %s UP", ifaceName, cidr)
	return nil
}

func DetectOutIface() (string, error) {
	routes, err := netlink.RouteList(nil, netlink.FAMILY_V4)
	if err != nil {
		return "", err
	}
	for _, r := range routes {
		if r.Dst == nil || r.Dst.String() == "0.0.0.0/0" {
			link, err := netlink.LinkByIndex(r.LinkIndex)
			if err == nil {
				return link.Attrs().Name, nil
			}
		}
	}
	return "", fmt.Errorf("aucune route par défaut")
}

func getDefaultRoute() (gw string, iface string, err error) {
	routes, err := netlink.RouteList(nil, netlink.FAMILY_V4)
	if err != nil {
		return "", "", err
	}
	for _, r := range routes {
		if r.Dst == nil || r.Dst.String() == "0.0.0.0/0" {
			if r.Gw != nil {
				gw = r.Gw.String()
			}
			link, err := netlink.LinkByIndex(r.LinkIndex)
			if err == nil {
				iface = link.Attrs().Name
			}
			return gw, iface, nil
		}
	}
	return "", "", fmt.Errorf("aucune route par défaut trouvée")
}

func addDefaultRoute(ifaceName string) error {
	link, err := netlink.LinkByName(ifaceName)
	if err != nil {
		return err
	}
	_, dst, _ := net.ParseCIDR("0.0.0.0/0")
	return netlink.RouteAdd(&netlink.Route{
		LinkIndex: link.Attrs().Index,
		Dst:       dst,
		Priority:  100,
	})
}

func removeDefaultRoute(ifaceName string) {
	link, err := netlink.LinkByName(ifaceName)
	if err != nil {
		return
	}
	_, dst, _ := net.ParseCIDR("0.0.0.0/0")
	netlink.RouteDel(&netlink.Route{
		LinkIndex: link.Attrs().Index,
		Dst:       dst,
	})
}

func addHostRoute(host, gw, ifaceName string) error {
	link, err := netlink.LinkByName(ifaceName)
	if err != nil {
		return err
	}
	_, dst, _ := net.ParseCIDR(host + "/32")
	return netlink.RouteAdd(&netlink.Route{
		LinkIndex: link.Attrs().Index,
		Dst:       dst,
		Gw:        net.ParseIP(gw),
	})
}

func removeHostRoute(host string) {
	_, dst, _ := net.ParseCIDR(host + "/32")
	netlink.RouteDel(&netlink.Route{Dst: dst})
}

func restoreDefaultRoute(gw, ifaceName string) {
	link, err := netlink.LinkByName(ifaceName)
	if err != nil {
		return
	}
	_, dst, _ := net.ParseCIDR("0.0.0.0/0")
	netlink.RouteAdd(&netlink.Route{
		LinkIndex: link.Attrs().Index,
		Dst:       dst,
		Gw:        net.ParseIP(gw),
	})
}

func enableForwarding() error {
	return os.WriteFile("/proc/sys/net/ipv4/ip_forward", []byte("1"), 0644)
}

func addNAT(tunIface, outIface string) error {
	cmd := exec.Command("iptables", "-t", "nat", "-A", "POSTROUTING",
		"-i", tunIface, "-o", outIface, "-j", "MASQUERADE")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("iptables MASQUERADE: %s: %w", out, err)
	}
	exec.Command("iptables", "-A", "FORWARD",
		"-i", tunIface, "-o", outIface, "-j", "ACCEPT").Run()
	exec.Command("iptables", "-A", "FORWARD",
		"-i", outIface, "-o", tunIface,
		"-m", "state", "--state", "RELATED,ESTABLISHED", "-j", "ACCEPT").Run()
	return nil
}

func removeNAT(tunIface, outIface string) {
	exec.Command("iptables", "-t", "nat", "-D", "POSTROUTING",
		"-i", tunIface, "-o", outIface, "-j", "MASQUERADE").Run()
	exec.Command("iptables", "-D", "FORWARD",
		"-i", tunIface, "-o", outIface, "-j", "ACCEPT").Run()
	exec.Command("iptables", "-D", "FORWARD",
		"-i", outIface, "-o", tunIface,
		"-m", "state", "--state", "RELATED,ESTABLISHED", "-j", "ACCEPT").Run()
}
