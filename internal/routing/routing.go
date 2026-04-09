package routing

import (
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"

	"github.com/vishvananda/netlink"
)

// ServerConfig configure le routing côté serveur
type ServerConfig struct {
	TUNName  string // ex: govpn0
	TUNAddr  string // ex: 10.0.0.1/24
	OutIface string // interface vers internet, ex: eth0
}

// ClientConfig configure le routing côté client
type ClientConfig struct {
	TUNName    string // ex: govpn1
	TUNAddr    string // ex: 10.0.0.2/24
	ServerReal string // IP réelle du serveur (pour ne pas router dans le tunnel)
}

// SetupServer active l'IP forwarding et configure le NAT
func SetupServer(cfg ServerConfig) (func(), error) {
	// IP forwarding
	if err := enableForwarding(); err != nil {
		return nil, fmt.Errorf("ip forwarding: %w", err)
	}
	log.Println("IP forwarding activé")

	// Adresse sur le TUN
	if err := addAddr(cfg.TUNName, cfg.TUNAddr); err != nil {
		return nil, fmt.Errorf("addAddr: %w", err)
	}

	// NAT — masquerade les paquets sortant par l'interface physique
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

// SetupClient route tout le trafic via le TUN
// Retourne une fonction de cleanup qui restaure l'état initial
func SetupClient(cfg ClientConfig) (func(), error) {
	// Adresse sur le TUN
	if err := addAddr(cfg.TUNName, cfg.TUNAddr); err != nil {
		return nil, fmt.Errorf("addAddr: %w", err)
	}

	// Sauvegarde la route par défaut actuelle
	defaultGW, defaultIface, err := getDefaultRoute()
	if err != nil {
		return nil, fmt.Errorf("lecture route défaut: %w", err)
	}
	log.Printf("Route défaut sauvegardée: via %s dev %s", defaultGW, defaultIface)

	// Route spécifique pour le trafic UDP vers le vrai serveur
	// (pour ne pas envoyer le tunnel dans le tunnel)
	if cfg.ServerReal != "" {
		if err := addHostRoute(cfg.ServerReal, defaultGW, defaultIface); err != nil {
			log.Printf("Warning: route serveur réel: %v", err)
		}
	}

	// Route par défaut via le TUN — tout le trafic passe par là
	if err := addDefaultRoute(cfg.TUNName); err != nil {
		return nil, fmt.Errorf("route défaut via TUN: %w", err)
	}
	log.Printf("Tout le trafic routé via %s", cfg.TUNName)

	cleanup := func() {
		// Supprime la route par défaut via TUN
		removeDefaultRoute(cfg.TUNName)
		// Restaure l'ancienne route par défaut
		if defaultGW != "" {
			restoreDefaultRoute(defaultGW, defaultIface)
			log.Printf("Route défaut restaurée: via %s dev %s", defaultGW, defaultIface)
		}
		// Supprime la route vers le serveur réel
		if cfg.ServerReal != "" {
			removeHostRoute(cfg.ServerReal)
		}
	}
	return cleanup, nil
}

// --- Primitives réseau ---

func addAddr(ifaceName, cidr string) error {
	link, err := netlink.LinkByName(ifaceName)
	if err != nil {
		return fmt.Errorf("interface %s introuvable: %w", ifaceName, err)
	}

	addr, err := netlink.ParseAddr(cidr)
	if err != nil {
		return fmt.Errorf("adresse invalide %s: %w", cidr, err)
	}

	if err := netlink.AddrAdd(link, addr); err != nil {
		// Ignore "already exists"
		if err.Error() != "file exists" {
			return err
		}
	}

	return netlink.LinkSetUp(link)
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
		Priority:  100, // métrique basse = priorité haute
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
	return os.WriteFile(
		"/proc/sys/net/ipv4/ip_forward",
		[]byte("1"),
		0644,
	)
}

func addNAT(tunIface, outIface string) error {
	// MASQUERADE sur les paquets venant du TUN sortant par l'interface physique
	cmd := exec.Command("iptables", "-t", "nat", "-A", "POSTROUTING",
		"-i", tunIface, "-o", outIface, "-j", "MASQUERADE")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("iptables: %s: %w", out, err)
	}

	// Forward les paquets entre TUN et interface physique
	cmd = exec.Command("iptables", "-A", "FORWARD",
		"-i", tunIface, "-o", outIface, "-j", "ACCEPT")
	cmd.CombinedOutput()

	cmd = exec.Command("iptables", "-A", "FORWARD",
		"-i", outIface, "-o", tunIface,
		"-m", "state", "--state", "RELATED,ESTABLISHED", "-j", "ACCEPT")
	cmd.CombinedOutput()

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

// DetectOutIface détecte automatiquement l'interface physique sortante
func DetectOutIface() (string, error) {
	_, _, iface, err := getDefaultRouteWithIface()
	return iface, err
}

func getDefaultRouteWithIface() (gw string, dst string, iface string, err error) {
	routes, err := netlink.RouteList(nil, netlink.FAMILY_V4)
	if err != nil {
		return "", "", "", err
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
			return gw, "0.0.0.0/0", iface, nil
		}
	}
	return "", "", "", fmt.Errorf("aucune route par défaut")
}
