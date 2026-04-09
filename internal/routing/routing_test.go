package routing

import (
	"testing"
)

func TestDetectOutIface(t *testing.T) {
	iface, err := DetectOutIface()
	if err != nil {
		t.Fatalf("DetectOutIface: %v", err)
	}
	if iface == "" {
		t.Fatal("interface vide")
	}
	t.Logf("Interface sortante détectée: %s", iface)
}

func TestGetDefaultRoute(t *testing.T) {
	gw, iface, err := getDefaultRoute()
	if err != nil {
		t.Fatalf("getDefaultRoute: %v", err)
	}
	t.Logf("Route défaut: gw=%s iface=%s", gw, iface)
}
