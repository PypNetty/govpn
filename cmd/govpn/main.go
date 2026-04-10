package main

import (
	"fmt"
	"os"

	"github.com/PypNetty/govpn/pkg/vpn"
	"github.com/spf13/cobra"
)

func main() {
	root := &cobra.Command{
		Use:   "govpn",
		Short: "Tunnel VPN chiffré — ChaCha20 + X25519",
	}
	root.AddCommand(
		vpn.KeygenCmd(),
		vpn.ServerCmd(),
		vpn.ClientCmd(),
	)
	if err := root.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
