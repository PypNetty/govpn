package vpn

import (
	"encoding/hex"
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

	"github.com/PypNetty/govpn/internal/config"
	"github.com/PypNetty/govpn/internal/handshake"
)

type keygenOptions struct {
	output  string
	tunName string
	addr    string
	listen  string
}

func KeygenCmd() *cobra.Command {
	o := &keygenOptions{}
	cmd := &cobra.Command{
		Use:   "keygen",
		Short: "Génère une paire de clés et un fichier de config",
		RunE:  o.run,
	}
	cmd.Flags().StringVarP(&o.output, "output", "o", "govpn.yaml", "fichier de config à créer")
	cmd.Flags().StringVar(&o.tunName, "tun", "govpn0", "nom de l'interface TUN")
	cmd.Flags().StringVar(&o.addr, "addr", "10.0.0.1/24", "adresse IP du TUN")
	cmd.Flags().StringVar(&o.listen, "listen", "0.0.0.0:51820", "adresse d'écoute UDP")
	return cmd
}

func (o *keygenOptions) run(cmd *cobra.Command, args []string) error {
	kp, err := handshake.GenerateKeyPair()
	if err != nil {
		return fmt.Errorf("génération clés: %w", err)
	}

	if _, err := os.Stat(o.output); err == nil {
		return fmt.Errorf("%s existe déjà — supprime-le d'abord", o.output)
	}

	cfg := &config.Config{
		PrivateKey: hex.EncodeToString(kp.Private[:]),
		Listen:     o.listen,
	}
	cfg.TUN.Name = o.tunName
	cfg.TUN.Address = o.addr

	if err := config.Save(o.output, cfg); err != nil {
		return err
	}

	pubHex := hex.EncodeToString(kp.Public[:])
	fmt.Printf("Config écrite : %s\n", o.output)
	fmt.Printf("Clé publique  : %s\n\n", pubHex)

	peerExample := map[string]interface{}{
		"peers": []map[string]string{{
			"name":       "mon-peer",
			"public_key": pubHex,
			"endpoint":   "IP_DU_PEER:51820",
		}},
	}
	example, _ := yaml.Marshal(peerExample)
	fmt.Println("Ajoute ça dans la config du peer :")
	fmt.Println("---")
	fmt.Print(string(example))
	return nil
}
