package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

type Config struct {
	PrivateKey string `yaml:"private_key"`
	OutIface   string `yaml:"out_iface,omitempty"`
	TUN        struct {
		Name    string `yaml:"name"`
		Address string `yaml:"address"`
	} `yaml:"tun"`
	Listen string       `yaml:"listen"`
	Peers  []PeerConfig `yaml:"peers"`
}

type PeerConfig struct {
	Name      string `yaml:"name"`       // label lisible
	PublicKey string `yaml:"public_key"` // hex 32 bytes
	Endpoint  string `yaml:"endpoint"`   // ip:port
}

func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("lecture config: %w", err)
	}
	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parsing YAML: %w", err)
	}
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("config invalide: %w", err)
	}
	return &cfg, nil
}

func (c *Config) Validate() error {
	if c.PrivateKey == "" {
		return fmt.Errorf("private_key manquant — lance: govpn keygen")
	}
	if c.TUN.Name == "" {
		return fmt.Errorf("tun.name manquant")
	}
	if c.TUN.Address == "" {
		return fmt.Errorf("tun.address manquant")
	}
	if c.Listen == "" {
		return fmt.Errorf("listen manquant")
	}
	return nil
}

// Save écrit la config dans un fichier YAML
func Save(path string, cfg *Config) error {
	data, err := yaml.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("sérialisation: %w", err)
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		return fmt.Errorf("écriture: %w", err)
	}
	return nil
}
