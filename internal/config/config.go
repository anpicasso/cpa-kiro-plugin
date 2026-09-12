// Package config parses and stores the plugin's configurable settings (the
// plugins.configs.kiro sub-tree delivered by the host on register/reconfigure).
package config

import (
	"encoding/json"
	"strings"
	"sync"

	"gopkg.in/yaml.v3"
)

// Config holds the plugin's configurable settings. The login method is inferred
// from IDCStartURL rather than chosen explicitly: when it is set, interactive
// login goes through the organization's IAM Identity Center (IdC); when it is
// empty, login falls back to AWS Builder ID (a personal account). The
// CodeWhisperer/OIDC region is not configurable for Builder ID (it always uses
// the default, us-east-1); IdC uses IDCRegion.
type Config struct {
	IDCStartURL  string `yaml:"idc_start_url"`
	IDCRegion    string `yaml:"idc_region"`
	AccountLabel string `yaml:"account_label"`
}

var (
	mu      sync.RWMutex
	current Config
)

// pluginConfigRequest is the subset of the register/reconfigure RPC we read: the
// host delivers the plugin's config sub-tree as YAML bytes (base64 in JSON).
type pluginConfigRequest struct {
	ConfigYAML []byte `json:"config_yaml"`
}

// Apply parses the config_yaml carried by a register/reconfigure request and
// stores it. Missing or malformed config leaves an empty config (interactive
// login then defaults to Builder ID).
func Apply(request []byte) {
	var req pluginConfigRequest
	if errUnmarshal := json.Unmarshal(request, &req); errUnmarshal != nil {
		return
	}
	var cfg Config
	if len(req.ConfigYAML) > 0 {
		if errYAML := yaml.Unmarshal(req.ConfigYAML, &cfg); errYAML != nil {
			return
		}
	}
	cfg.IDCStartURL = strings.TrimSpace(cfg.IDCStartURL)
	cfg.IDCRegion = strings.TrimSpace(cfg.IDCRegion)
	cfg.AccountLabel = strings.TrimSpace(cfg.AccountLabel)

	mu.Lock()
	current = cfg
	mu.Unlock()
}

// Get returns a copy of the current plugin config.
func Get() Config {
	mu.RLock()
	defer mu.RUnlock()
	return current
}
