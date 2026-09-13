package kiro

import "github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"

// providerKiro is the provider key and plugin identifier used across all methods.
// It must match the plugin binary basename (kiro.dylib / kiro.so) and the
// plugins.configs.<id> key in config.yaml.
const providerKiro = "kiro"

// registration is the plugin.register / plugin.reconfigure result payload.
// It mirrors the host's rpcRegistration schema (internal/pluginhost/rpc_schema.go).
type registration struct {
	SchemaVersion uint32                 `json:"schema_version"`
	Metadata      pluginapi.Metadata     `json:"metadata"`
	Capabilities  registrationCapability `json:"capabilities"`
}

// registrationCapability declares the integration points this plugin implements.
// Field JSON keys must match the host's rpcCapabilities.
type registrationCapability struct {
	ModelProvider         bool                         `json:"model_provider"`
	AuthProvider          bool                         `json:"auth_provider"`
	Executor              bool                         `json:"executor"`
	ExecutorModelScope    pluginapi.ExecutorModelScope `json:"executor_model_scope"`
	ExecutorInputFormats  []string                     `json:"executor_input_formats,omitempty"`
	ExecutorOutputFormats []string                     `json:"executor_output_formats,omitempty"`
	ManagementAPI         bool                         `json:"management_api,omitempty"`
	QuotaProvider         bool                         `json:"quota_provider,omitempty"`
}

// identifierResponse is the result payload for the *.identifier methods.
type identifierResponse struct {
	Identifier string `json:"identifier"`
}

// kiroCredential is the persisted Kiro auth material stored under auths/*.json.
// Only the fields needed for parsing and (later) refresh are modeled here; the
// full StorageJSON is preserved verbatim so no field is lost on round-trip.
type kiroCredential struct {
	Type         string `json:"type"`
	AccessToken  string `json:"accessToken"`
	RefreshToken string `json:"refreshToken"`
	ClientID     string `json:"clientId"`
	ClientSecret string `json:"clientSecret"`
	ExpiresAt    string `json:"expiresAt"`
	AuthMethod   string `json:"authMethod"`
	Region       string `json:"region"`
	IDCRegion    string `json:"idcRegion"`
	ProfileArn   string `json:"profileArn"`
}
