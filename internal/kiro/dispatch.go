package kiro

import (
	_ "embed"
	"encoding/base64"
	"net/http"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginabi"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"

	"github.com/xiaokui-dev/cliproxyapi-kiro-plugin/internal/config"
	"github.com/xiaokui-dev/cliproxyapi-kiro-plugin/internal/wire"
)

//go:embed kiro-logo.svg
var kiroLogoSVG []byte

var kiroLogo = "data:image/svg+xml;base64," + base64.StdEncoding.EncodeToString(kiroLogoSVG)

// HandleMethod dispatches a host RPC call to the matching handler and returns a
// JSON envelope. request is the raw JSON body of the method-specific request.
func HandleMethod(method string, request []byte) ([]byte, error) {
	switch method {
	// ---- lifecycle ----
	case pluginabi.MethodPluginRegister, pluginabi.MethodPluginReconfigure:
		config.Apply(request)
		return wire.OK(kiroRegistration())
	case pluginabi.MethodPluginQuiesce, pluginabi.MethodPluginShutdown:
		return wire.OK(map[string]any{})

	// ---- auth provider ----
	case pluginabi.MethodAuthIdentifier:
		return wire.OK(identifierResponse{Identifier: providerKiro})
	case pluginabi.MethodAuthParse:
		return parseKiroAuth(request)
	case pluginabi.MethodAuthLoginStart:
		return startKiroLogin(request)
	case pluginabi.MethodAuthLoginPoll:
		return pollKiroLogin(request)
	case pluginabi.MethodAuthRefresh:
		return refreshKiroAuth(request)

	// ---- model provider ----
	case pluginabi.MethodModelStatic:
		// Kiro models are OAuth-bound; there are no static (auth-less) models.
		return wire.OK(pluginapi.ModelResponse{Provider: providerKiro})
	case pluginabi.MethodModelForAuth:
		return kiroModelsForAuth(request)

	// ---- executor ----
	case pluginabi.MethodExecutorIdentifier:
		return wire.OK(identifierResponse{Identifier: providerKiro})
	case pluginabi.MethodExecutorExecute:
		return executeKiro(request)
	case pluginabi.MethodExecutorExecuteStream:
		return executeKiroStream(request)
	case pluginabi.MethodExecutorCountTokens,
		pluginabi.MethodExecutorHTTPRequest:
		return wire.ErrorStatus("not_implemented", "count-tokens/http-request are not implemented yet", http.StatusNotImplemented), nil

	// ---- management API ----
	case pluginabi.MethodManagementRegister:
		return registerManagement()
	case pluginabi.MethodManagementHandle:
		return handleManagement(request)

	default:
		return wire.Error("unknown_method", "unknown method: "+method), nil
	}
}

// kiroRegistration declares the plugin metadata and capabilities.
func kiroRegistration() registration {
	return registration{
		SchemaVersion: pluginabi.SchemaVersion,
		Metadata: pluginapi.Metadata{
			Name:             providerKiro,
			Version:          "0.2.1",
			Author:           "anpicasso",
			GitHubRepository: "https://github.com/anpicasso/cpa-kiro-plugin",
			Logo:             kiroLogo,
			ConfigFields: []pluginapi.ConfigField{
				{Name: "idc_start_url", Type: pluginapi.ConfigFieldTypeString, Description: "AWS IAM Identity Center start URL for your organization."},
				{Name: "idc_region", Type: pluginapi.ConfigFieldTypeString, Description: "AWS Region hosting your IAM Identity Center instance."},
			},
		},
		Capabilities: registrationCapability{
			AuthProvider:          true,
			ModelProvider:         true,
			Executor:              true,
			ExecutorModelScope:    pluginapi.ExecutorModelScopeOAuth,
			ExecutorInputFormats:  []string{"claude"},
			ExecutorOutputFormats: []string{"claude"},
			ManagementAPI:         true,
		},
	}
}
