package kiro

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"

	"github.com/xiaokui-dev/cliproxyapi-kiro-plugin/internal/config"
	"github.com/xiaokui-dev/cliproxyapi-kiro-plugin/internal/wire"
)

// parseKiroAuth recognizes Kiro credential files and converts them into AuthData.
// The raw credential JSON is preserved verbatim as StorageJSON so no field is lost.
func parseKiroAuth(request []byte) ([]byte, error) {
	var req pluginapi.AuthParseRequest
	if errUnmarshal := json.Unmarshal(request, &req); errUnmarshal != nil {
		return nil, errUnmarshal
	}

	var cred kiroCredential
	if errUnmarshal := json.Unmarshal(req.RawJSON, &cred); errUnmarshal != nil {
		// Not JSON we understand: report unhandled so other providers can try.
		return wire.OK(pluginapi.AuthParseResponse{Handled: false})
	}
	if !looksLikeKiro(cred) {
		return wire.OK(pluginapi.AuthParseResponse{Handled: false})
	}

	// 导入即校验:region/idcRegion 之后会被拼进上游端点的 authority,凭据文件
	// 又可能来自外部。缺省(空)可接受——运行时回退默认区域;但"非空且不合法"
	// 一定是损坏或投毒,此时拒绝导入,避免坏取值潜伏到后续请求路径。
	for field, value := range map[string]string{"region": cred.Region, "idcRegion": cred.IDCRegion} {
		if strings.TrimSpace(value) == "" {
			continue
		}
		if _, errRegion := validateRegion(value); errRegion != nil {
			return wire.ErrorStatus("invalid_credential",
				"kiro credential has invalid "+field+": "+errRegion.Error(),
				http.StatusBadRequest), nil
		}
	}

	metadata := map[string]any{
		"type": providerKiro,
		// Drives the host's auto-refresh scheduler for plugin providers: with a
		// preferred interval set, the scheduler keeps the auth queued and refreshes
		// it as expiresAt approaches (plugins cannot register a RefreshLead).
		"refresh_interval_seconds": refreshIntervalSeconds,
	}
	if cred.AuthMethod != "" {
		metadata["authMethod"] = cred.AuthMethod
	}
	if cred.Region != "" {
		metadata["region"] = cred.Region
	}
	if cred.ExpiresAt != "" {
		metadata["expiresAt"] = cred.ExpiresAt
	}

	label := "Kiro"
	if cred.AuthMethod != "" {
		label = "Kiro (" + cred.AuthMethod + ")"
	}

	// ID and FileName are filled in by the host from req.Path / req.FileName.
	authData := pluginapi.AuthData{
		Provider:    providerKiro,
		Label:       label,
		StorageJSON: req.RawJSON,
		Metadata:    metadata,
	}

	// Plugin providers cannot register a RefreshLead with the host, so the host's
	// auto-refresh loop only reschedules a plugin auth through NextRefreshAfter.
	// Derive it from expiresAt (with lead) so the token is refreshed BEFORE it
	// expires; if already (near) expired, schedule a refresh shortly after load.
	// The value must be in the future to be picked up by the refresh scheduler.
	if exp, ok := parseKiroTime(cred.ExpiresAt); ok {
		next := exp.Add(-refreshLeadTime)
		soon := time.Now().Add(30 * time.Second)
		if next.Before(soon) {
			next = soon
		}
		authData.NextRefreshAfter = next
	}

	return wire.OK(pluginapi.AuthParseResponse{Handled: true, Auth: authData})
}

// looksLikeKiro decides whether the credential material belongs to Kiro.
func looksLikeKiro(cred kiroCredential) bool {
	if strings.EqualFold(strings.TrimSpace(cred.Type), providerKiro) {
		return true
	}
	// Heuristic for files without an explicit type: Kiro credentials always
	// carry a refresh token together with an auth method (social / builder-id).
	return cred.RefreshToken != "" && cred.AuthMethod != ""
}

// authLoginStartRequest / authLoginPollRequest mirror the host's login RPC
// wire schema: the embedded pluginapi request (PascalCase) plus host_callback_id,
// which binds host.http.do calls to the host transport for this login flow.
type authLoginStartRequest struct {
	pluginapi.AuthLoginStartRequest
	HostCallbackID string `json:"host_callback_id,omitempty"`
}

type authLoginPollRequest struct {
	pluginapi.AuthLoginPollRequest
	HostCallbackID string `json:"host_callback_id,omitempty"`
}

// startKiroLogin begins an AWS Builder ID device-code login. It registers an OIDC
// client and starts device authorization, then returns the user-facing
// verification URL plus an opaque State and the device-code context in Metadata.
// The host persists Metadata against State and hands it back on each poll (the
// plugin is stateless across calls, so all flow state travels through Metadata).
func startKiroLogin(request []byte) ([]byte, error) {
	var req authLoginStartRequest
	if errUnmarshal := json.Unmarshal(request, &req); errUnmarshal != nil {
		return nil, errUnmarshal
	}

	// Request metadata overrides plugin defaults for this login only. CPA passes
	// query parameters to AuthLoginStartRequest.Metadata without persisting them.
	// An empty idc_start_url deliberately selects AWS Builder ID for this flow.
	cfg := config.Get()
	startURL := loginConfigValue(req.Metadata, "idc_start_url", cfg.IDCStartURL)
	idcRegion := loginConfigValue(req.Metadata, "idc_region", cfg.IDCRegion)
	authMethod := builderIDAuthMethod
	region := defaultKiroRegion
	if startURL != "" {
		authMethod = idcAuthMethod
		// idc_region enters the endpoint authority, so reject invalid values instead
		// of silently falling back to a default the user did not choose.
		validRegion, errRegion := validateRegion(firstNonEmptyStr(idcRegion, defaultKiroRegion))
		if errRegion != nil {
			return wire.ErrorStatus("login_invalid_region", "invalid idc_region: "+errRegion.Error(), http.StatusBadRequest), nil
		}
		region = validRegion
	}

	reg, errRegister := builderIDRegisterClient(req.HostCallbackID, region)
	if errRegister != nil {
		return wire.ErrorStatus("login_register_failed", errRegister.Error(), http.StatusBadGateway), nil
	}
	device, errDevice := builderIDStartDeviceAuth(req.HostCallbackID, region, reg.ClientID, reg.ClientSecret, startURL)
	if errDevice != nil {
		return wire.ErrorStatus("login_device_failed", errDevice.Error(), http.StatusBadGateway), nil
	}

	expiresIn := device.ExpiresIn
	if expiresIn <= 0 {
		expiresIn = defaultDeviceExpiresIn
	}
	interval := device.Interval
	if interval <= 0 {
		interval = defaultDeviceInterval
	}
	url := firstNonEmptyStr(device.VerificationURIComplete, device.VerificationURI)

	metadata := map[string]any{
		"authMethod":   authMethod,
		"clientId":     reg.ClientID,
		"clientSecret": reg.ClientSecret,
		"deviceCode":   device.DeviceCode,
		"region":       region,
		"interval":     interval,
	}
	if device.UserCode != "" {
		metadata["userCode"] = device.UserCode
	}

	return wire.OK(pluginapi.AuthLoginStartResponse{
		Provider:  providerKiro,
		URL:       url,
		State:     "kiro-" + randomHexN(16),
		ExpiresAt: time.Now().Add(time.Duration(expiresIn) * time.Second),
		Metadata:  metadata,
	})
}

func loginConfigValue(metadata map[string]any, key, fallback string) string {
	if value, ok := metadata[key].(string); ok {
		return strings.TrimSpace(value)
	}
	return strings.TrimSpace(fallback)
}

// pollKiroLogin performs a single token poll for a Builder ID device-code login.
// It reads the device-code context from Metadata (round-tripped by the host from
// StartLogin) and returns pending until the user approves, then success with the
// completed Kiro credential as AuthData.
func pollKiroLogin(request []byte) ([]byte, error) {
	var req authLoginPollRequest
	if errUnmarshal := json.Unmarshal(request, &req); errUnmarshal != nil {
		return nil, errUnmarshal
	}

	metadata := req.Metadata
	clientID := metaString(metadata, "clientId")
	clientSecret := metaString(metadata, "clientSecret")
	deviceCode := metaString(metadata, "deviceCode")
	// metadata 由宿主按 state 存取后回传,读回时重新校验 region,避免中途被改写。
	region, errRegion := resolveRegion(metaString(metadata, "region"))
	if errRegion != nil {
		return wire.OK(pluginapi.AuthLoginPollResponse{
			Status:  pluginapi.AuthLoginStatusError,
			Message: "login session has an invalid region: " + errRegion.Error(),
		})
	}
	authMethod := firstNonEmptyStr(metaString(metadata, "authMethod"), builderIDAuthMethod)
	if clientID == "" || clientSecret == "" || deviceCode == "" {
		return wire.OK(pluginapi.AuthLoginPollResponse{
			Status:  pluginapi.AuthLoginStatusError,
			Message: "login session is missing device-code context",
		})
	}

	token, errPoll := builderIDPollToken(req.HostCallbackID, region, clientID, clientSecret, deviceCode)
	if errPoll != nil {
		return wire.OK(pluginapi.AuthLoginPollResponse{
			Status:  pluginapi.AuthLoginStatusError,
			Message: errPoll.Error(),
		})
	}

	if token.AccessToken != "" {
		return wire.OK(buildLoginSuccess(token, clientID, clientSecret, region, authMethod))
	}

	switch token.Error {
	case "", "authorization_pending", "slow_down":
		return wire.OK(pluginapi.AuthLoginPollResponse{
			Status:  pluginapi.AuthLoginStatusPending,
			Message: "waiting for user authorization",
		})
	default:
		return wire.OK(pluginapi.AuthLoginPollResponse{
			Status:  pluginapi.AuthLoginStatusError,
			Message: "authorization failed: " + token.Error,
		})
	}
}

// buildLoginSuccess assembles the AuthData for a completed device-code login,
// matching what parseKiroAuth / refreshKiroAuth expect (type + authMethod +
// expiresAt + refresh_interval_seconds, and NextRefreshAfter for proactive
// refresh). authMethod distinguishes AWS Builder ID from org IdC; both refresh
// through the same SSO OIDC token endpoint.
func buildLoginSuccess(token *oidcTokenResponse, clientID, clientSecret, region, authMethod string) pluginapi.AuthLoginPollResponse {
	if authMethod == "" {
		authMethod = builderIDAuthMethod
	}
	expiresIn := token.ExpiresIn
	if expiresIn <= 0 {
		expiresIn = defaultExpiresInSeconds
	}
	expiresAt := time.Now().UTC().Add(time.Duration(expiresIn) * time.Second)

	cred := kiroCredential{
		Type:         providerKiro,
		AccessToken:  token.AccessToken,
		RefreshToken: token.RefreshToken,
		ClientID:     clientID,
		ClientSecret: clientSecret,
		ExpiresAt:    expiresAt.Format(time.RFC3339),
		AuthMethod:   authMethod,
		Region:       region,
		IDCRegion:    region,
	}
	storage, errMarshal := json.Marshal(cred)
	if errMarshal != nil {
		return pluginapi.AuthLoginPollResponse{
			Status:  pluginapi.AuthLoginStatusError,
			Message: "encode credential: " + errMarshal.Error(),
		}
	}

	fileName := "kiro-" + randomHexN(6) + ".json"
	metadata := map[string]any{
		"type":                     providerKiro,
		"authMethod":               authMethod,
		"expiresAt":                cred.ExpiresAt,
		"region":                   region,
		"refresh_interval_seconds": refreshIntervalSeconds,
	}

	return pluginapi.AuthLoginPollResponse{
		Status: pluginapi.AuthLoginStatusSuccess,
		Auth: pluginapi.AuthData{
			Provider:         providerKiro,
			ID:               fileName,
			FileName:         fileName,
			Label:            "Kiro (" + authMethod + ")",
			StorageJSON:      storage,
			Metadata:         metadata,
			NextRefreshAfter: expiresAt.Add(-refreshLeadTime),
		},
	}
}

// metaString reads a string value from a login metadata map, tolerating the
// value being absent or a non-string.
func metaString(m map[string]any, key string) string {
	if m == nil {
		return ""
	}
	if v, ok := m[key]; ok {
		if s, ok := v.(string); ok {
			return strings.TrimSpace(s)
		}
	}
	return ""
}
