package kiro

import (
	"encoding/json"
	"net/url"
	"testing"

	"github.com/xiaokui-dev/cliproxyapi-kiro-plugin/internal/config"
)

// queryValuesToMetadata is copied verbatim from CLIProxyAPI dev commit 3c3938f
// (internal/api/handlers/management/auth_files_oauth_callback.go). This pins our
// parser against the exact shape the host now sends.
func queryValuesToMetadata(values url.Values) map[string]any {
	if len(values) == 0 {
		return nil
	}
	metadata := make(map[string]any, len(values))
	for k, v := range values {
		if len(v) == 1 {
			metadata[k] = v[0]
		} else if len(v) > 1 {
			metadata[k] = append([]string(nil), v...)
		}
	}
	return metadata
}

func TestHostQueryMetadataDrivesLogin(t *testing.T) {
	resetKiroConfig(t)
	// Defaults in config; the query string must override them per login.
	config.Apply(mustConfigRequest(t, "enabled: true\naccount_label: from-config\n"))

	q, err := url.ParseQuery("idc_start_url=https%3A%2F%2Fd-team.awsapps.com%2Fstart&idc_region=eu-west-1&account_label=team-b")
	if err != nil {
		t.Fatalf("parse query: %v", err)
	}
	metadata := queryValuesToMetadata(q)

	// Round-trip through JSON: the real host sends this over RPC, so the plugin
	// sees decoded JSON, not the original Go map.
	raw, errMarshal := json.Marshal(metadata)
	if errMarshal != nil {
		t.Fatalf("marshal metadata: %v", errMarshal)
	}
	var wire map[string]any
	if errUnmarshal := json.Unmarshal(raw, &wire); errUnmarshal != nil {
		t.Fatalf("unmarshal metadata: %v", errUnmarshal)
	}

	auth, startURL := loginOnceCapturingStartURL(t, wire, "token-b")
	if startURL != "https://d-team.awsapps.com/start" {
		t.Fatalf("startUrl = %q, want the query-provided org portal", startURL)
	}
	if auth.Label != "Kiro ("+idcAuthMethod+") - team-b" {
		t.Fatalf("label = %q, want the query-provided account label", auth.Label)
	}
	var cred kiroCredential
	if errCred := json.Unmarshal(auth.StorageJSON, &cred); errCred != nil {
		t.Fatalf("decode credential: %v", errCred)
	}
	if cred.Region != "eu-west-1" || cred.AuthMethod != idcAuthMethod {
		t.Fatalf("credential = region %q method %q, want eu-west-1 / IdC", cred.Region, cred.AuthMethod)
	}

	// A login with no query params must still fall back to config defaults.
	authDefault, startURLDefault := loginOnceCapturingStartURL(t, queryValuesToMetadata(url.Values{}), "token-a")
	if startURLDefault != builderIDStartURL {
		t.Fatalf("default login startUrl = %q, want Builder ID default", startURLDefault)
	}
	if authDefault.Label != "Kiro ("+builderIDAuthMethod+") - from-config" {
		t.Fatalf("default login label = %q, want the config label", authDefault.Label)
	}
}
