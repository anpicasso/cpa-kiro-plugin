package kiro

import (
	"encoding/json"
	"strings"
	"sync"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"

	"github.com/xiaokui-dev/cliproxyapi-kiro-plugin/internal/config"
	"github.com/xiaokui-dev/cliproxyapi-kiro-plugin/internal/hostapi"
)

// loginOnce drives a full start+poll login and returns the resulting AuthData.
// flowMetadata is the per-login OAuth flow metadata (nil = config-only login).
func loginOnce(t *testing.T, flowMetadata map[string]any, accessToken string) pluginapi.AuthData {
	t.Helper()

	oldHTTPDo := kiroHTTPDo
	t.Cleanup(func() { kiroHTTPDo = oldHTTPDo })
	kiroHTTPDo = func(req hostapi.HTTPRequest) (*hostapi.HTTPResponse, error) {
		switch {
		case strings.HasSuffix(req.URL, "/client/register"):
			return &hostapi.HTTPResponse{StatusCode: 200, Body: []byte(`{"clientId":"cid","clientSecret":"secret"}`)}, nil
		case strings.HasSuffix(req.URL, "/device_authorization"):
			return &hostapi.HTTPResponse{StatusCode: 200, Body: []byte(`{"deviceCode":"dev-123","verificationUriComplete":"https://d.example/?code=WXYZ","expiresIn":600,"interval":5}`)}, nil
		case strings.HasSuffix(req.URL, "/token"):
			return &hostapi.HTTPResponse{StatusCode: 200, Body: []byte(`{"accessToken":"` + accessToken + `","refreshToken":"rt-` + accessToken + `","expiresIn":3600}`)}, nil
		default:
			t.Fatalf("unexpected URL: %s", req.URL)
			return nil, nil
		}
	}

	startReq := map[string]any{"Provider": providerKiro, "host_callback_id": "cb-1"}
	if flowMetadata != nil {
		startReq["Metadata"] = flowMetadata
	}
	rawStart, errStart := json.Marshal(startReq)
	if errStart != nil {
		t.Fatalf("marshal start request: %v", errStart)
	}
	rawResp, err := startKiroLogin(rawStart)
	if err != nil {
		t.Fatalf("startKiroLogin: %v", err)
	}
	startResp := decodeLoginStart(t, rawResp)

	pollResp := decodeLoginPoll(t, mustPoll(t, mustMarshalPollRequest(t, startResp.Metadata)))
	if pollResp.Status != pluginapi.AuthLoginStatusSuccess {
		t.Fatalf("expected success, got %+v", pollResp)
	}
	return pollResp.Auth
}

// Two Kiro accounts logged in back to back must produce two independent auth
// records: distinct file names/IDs, distinct labels, and their own credentials.
// Without this the account_label / per-login config work is pointless, because
// the second login would collide with or overwrite the first.
func TestTwoAccountsProduceIndependentAuths(t *testing.T) {
	resetKiroConfig(t)
	// Account A comes from plugin config (the only path the host feeds today).
	config.Apply(mustConfigRequest(t, "enabled: true\naccount_label: team-a\n"))
	authA := loginOnce(t, nil, "token-a")

	// Account B overrides via per-login flow metadata: org IdC, different region.
	authB := loginOnce(t, map[string]any{
		"oauth_flow_config": map[string]any{
			"idc_start_url": "https://d-teamb.awsapps.com/start",
			"idc_region":    "eu-west-1",
			"account_label": "team-b",
		},
	}, "token-b")

	if authA.FileName == authB.FileName {
		t.Fatalf("two logins collided on file name: %s", authA.FileName)
	}
	if authA.ID == authB.ID {
		t.Fatalf("two logins collided on auth ID: %s", authA.ID)
	}
	if authA.Label == authB.Label {
		t.Fatalf("two logins produced the same label: %s", authA.Label)
	}
	if authA.Label != "Kiro ("+builderIDAuthMethod+") - team-a" {
		t.Fatalf("account A label: %q", authA.Label)
	}
	if authB.Label != "Kiro ("+idcAuthMethod+") - team-b" {
		t.Fatalf("account B label: %q", authB.Label)
	}

	var credA, credB kiroCredential
	if err := json.Unmarshal(authA.StorageJSON, &credA); err != nil {
		t.Fatalf("decode cred A: %v", err)
	}
	if err := json.Unmarshal(authB.StorageJSON, &credB); err != nil {
		t.Fatalf("decode cred B: %v", err)
	}
	if credA.AccessToken == credB.AccessToken {
		t.Fatalf("accounts share an access token: %s", credA.AccessToken)
	}
	if credA.AuthMethod != builderIDAuthMethod || credB.AuthMethod != idcAuthMethod {
		t.Fatalf("auth methods not independent: %q / %q", credA.AuthMethod, credB.AuthMethod)
	}
	// Region rides in the credential, so each account refreshes against its own
	// endpoint regardless of what the other account (or current config) says.
	if credA.Region != defaultKiroRegion || credB.Region != "eu-west-1" {
		t.Fatalf("regions not independent: %q / %q", credA.Region, credB.Region)
	}
}

// Refresh must be driven purely by the credential it is handed, never by plugin
// config, or account B would be refreshed against account A's region once the
// config changes.
func TestRefreshIsPerCredentialNotConfig(t *testing.T) {
	resetKiroConfig(t)
	// Config points at a region that belongs to NEITHER credential below.
	config.Apply(mustConfigRequest(t, "enabled: true\nidc_start_url: https://d-cfg.awsapps.com/start\nidc_region: ap-southeast-1\naccount_label: from-config\n"))

	oldHTTPDo := kiroHTTPDo
	t.Cleanup(func() { kiroHTTPDo = oldHTTPDo })
	var refreshURL, refreshBody string
	kiroHTTPDo = func(req hostapi.HTTPRequest) (*hostapi.HTTPResponse, error) {
		refreshURL = req.URL
		refreshBody = string(req.Body)
		return &hostapi.HTTPResponse{StatusCode: 200, Body: []byte(`{"accessToken":"fresh","refreshToken":"rt-new","expiresIn":3600}`)}, nil
	}

	refreshOne := func(cred kiroCredential, metadata map[string]any) pluginapi.AuthRefreshResponse {
		storage, errMarshal := json.Marshal(cred)
		if errMarshal != nil {
			t.Fatalf("marshal credential: %v", errMarshal)
		}
		raw, errReq := json.Marshal(map[string]any{
			"AuthID":           "auth-x",
			"AuthProvider":     providerKiro,
			"StorageJSON":      storage,
			"Metadata":         metadata,
			"host_callback_id": "cb-1",
		})
		if errReq != nil {
			t.Fatalf("marshal refresh request: %v", errReq)
		}
		rawResp, errRefresh := refreshKiroAuth(raw)
		if errRefresh != nil {
			t.Fatalf("refreshKiroAuth: %v", errRefresh)
		}
		var env struct {
			Result json.RawMessage `json:"result"`
		}
		if errEnv := json.Unmarshal(rawResp, &env); errEnv != nil {
			t.Fatalf("decode envelope: %v", errEnv)
		}
		var resp pluginapi.AuthRefreshResponse
		if errResp := json.Unmarshal(env.Result, &resp); errResp != nil {
			t.Fatalf("decode refresh response: %v (%s)", errResp, rawResp)
		}
		return resp
	}

	// Account B: org IdC in eu-west-1, labelled team-b in its own metadata.
	respB := refreshOne(
		kiroCredential{Type: providerKiro, AccessToken: "a", RefreshToken: "rb", ClientID: "cid", ClientSecret: "sec", AuthMethod: idcAuthMethod, Region: "eu-west-1", IDCRegion: "eu-west-1"},
		map[string]any{"accountLabel": "team-b"},
	)
	if !strings.Contains(refreshURL, "eu-west-1") {
		t.Fatalf("refresh used config region instead of the credential's: %s", refreshURL)
	}
	if strings.Contains(refreshURL, "ap-southeast-1") {
		t.Fatalf("config region leaked into refresh: %s", refreshURL)
	}
	if !strings.Contains(refreshBody, "rb") {
		t.Fatalf("refresh sent the wrong refresh token: %s", refreshBody)
	}
	// The host only keeps the plugin's label/metadata; accountLabel must survive
	// a refresh or multi-account labels decay back to identical strings.
	if metaString(respB.Auth.Metadata, "accountLabel") != "team-b" {
		t.Fatalf("refresh dropped accountLabel: %+v", respB.Auth.Metadata)
	}
	if metaString(respB.Auth.Metadata, "authMethod") != idcAuthMethod {
		t.Fatalf("refresh lost authMethod: %+v", respB.Auth.Metadata)
	}

	// Account A: Builder ID in us-east-1 — same process, unaffected by B or config.
	respA := refreshOne(
		kiroCredential{Type: providerKiro, AccessToken: "a", RefreshToken: "ra", ClientID: "cid", ClientSecret: "sec", AuthMethod: builderIDAuthMethod, Region: defaultKiroRegion},
		map[string]any{"accountLabel": "team-a"},
	)
	if !strings.Contains(refreshURL, defaultKiroRegion) {
		t.Fatalf("account A refresh used the wrong region: %s", refreshURL)
	}
	if !strings.Contains(refreshBody, "ra") {
		t.Fatalf("account A refresh sent the wrong token: %s", refreshBody)
	}
	if metaString(respA.Auth.Metadata, "accountLabel") != "team-a" {
		t.Fatalf("account A lost its label: %+v", respA.Auth.Metadata)
	}
}

// The primary flow: several accounts on the default start URL and region, with
// no plugin config set at all. Each login must yield its own credential file.
func TestMultipleDefaultAccounts(t *testing.T) {
	resetKiroConfig(t)

	seen := map[string]bool{}
	for _, token := range []string{"acct-1", "acct-2", "acct-3"} {
		auth := loginOnce(t, nil, token)
		if seen[auth.FileName] {
			t.Fatalf("login reused a credential file: %s", auth.FileName)
		}
		seen[auth.FileName] = true

		var cred kiroCredential
		if err := json.Unmarshal(auth.StorageJSON, &cred); err != nil {
			t.Fatalf("decode credential: %v", err)
		}
		if cred.AccessToken != token {
			t.Fatalf("credential %s holds the wrong token: %s", auth.FileName, cred.AccessToken)
		}
		if cred.AuthMethod != builderIDAuthMethod {
			t.Fatalf("expected builder-id by default, got %q", cred.AuthMethod)
		}
		if cred.Region != defaultKiroRegion {
			t.Fatalf("expected default region, got %q", cred.Region)
		}
	}
	if len(seen) != 3 {
		t.Fatalf("expected 3 distinct credential files, got %d", len(seen))
	}
}

// Two saved credential files must both serve traffic at the same time, each
// against its own token and region, with plugin config pointing at neither.
func TestTwoCredentialsServeConcurrently(t *testing.T) {
	resetKiroConfig(t)
	config.Apply(mustConfigRequest(t, "enabled: true\nidc_start_url: https://d-cfg.awsapps.com/start\nidc_region: ap-southeast-1\n"))

	payload, errPayload := json.Marshal(claudeRequest{
		Model:    "claude-sonnet-4-5",
		Messages: []claudeMessage{{Role: "user", Content: json.RawMessage(`"hello"`)}},
	})
	if errPayload != nil {
		t.Fatalf("marshal payload: %v", errPayload)
	}

	var mu sync.Mutex
	seen := map[string]string{} // access token -> URL it was sent to
	oldHTTPDo := kiroHTTPDo
	t.Cleanup(func() { kiroHTTPDo = oldHTTPDo })
	kiroHTTPDo = func(req hostapi.HTTPRequest) (*hostapi.HTTPResponse, error) {
		token := strings.TrimPrefix(strings.Join(req.Headers["Authorization"], ""), "Bearer ")
		mu.Lock()
		seen[token] = req.URL
		mu.Unlock()
		return &hostapi.HTTPResponse{
			StatusCode: 200,
			Body:       encodeFrame("assistantResponseEvent", `{"content":"from-`+token+`"}`),
		}, nil
	}

	run := func(cred kiroCredential) (*kiroExecResult, error) {
		storage, errStorage := json.Marshal(cred)
		if errStorage != nil {
			return nil, errStorage
		}
		raw, errRaw := json.Marshal(executorRequest{ExecutorRequest: pluginapi.ExecutorRequest{
			Model:       "claude-sonnet-4-5",
			Payload:     payload,
			StorageJSON: storage,
		}})
		if errRaw != nil {
			return nil, errRaw
		}
		result, errEnvelope, errFetch := fetchKiroEvents(raw)
		if errFetch != nil {
			return nil, errFetch
		}
		if errEnvelope != nil {
			t.Errorf("error envelope: %s", errEnvelope)
		}
		return result, nil
	}

	credA := kiroCredential{Type: providerKiro, AccessToken: "token-a", AuthMethod: builderIDAuthMethod, Region: defaultKiroRegion}
	credB := kiroCredential{Type: providerKiro, AccessToken: "token-b", AuthMethod: idcAuthMethod, Region: "eu-west-1", IDCRegion: "eu-west-1"}

	// Fire both at once: nothing may be shared through package state.
	var wg sync.WaitGroup
	results := make([]*kiroExecResult, 2)
	errs := make([]error, 2)
	for i, cred := range []kiroCredential{credA, credB} {
		wg.Add(1)
		go func(i int, cred kiroCredential) {
			defer wg.Done()
			results[i], errs[i] = run(cred)
		}(i, cred)
	}
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Fatalf("request %d failed: %v", i, err)
		}
		if results[i] == nil {
			t.Fatalf("request %d returned no result", i)
		}
	}
	if results[0].text != "from-token-a" {
		t.Fatalf("account A got the wrong response: %q", results[0].text)
	}
	if results[1].text != "from-token-b" {
		t.Fatalf("account B got the wrong response: %q", results[1].text)
	}

	if len(seen) != 2 {
		t.Fatalf("expected two distinct tokens upstream, got %v", seen)
	}
	if !strings.Contains(seen["token-a"], defaultKiroRegion) {
		t.Fatalf("account A hit the wrong region: %s", seen["token-a"])
	}
	if !strings.Contains(seen["token-b"], "eu-west-1") {
		t.Fatalf("account B hit the wrong region: %s", seen["token-b"])
	}
	for token, url := range seen {
		if strings.Contains(url, "ap-southeast-1") {
			t.Fatalf("plugin config region leaked into %s request: %s", token, url)
		}
	}
}

// The target fleet: several accounts on the defaults plus a couple with their
// own start URL / region, all saved at once and all serving traffic together.
// Config is re-applied between logins because that is the only per-login channel
// the host offers today; what matters is that the resulting credentials are
// independent and stay correct afterwards.
func TestMixedFleetDefaultsPlusOverrides(t *testing.T) {
	resetKiroConfig(t)

	type want struct {
		token      string
		authMethod string
		region     string
	}
	plan := []struct {
		configYAML string
		want       want
	}{
		{"enabled: true\n", want{"default-1", builderIDAuthMethod, defaultKiroRegion}},
		{"enabled: true\n", want{"default-2", builderIDAuthMethod, defaultKiroRegion}},
		{"enabled: true\n", want{"default-3", builderIDAuthMethod, defaultKiroRegion}},
		{"enabled: true\nidc_start_url: https://d-teamb.awsapps.com/start\nidc_region: eu-west-1\n", want{"org-eu", idcAuthMethod, "eu-west-1"}},
		{"enabled: true\nidc_start_url: https://d-teamc.awsapps.com/start\nidc_region: ap-northeast-1\n", want{"org-ap", idcAuthMethod, "ap-northeast-1"}},
	}

	creds := make([]kiroCredential, 0, len(plan))
	files := map[string]bool{}
	for _, step := range plan {
		config.Apply(mustConfigRequest(t, step.configYAML))
		auth := loginOnce(t, nil, step.want.token)
		if files[auth.FileName] {
			t.Fatalf("credential file reused: %s", auth.FileName)
		}
		files[auth.FileName] = true

		var cred kiroCredential
		if err := json.Unmarshal(auth.StorageJSON, &cred); err != nil {
			t.Fatalf("decode credential: %v", err)
		}
		if cred.AccessToken != step.want.token {
			t.Fatalf("wrong token stored: %q", cred.AccessToken)
		}
		if cred.AuthMethod != step.want.authMethod {
			t.Fatalf("%s: auth method %q, want %q", step.want.token, cred.AuthMethod, step.want.authMethod)
		}
		if cred.Region != step.want.region {
			t.Fatalf("%s: region %q, want %q", step.want.token, cred.Region, step.want.region)
		}
		creds = append(creds, cred)
	}
	if len(files) != len(plan) {
		t.Fatalf("expected %d credential files, got %d", len(plan), len(files))
	}

	// Config now points somewhere unrelated to every credential above. The whole
	// fleet must keep working off what is baked into each credential.
	config.Apply(mustConfigRequest(t, "enabled: true\nidc_start_url: https://d-later.awsapps.com/start\nidc_region: sa-east-1\n"))

	payload, errPayload := json.Marshal(claudeRequest{
		Model:    "claude-sonnet-4-5",
		Messages: []claudeMessage{{Role: "user", Content: json.RawMessage(`"hi"`)}},
	})
	if errPayload != nil {
		t.Fatalf("marshal payload: %v", errPayload)
	}

	var mu sync.Mutex
	hits := map[string]string{} // token -> upstream URL
	oldHTTPDo := kiroHTTPDo
	t.Cleanup(func() { kiroHTTPDo = oldHTTPDo })
	kiroHTTPDo = func(req hostapi.HTTPRequest) (*hostapi.HTTPResponse, error) {
		token := strings.TrimPrefix(strings.Join(req.Headers["Authorization"], ""), "Bearer ")
		mu.Lock()
		hits[token] = req.URL
		mu.Unlock()
		return &hostapi.HTTPResponse{
			StatusCode: 200,
			Body:       encodeFrame("assistantResponseEvent", `{"content":"ok-`+token+`"}`),
		}, nil
	}

	// All five serve at the same time.
	var wg sync.WaitGroup
	texts := make([]string, len(creds))
	errs := make([]error, len(creds))
	for i, cred := range creds {
		wg.Add(1)
		go func(i int, cred kiroCredential) {
			defer wg.Done()
			storage, errStorage := json.Marshal(cred)
			if errStorage != nil {
				errs[i] = errStorage
				return
			}
			raw, errRaw := json.Marshal(executorRequest{ExecutorRequest: pluginapi.ExecutorRequest{
				Model:       "claude-sonnet-4-5",
				Payload:     payload,
				StorageJSON: storage,
			}})
			if errRaw != nil {
				errs[i] = errRaw
				return
			}
			result, errEnvelope, errFetch := fetchKiroEvents(raw)
			if errFetch != nil {
				errs[i] = errFetch
				return
			}
			if errEnvelope != nil {
				t.Errorf("%s: error envelope %s", cred.AccessToken, errEnvelope)
				return
			}
			texts[i] = result.text
		}(i, cred)
	}
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Fatalf("credential %d failed: %v", i, err)
		}
		if texts[i] != "ok-"+creds[i].AccessToken {
			t.Fatalf("credential %d got a crossed response: %q", i, texts[i])
		}
	}
	if len(hits) != len(creds) {
		t.Fatalf("expected %d distinct tokens upstream, got %v", len(creds), hits)
	}
	for _, cred := range creds {
		url := hits[cred.AccessToken]
		if !strings.Contains(url, cred.Region) {
			t.Fatalf("%s went to %s, expected region %s", cred.AccessToken, url, cred.Region)
		}
		if strings.Contains(url, "sa-east-1") {
			t.Fatalf("current config region leaked into %s: %s", cred.AccessToken, url)
		}
	}
}
