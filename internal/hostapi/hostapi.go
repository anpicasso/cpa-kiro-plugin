// Package hostapi wraps the plugin→host callbacks (host.http.do, host.auth.*).
//
// The actual CGO callback into the host lives in the main package (it needs C
// types and cannot be shared across packages). The main package injects it here
// as HostCall at init time, keeping this package free of CGO so it can be reused
// and unit-tested with a plain Go function.
package hostapi

import (
	"encoding/json"
	"fmt"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginabi"

	"github.com/xiaokui-dev/cliproxyapi-kiro-plugin/internal/wire"
)

// HostCall is the plugin→host bridge, injected by the main package at init time
// (it wraps the CGO call into the host). It returns the host's raw JSON envelope
// bytes for the given method and payload.
var HostCall func(method string, payload []byte) ([]byte, error)

// callHost invokes the injected host bridge, guarding against a missing injection.
func callHost(method string, payload []byte) ([]byte, error) {
	if HostCall == nil {
		return nil, fmt.Errorf("host callback not initialized")
	}
	return HostCall(method, payload)
}

// HTTPRequest mirrors the host's rpcHostHTTPRequest wire schema
// (internal/pluginhost/host_callbacks.go). The HostCallbackID binds the request
// to the auth-scoped transport opened by the host for this RPC.
type HTTPRequest struct {
	HostCallbackID string              `json:"host_callback_id,omitempty"`
	Method         string              `json:"method,omitempty"`
	URL            string              `json:"url,omitempty"`
	Headers        map[string][]string `json:"headers,omitempty"`
	Body           []byte              `json:"body,omitempty"`
}

// HTTPResponse mirrors pluginapi.HTTPResponse (PascalCase JSON, no tags).
type HTTPResponse struct {
	StatusCode int                 `json:"StatusCode"`
	Headers    map[string][]string `json:"Headers"`
	Body       []byte              `json:"Body"`
}

// HTTPStreamResponse mirrors the host's rpcHostHTTPStreamResponse.
type HTTPStreamResponse struct {
	StatusCode int                 `json:"status_code"`
	Headers    map[string][]string `json:"headers,omitempty"`
	StreamID   string              `json:"stream_id,omitempty"`
}

// HTTPStreamReadResponse mirrors the host's rpcHostHTTPStreamReadResponse.
type HTTPStreamReadResponse struct {
	Payload []byte `json:"payload,omitempty"`
	Error   string `json:"error,omitempty"`
	Done    bool   `json:"done,omitempty"`
}

// HTTPDo executes an HTTP request through the host transport (proxy, request
// logging) via the host.http.do callback and returns the response.
func HTTPDo(req HTTPRequest) (*HTTPResponse, error) {
	payload, errMarshal := json.Marshal(req)
	if errMarshal != nil {
		return nil, errMarshal
	}
	raw, errCall := callHost(pluginabi.MethodHostHTTPDo, payload)
	if errCall != nil {
		return nil, errCall
	}
	var env wire.Envelope
	if errUnmarshal := json.Unmarshal(raw, &env); errUnmarshal != nil {
		return nil, fmt.Errorf("decode host http envelope: %w", errUnmarshal)
	}
	if !env.OK {
		if env.Error != nil && env.Error.Message != "" {
			return nil, fmt.Errorf("host http call failed: %s", env.Error.Message)
		}
		return nil, fmt.Errorf("host http call failed")
	}
	var resp HTTPResponse
	if len(env.Result) > 0 {
		if errUnmarshal := json.Unmarshal(env.Result, &resp); errUnmarshal != nil {
			return nil, fmt.Errorf("decode host http response: %w", errUnmarshal)
		}
	}
	return &resp, nil
}

// HTTPDoStream starts an HTTP stream through the host transport. The returned
// stream must be read with HTTPStreamRead and closed with HTTPStreamClose.
func HTTPDoStream(req HTTPRequest) (*HTTPStreamResponse, error) {
	payload, errMarshal := json.Marshal(req)
	if errMarshal != nil {
		return nil, errMarshal
	}
	var resp HTTPStreamResponse
	if err := callJSON(pluginabi.MethodHostHTTPDoStream, payload, &resp); err != nil {
		return nil, err
	}
	if resp.StreamID == "" {
		return nil, fmt.Errorf("host http stream returned no stream_id")
	}
	return &resp, nil
}

// HTTPStreamRead reads the next raw upstream chunk.
func HTTPStreamRead(streamID string) (*HTTPStreamReadResponse, error) {
	payload, errMarshal := json.Marshal(map[string]string{"stream_id": streamID})
	if errMarshal != nil {
		return nil, errMarshal
	}
	var resp HTTPStreamReadResponse
	if err := callJSON(pluginabi.MethodHostHTTPStreamRead, payload, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// HTTPStreamClose cancels and releases an upstream stream.
func HTTPStreamClose(streamID string) error {
	payload, errMarshal := json.Marshal(map[string]string{"stream_id": streamID})
	if errMarshal != nil {
		return errMarshal
	}
	return callJSON(pluginabi.MethodHostHTTPStreamClose, payload, nil)
}

// StreamEmit appends a payload to the client-facing plugin stream.
func StreamEmit(streamID string, payload []byte) error {
	request, errMarshal := json.Marshal(struct {
		StreamID string `json:"stream_id"`
		Payload  []byte `json:"payload,omitempty"`
	}{StreamID: streamID, Payload: payload})
	if errMarshal != nil {
		return errMarshal
	}
	return callJSON(pluginabi.MethodHostStreamEmit, request, nil)
}

// StreamClose completes the client-facing plugin stream, optionally with an error.
func StreamClose(streamID, errMsg string) error {
	payload, errMarshal := json.Marshal(struct {
		StreamID string `json:"stream_id"`
		Error    string `json:"error,omitempty"`
	}{StreamID: streamID, Error: errMsg})
	if errMarshal != nil {
		return errMarshal
	}
	return callJSON(pluginabi.MethodHostStreamClose, payload, nil)
}

// callJSON invokes a host callback and unmarshals the {ok,result} envelope's
// result into out. Used for host.auth.* callbacks (host.http.do has its own wrapper).
func callJSON(method string, payload []byte, out any) error {
	raw, errCall := callHost(method, payload)
	if errCall != nil {
		return errCall
	}
	var env wire.Envelope
	if errUnmarshal := json.Unmarshal(raw, &env); errUnmarshal != nil {
		return fmt.Errorf("decode %s envelope: %w", method, errUnmarshal)
	}
	if !env.OK {
		if env.Error != nil && env.Error.Message != "" {
			return fmt.Errorf("%s failed: %s", method, env.Error.Message)
		}
		return fmt.Errorf("%s failed", method)
	}
	if out != nil && len(env.Result) > 0 {
		if errUnmarshal := json.Unmarshal(env.Result, out); errUnmarshal != nil {
			return fmt.Errorf("decode %s result: %w", method, errUnmarshal)
		}
	}
	return nil
}

// AuthEntry is the subset of the host's HostAuthFileEntry the plugin needs to
// select its own credentials.
type AuthEntry struct {
	AuthIndex string `json:"auth_index"`
	Name      string `json:"name"`
	Provider  string `json:"provider"`
	Type      string `json:"type"`
	Label     string `json:"label"`
	Status    string `json:"status"`
	Email     string `json:"email"`
}

type authListResult struct {
	Files []AuthEntry `json:"files"`
}

// AuthGetResult carries the physical credential JSON resolved by auth index.
type AuthGetResult struct {
	AuthIndex string          `json:"auth_index"`
	Name      string          `json:"name"`
	Path      string          `json:"path"`
	JSON      json.RawMessage `json:"json"`
}

// AuthList lists all credentials known to the host.
func AuthList() ([]AuthEntry, error) {
	var resp authListResult
	if err := callJSON(pluginabi.MethodHostAuthList, nil, &resp); err != nil {
		return nil, err
	}
	return resp.Files, nil
}

// AuthGet fetches one credential's physical JSON by auth index.
func AuthGet(authIndex string) (*AuthGetResult, error) {
	payload, errMarshal := json.Marshal(map[string]string{"auth_index": authIndex})
	if errMarshal != nil {
		return nil, errMarshal
	}
	var resp AuthGetResult
	if err := callJSON(pluginabi.MethodHostAuthGet, payload, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}
