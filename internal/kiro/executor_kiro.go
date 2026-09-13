package kiro

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"

	"github.com/xiaokui-dev/cliproxyapi-kiro-plugin/internal/hostapi"
	"github.com/xiaokui-dev/cliproxyapi-kiro-plugin/internal/wire"
)

const generateURLTemplate = "https://q.%s.amazonaws.com/generateAssistantResponse"

// maxEmptyResponseAttempts bounds retries when Kiro returns HTTP 200 with no
// content and no tool calls. Upstream occasionally goes silent for a given
// conversation; a fresh conversationId on the next attempt usually recovers.
const maxEmptyResponseAttempts = 3

// executorRequest mirrors the host's rpcExecutorRequest: the embedded
// ExecutorRequest (PascalCase) plus stream_id / host_callback_id.
type executorRequest struct {
	pluginapi.ExecutorRequest
	StreamID       string `json:"stream_id,omitempty"`
	HostCallbackID string `json:"host_callback_id,omitempty"`
}

// kiroExecResult holds the aggregated assistant output and the context needed to
// render either a non-streaming message or an SSE stream.
type kiroExecResult struct {
	text           string
	calls          []toolCall
	model          string
	requestPayload []byte
}

// fetchKiroEvents runs the shared request path: build the conversationState
// body, send it via host.http.do, decode the event-stream response, and
// aggregate it. When the upstream returns a completely empty result (no text,
// no tool calls) it retries with a fresh request up to maxEmptyResponseAttempts.
// Returns (result, nil, nil) on success, (nil, an error envelope, nil) for a
// credential/upstream error already encoded as an envelope, or (nil, nil, err)
// for an internal error.
func fetchKiroEvents(request []byte) (*kiroExecResult, []byte, error) {
	var req executorRequest
	if errUnmarshal := json.Unmarshal(request, &req); errUnmarshal != nil {
		return nil, nil, errUnmarshal
	}

	var creq claudeRequest
	if errUnmarshal := json.Unmarshal(req.Payload, &creq); errUnmarshal != nil {
		return nil, nil, fmt.Errorf("decode claude request: %w", errUnmarshal)
	}

	var cred kiroCredential
	if errUnmarshal := json.Unmarshal(req.StorageJSON, &cred); errUnmarshal != nil {
		return nil, nil, fmt.Errorf("decode kiro credential: %w", errUnmarshal)
	}
	if strings.TrimSpace(cred.AccessToken) == "" {
		return nil, wire.ErrorStatus("invalid_credential", "kiro credential has no accessToken", http.StatusUnauthorized), nil
	}

	model := firstNonEmptyStr(req.Model, creq.Model)
	// 请求头携带 accessToken,故端点主机必须由校验过的 region 推导。
	region, errRegion := resolveRegion(cred.Region, cred.IDCRegion)
	if errRegion != nil {
		return nil, wire.ErrorStatus("invalid_credential", "invalid kiro credential region: "+errRegion.Error(), http.StatusBadRequest), nil
	}
	url, errURL := safeEndpoint(generateURLTemplate, region, "")
	if errURL != nil {
		return nil, wire.ErrorStatus("invalid_credential", "invalid kiro endpoint: "+errURL.Error(), http.StatusBadRequest), nil
	}

	var lastResult *kiroExecResult
	for attempt := 0; attempt < maxEmptyResponseAttempts; attempt++ {
		// Rebuild each attempt so a retry carries a fresh conversationId.
		cwReq, maps := buildCodeWhispererRequest(creq, model, cred)
		cwBody, errMarshal := json.Marshal(cwReq)
		if errMarshal != nil {
			return nil, nil, fmt.Errorf("encode codewhisperer request: %w", errMarshal)
		}

		resp, errDo := kiroHTTPDo(hostapi.HTTPRequest{
			HostCallbackID: req.HostCallbackID,
			Method:         http.MethodPost,
			URL:            url,
			Headers:        kiroRequestHeaders(cred),
			Body:           cwBody,
		})
		if errDo != nil {
			return nil, wire.ErrorStatus("upstream_error", errDo.Error(), http.StatusBadGateway), nil
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			// Propagate the upstream status verbatim. We deliberately do NOT remap the
			// token-expired 403 to 401: a 401 marks the auth as an unauthorized failure
			// (hasUnauthorizedAuthFailure) and permanently blocks the host's auto-refresh
			// loop. Token freshness is kept proactively via NextRefreshAfter (set at
			// parse/refresh time), so a healthy credential never reaches this branch.
			return nil, wire.ErrorStatus("upstream_status", fmt.Sprintf("kiro generateAssistantResponse HTTP %d: %s", resp.StatusCode, truncate(string(resp.Body), 300)), resp.StatusCode), nil
		}

		text, calls := aggregateEvents(parseEventStreamFrames(resp.Body), maps)
		lastResult = &kiroExecResult{
			text:           text,
			calls:          calls,
			model:          model,
			requestPayload: req.Payload,
		}
		if strings.TrimSpace(text) != "" || len(calls) > 0 {
			return lastResult, nil, nil
		}
		// Empty result: retry with a fresh request unless attempts are exhausted.
	}

	// All attempts came back empty; return the last (empty) result so the client
	// receives a valid, empty message rather than an error that would penalize
	// the credential.
	return lastResult, nil, nil
}

// executeKiro handles a non-streaming request and returns an aggregated message.
func executeKiro(request []byte) ([]byte, error) {
	res, errEnv, err := fetchKiroEvents(request)
	if err != nil {
		return nil, err
	}
	if errEnv != nil {
		return errEnv, nil
	}

	message := aggregateToClaudeMessage(res.text, res.calls, res.model, res.requestPayload)
	payload, errMarshalResp := json.Marshal(message)
	if errMarshalResp != nil {
		return nil, fmt.Errorf("encode claude response: %w", errMarshalResp)
	}

	return wire.OK(pluginapi.ExecutorResponse{
		Payload: payload,
		Headers: http.Header{"Content-Type": []string{"application/json"}},
	})
}

// executeKiroStream opens a live Kiro response stream and forwards each decoded
// event immediately as Claude SSE. Unlike fetchKiroEvents, it intentionally
// does not retry: a retry after any emitted byte would duplicate the response.
func executeKiroStream(request []byte) ([]byte, error) {
	var req executorRequest
	if errUnmarshal := json.Unmarshal(request, &req); errUnmarshal != nil {
		return nil, errUnmarshal
	}
	if strings.TrimSpace(req.StreamID) == "" {
		return wire.ErrorStatus("invalid_request", "kiro stream_id is required", http.StatusBadRequest), nil
	}

	var creq claudeRequest
	if errUnmarshal := json.Unmarshal(req.Payload, &creq); errUnmarshal != nil {
		return nil, fmt.Errorf("decode claude request: %w", errUnmarshal)
	}
	var cred kiroCredential
	if errUnmarshal := json.Unmarshal(req.StorageJSON, &cred); errUnmarshal != nil {
		return nil, fmt.Errorf("decode kiro credential: %w", errUnmarshal)
	}
	if strings.TrimSpace(cred.AccessToken) == "" {
		return wire.ErrorStatus("invalid_credential", "kiro credential has no accessToken", http.StatusUnauthorized), nil
	}

	model := firstNonEmptyStr(req.Model, creq.Model)
	region, errRegion := resolveRegion(cred.Region, cred.IDCRegion)
	if errRegion != nil {
		return wire.ErrorStatus("invalid_credential", "invalid kiro credential region: "+errRegion.Error(), http.StatusBadRequest), nil
	}
	url, errURL := safeEndpoint(generateURLTemplate, region, "")
	if errURL != nil {
		return wire.ErrorStatus("invalid_credential", "invalid kiro endpoint: "+errURL.Error(), http.StatusBadRequest), nil
	}
	cwReq, maps := buildCodeWhispererRequest(creq, model, cred)
	cwBody, errMarshal := json.Marshal(cwReq)
	if errMarshal != nil {
		return nil, fmt.Errorf("encode codewhisperer request: %w", errMarshal)
	}

	upstream, errDo := kiroHTTPDoStream(hostapi.HTTPRequest{
		HostCallbackID: req.HostCallbackID,
		Method:         http.MethodPost,
		URL:            url,
		Headers:        kiroRequestHeaders(cred),
		Body:           cwBody,
	})
	if errDo != nil {
		return wire.ErrorStatus("upstream_error", errDo.Error(), http.StatusBadGateway), nil
	}
	if upstream.StatusCode < 200 || upstream.StatusCode >= 300 {
		_ = kiroHTTPStreamClose(upstream.StreamID)
		return wire.ErrorStatus("upstream_status", fmt.Sprintf("kiro generateAssistantResponse HTTP %d", upstream.StatusCode), upstream.StatusCode), nil
	}

	response, errResponse := wire.OK(executorStreamResponse{Headers: map[string][]string{"Content-Type": {"text/event-stream"}}})
	if errResponse != nil {
		_ = kiroHTTPStreamClose(upstream.StreamID)
		return nil, errResponse
	}
	go func() {
		errForward := forwardKiroStream(upstream.StreamID, req.StreamID, model, estimateTokens(len(req.Payload)), maps)
		errText := ""
		if errForward != nil {
			errText = errForward.Error()
		}
		_ = kiroStreamClose(req.StreamID, errText)
	}()
	return response, nil
}

func forwardKiroStream(upstreamID, pluginStreamID, model string, inputTokens int, maps *toolNameMaps) (err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			err = fmt.Errorf("kiro stream panic: %v", recovered)
		}
		_ = kiroHTTPStreamClose(upstreamID)
	}()

	writer := newClaudeStreamWriter(model, inputTokens, maps, func(payload []byte) error {
		return kiroStreamEmit(pluginStreamID, payload)
	})
	if errStart := writer.start(); errStart != nil {
		return errStart
	}

	var pending []byte
	for {
		chunk, errRead := kiroHTTPStreamRead(upstreamID)
		if errRead != nil {
			return errRead
		}
		if chunk.Error != "" {
			return fmt.Errorf("kiro upstream stream: %s", chunk.Error)
		}
		pending = append(pending, chunk.Payload...)
		events, rest := consumeEventStreamFrames(pending)
		pending = rest
		for _, event := range events {
			if errWrite := writer.write(event); errWrite != nil {
				return errWrite
			}
		}
		if chunk.Done {
			return writer.finish()
		}
	}
}

// kiroRequestHeaders builds the AWS/KiroIDE headers required by CodeWhisperer.
func kiroRequestHeaders(cred kiroCredential) map[string][]string {
	mid := machineID(cred)
	return map[string][]string{
		"Authorization":               {"Bearer " + cred.AccessToken},
		"Content-Type":                {"application/json"},
		"Accept":                      {"application/json"},
		"amz-sdk-invocation-id":       {uuidV4()},
		"amz-sdk-request":             {"attempt=1; max=3"},
		"x-amzn-codewhisperer-optout": {"true"},
		"x-amzn-kiro-agent-mode":      {"vibe"},
		"x-amz-user-agent":            {fmt.Sprintf("aws-sdk-js/1.0.34 KiroIDE-%s-%s", kiroVersion, mid)},
		"user-agent":                  {fmt.Sprintf("aws-sdk-js/1.0.34 ua/2.1 os/other lang/js md/nodejs#20.11.0 api/codewhispererstreaming#1.0.34 m/E KiroIDE-%s-%s", kiroVersion, mid)},
	}
}
