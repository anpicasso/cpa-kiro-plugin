package kiro

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"

	"github.com/xiaokui-dev/cliproxyapi-kiro-plugin/internal/hostapi"
	"github.com/xiaokui-dev/cliproxyapi-kiro-plugin/internal/wire"
)

func TestFetchKiroEventsRetriesEmptyResponse(t *testing.T) {
	payload, err := json.Marshal(claudeRequest{
		Model:    "claude-sonnet-4-5",
		Messages: []claudeMessage{{Role: "user", Content: json.RawMessage(`"hello"`)}},
	})
	if err != nil {
		t.Fatalf("marshal Claude request: %v", err)
	}
	storage, err := json.Marshal(kiroCredential{AccessToken: "test-access-token"})
	if err != nil {
		t.Fatalf("marshal credential: %v", err)
	}
	rawRequest, err := json.Marshal(executorRequest{ExecutorRequest: pluginapi.ExecutorRequest{
		Model:       "claude-sonnet-4-5",
		Payload:     payload,
		StorageJSON: storage,
	}})
	if err != nil {
		t.Fatalf("marshal executor request: %v", err)
	}

	oldHTTPDo := kiroHTTPDo
	t.Cleanup(func() { kiroHTTPDo = oldHTTPDo })
	calls := 0
	kiroHTTPDo = func(req hostapi.HTTPRequest) (*hostapi.HTTPResponse, error) {
		calls++
		switch calls {
		case 1, 2:
			return &hostapi.HTTPResponse{StatusCode: 200}, nil
		case 3:
			body := encodeFrame("assistantResponseEvent", `{"content":"recovered"}`)
			return &hostapi.HTTPResponse{StatusCode: 200, Body: body}, nil
		default:
			t.Fatalf("unexpected extra HTTP call: %d", calls)
			return nil, nil
		}
	}

	result, errEnvelope, errFetch := fetchKiroEvents(rawRequest)
	if errFetch != nil {
		t.Fatalf("fetch failed: %v", errFetch)
	}
	if errEnvelope != nil {
		t.Fatalf("unexpected error envelope: %s", errEnvelope)
	}
	if calls != 3 {
		t.Fatalf("expected two retries and one successful request, got %d calls", calls)
	}
	if result == nil || result.text != "recovered" || len(result.calls) != 0 {
		t.Fatalf("unexpected recovered result: %+v", result)
	}
}

func TestFetchKiroEventsStopsAfterEmptyResponseLimit(t *testing.T) {
	payload, err := json.Marshal(claudeRequest{
		Model:    "claude-sonnet-4-5",
		Messages: []claudeMessage{{Role: "user", Content: json.RawMessage(`"hello"`)}},
	})
	if err != nil {
		t.Fatalf("marshal Claude request: %v", err)
	}
	storage, err := json.Marshal(kiroCredential{AccessToken: "test-access-token"})
	if err != nil {
		t.Fatalf("marshal credential: %v", err)
	}
	rawRequest, err := json.Marshal(executorRequest{ExecutorRequest: pluginapi.ExecutorRequest{
		Model:       "claude-sonnet-4-5",
		Payload:     payload,
		StorageJSON: storage,
	}})
	if err != nil {
		t.Fatalf("marshal executor request: %v", err)
	}

	oldHTTPDo := kiroHTTPDo
	t.Cleanup(func() { kiroHTTPDo = oldHTTPDo })
	calls := 0
	kiroHTTPDo = func(req hostapi.HTTPRequest) (*hostapi.HTTPResponse, error) {
		calls++
		return &hostapi.HTTPResponse{StatusCode: 200}, nil
	}

	result, errEnvelope, errFetch := fetchKiroEvents(rawRequest)
	if errFetch != nil {
		t.Fatalf("fetch failed: %v", errFetch)
	}
	if errEnvelope != nil {
		t.Fatalf("unexpected error envelope: %s", errEnvelope)
	}
	if calls != maxEmptyResponseAttempts {
		t.Fatalf("expected %d attempts, got %d", maxEmptyResponseAttempts, calls)
	}
	if result == nil || result.text != "" || len(result.calls) != 0 {
		t.Fatalf("expected final empty result, got %+v", result)
	}
}

func TestExecuteKiroStreamForwardsSplitFrames(t *testing.T) {
	payload, errMarshal := json.Marshal(claudeRequest{
		Model:    "claude-sonnet-4-5",
		Messages: []claudeMessage{{Role: "user", Content: json.RawMessage(`"hello"`)}},
	})
	if errMarshal != nil {
		t.Fatalf("marshal Claude request: %v", errMarshal)
	}
	storage, errMarshal := json.Marshal(kiroCredential{AccessToken: "test-access-token"})
	if errMarshal != nil {
		t.Fatalf("marshal credential: %v", errMarshal)
	}
	rawRequest, errMarshal := json.Marshal(executorRequest{
		ExecutorRequest: pluginapi.ExecutorRequest{Model: "claude-sonnet-4-5", Payload: payload, StorageJSON: storage},
		StreamID:        "client-stream",
		HostCallbackID:  "callback",
	})
	if errMarshal != nil {
		t.Fatalf("marshal executor request: %v", errMarshal)
	}

	oldDoStream, oldRead, oldClose := kiroHTTPDoStream, kiroHTTPStreamRead, kiroHTTPStreamClose
	oldEmit, oldStreamClose := kiroStreamEmit, kiroStreamClose
	t.Cleanup(func() {
		kiroHTTPDoStream, kiroHTTPStreamRead, kiroHTTPStreamClose = oldDoStream, oldRead, oldClose
		kiroStreamEmit, kiroStreamClose = oldEmit, oldStreamClose
	})

	frames := append(encodeFrame("assistantResponseEvent", `{"content":"Hello"}`),
		encodeFrame("toolUseEvent", `{"name":"get_weather","toolUseId":"t1","input":"{\"city\":"}`)...)
	frames = append(frames, encodeFrame("toolUseEvent", `{"toolUseId":"t1","input":"\"NYC\"}","stop":true}`)...)
	kiroHTTPDoStream = func(req hostapi.HTTPRequest) (*hostapi.HTTPStreamResponse, error) {
		if req.HostCallbackID != "callback" {
			t.Fatalf("callback id = %q", req.HostCallbackID)
		}
		return &hostapi.HTTPStreamResponse{StatusCode: 200, StreamID: "upstream"}, nil
	}
	reads := 0
	kiroHTTPStreamRead = func(streamID string) (*hostapi.HTTPStreamReadResponse, error) {
		if streamID != "upstream" {
			t.Fatalf("upstream id = %q", streamID)
		}
		reads++
		if reads == 1 {
			return &hostapi.HTTPStreamReadResponse{Payload: frames[:len(frames)/2]}, nil
		}
		return &hostapi.HTTPStreamReadResponse{Payload: frames[len(frames)/2:], Done: true}, nil
	}
	upstreamClosed := 0
	kiroHTTPStreamClose = func(string) error {
		upstreamClosed++
		return nil
	}
	var emitted [][]byte
	kiroStreamEmit = func(streamID string, chunk []byte) error {
		if streamID != "client-stream" {
			t.Fatalf("client id = %q", streamID)
		}
		emitted = append(emitted, append([]byte(nil), chunk...))
		return nil
	}
	closed := make(chan string, 1)
	kiroStreamClose = func(streamID, errText string) error {
		closed <- errText
		return nil
	}

	response, errExecute := executeKiroStream(rawRequest)
	if errExecute != nil {
		t.Fatalf("execute stream: %v", errExecute)
	}
	var env wire.Envelope
	if errUnmarshal := json.Unmarshal(response, &env); errUnmarshal != nil || !env.OK {
		t.Fatalf("unexpected response envelope: %s (%v)", response, errUnmarshal)
	}
	var streamResponse executorStreamResponse
	if errUnmarshal := json.Unmarshal(env.Result, &streamResponse); errUnmarshal != nil {
		t.Fatalf("decode stream response: %v", errUnmarshal)
	}
	if len(streamResponse.Chunks) != 0 || streamResponse.Headers["Content-Type"][0] != "text/event-stream" {
		t.Fatalf("expected async SSE response, got %+v", streamResponse)
	}

	select {
	case errText := <-closed:
		if errText != "" {
			t.Fatalf("unexpected stream error: %s", errText)
		}
	case <-time.After(time.Second):
		t.Fatal("stream did not finish")
	}
	if upstreamClosed != 1 || reads != 2 {
		t.Fatalf("upstream close/reads = %d/%d, want 1/2", upstreamClosed, reads)
	}
	got := make([]string, 0, len(emitted))
	for _, chunk := range emitted {
		got = append(got, sseEventType(chunk))
	}
	want := []string{"message_start", "content_block_start", "content_block_delta", "content_block_stop", "content_block_start", "content_block_delta", "content_block_delta", "content_block_stop", "message_delta", "message_stop"}
	if len(got) != len(want) {
		t.Fatalf("event count = %d, want %d: %v", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("event %d = %q, want %q: %v", i, got[i], want[i], got)
		}
	}
}
