package hostapi

import (
	"encoding/json"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginabi"

	"github.com/xiaokui-dev/cliproxyapi-kiro-plugin/internal/wire"
)

func TestStreamingCallbacksUseCPAWireSchema(t *testing.T) {
	old := HostCall
	t.Cleanup(func() { HostCall = old })
	var methods []string
	HostCall = func(method string, payload []byte) ([]byte, error) {
		methods = append(methods, method)
		switch method {
		case pluginabi.MethodHostHTTPDoStream:
			var req HTTPRequest
			if err := json.Unmarshal(payload, &req); err != nil || req.HostCallbackID != "callback" {
				t.Fatalf("do_stream request = %s (%v)", payload, err)
			}
			return wire.OK(HTTPStreamResponse{StatusCode: 200, StreamID: "upstream"})
		case pluginabi.MethodHostHTTPStreamRead:
			return wire.OK(HTTPStreamReadResponse{Payload: []byte("chunk"), Done: true})
		default:
			return wire.OK(map[string]any{})
		}
	}

	stream, err := HTTPDoStream(HTTPRequest{HostCallbackID: "callback"})
	if err != nil || stream.StreamID != "upstream" || stream.StatusCode != 200 {
		t.Fatalf("do stream = %#v, %v", stream, err)
	}
	chunk, err := HTTPStreamRead(stream.StreamID)
	if err != nil || string(chunk.Payload) != "chunk" || !chunk.Done {
		t.Fatalf("stream read = %#v, %v", chunk, err)
	}
	if err := HTTPStreamClose(stream.StreamID); err != nil {
		t.Fatalf("stream close: %v", err)
	}
	if err := StreamEmit("client", []byte("sse")); err != nil {
		t.Fatalf("stream emit: %v", err)
	}
	if err := StreamClose("client", ""); err != nil {
		t.Fatalf("stream close: %v", err)
	}
	want := []string{pluginabi.MethodHostHTTPDoStream, pluginabi.MethodHostHTTPStreamRead, pluginabi.MethodHostHTTPStreamClose, pluginabi.MethodHostStreamEmit, pluginabi.MethodHostStreamClose}
	if len(methods) != len(want) {
		t.Fatalf("methods = %v, want %v", methods, want)
	}
	for i := range want {
		if methods[i] != want[i] {
			t.Fatalf("method %d = %q, want %q", i, methods[i], want[i])
		}
	}
}
