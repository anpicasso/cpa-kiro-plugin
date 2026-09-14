package kiro

import (
	"bytes"
	"encoding/binary"
	"testing"
)

// encodeFrame builds one AWS event-stream frame with a single :event-type
// string header and a JSON payload. CRC fields are left zero (the parser does
// not verify them).
func encodeFrame(eventType, payloadJSON string) []byte {
	headerName := ":event-type"
	header := []byte{byte(len(headerName))}
	header = append(header, headerName...)
	header = append(header, 7) // value type: string
	var vlen [2]byte
	binary.BigEndian.PutUint16(vlen[:], uint16(len(eventType)))
	header = append(header, vlen[:]...)
	header = append(header, eventType...)

	payload := []byte(payloadJSON)
	totalLen := 12 + len(header) + len(payload) + 4

	frame := make([]byte, 0, totalLen)
	var prelude [12]byte
	binary.BigEndian.PutUint32(prelude[0:4], uint32(totalLen))
	binary.BigEndian.PutUint32(prelude[4:8], uint32(len(header)))
	// prelude[8:12] CRC = 0
	frame = append(frame, prelude[:]...)
	frame = append(frame, header...)
	frame = append(frame, payload...)
	frame = append(frame, 0, 0, 0, 0) // message CRC = 0
	return frame
}

func TestParseEventStreamContent(t *testing.T) {
	var buf []byte
	buf = append(buf, encodeFrame("assistantResponseEvent", `{"content":"Hello, "}`)...)
	buf = append(buf, encodeFrame("assistantResponseEvent", `{"content":"world"}`)...)

	events := parseEventStreamFrames(buf)
	if len(events) != 2 {
		t.Fatalf("expected 2 events, got %d", len(events))
	}
	if events[0].Kind != cwEventContent || events[0].Text != "Hello, " {
		t.Fatalf("unexpected event[0]: %+v", events[0])
	}

	text, calls := aggregateEvents(events, &toolNameMaps{})
	msg := aggregateToClaudeMessage(text, calls, "claude-sonnet-4-5", []byte("{}"))
	if len(msg.Content) != 1 {
		t.Fatalf("expected 1 content block, got %d", len(msg.Content))
	}
	if msg.StopReason != "end_turn" {
		t.Fatalf("expected end_turn, got %q", msg.StopReason)
	}
	if got := string(msg.Content[0]); got != `{"text":"Hello, world","type":"text"}` {
		t.Fatalf("unexpected text block: %s", got)
	}
}

func TestKiroJSONEventScannerHandlesSplitFramePayload(t *testing.T) {
	frame := encodeFrame("assistantResponseEvent", `{"content":"gateway-compatible"}`)
	start := bytes.Index(frame, []byte(`{"content":"gateway`))
	if start < 0 {
		t.Fatal("test frame did not contain payload")
	}
	split := start + len(`{"content":"gateway`)
	var scanner kiroJSONEventScanner
	if got := scanner.feed(frame[:split]); len(got) != 0 {
		t.Fatalf("expected no partial event, got %+v", got)
	}
	got := scanner.feed(frame[split:])
	if len(got) != 1 || got[0].Kind != cwEventContent || got[0].Text != "gateway-compatible" {
		t.Fatalf("unexpected events: %+v", got)
	}
}

func TestParseEventStreamToolUse(t *testing.T) {
	var buf []byte
	buf = append(buf, encodeFrame("assistantResponseEvent", `{"content":"let me check"}`)...)
	buf = append(buf, encodeFrame("toolUseEvent", `{"name":"get_weather","toolUseId":"tool_1","input":"{\"city\":\"NYC\"}"}`)...)

	events := parseEventStreamFrames(buf)
	maps := &toolNameMaps{fromKiroMap: map[string]string{}}
	text, calls := aggregateEvents(events, maps)
	msg := aggregateToClaudeMessage(text, calls, "claude-sonnet-4-5", []byte("{}"))

	if msg.StopReason != "tool_use" {
		t.Fatalf("expected tool_use stop reason, got %q", msg.StopReason)
	}
	if len(msg.Content) != 2 {
		t.Fatalf("expected text + tool_use blocks, got %d", len(msg.Content))
	}
	if got := string(msg.Content[1]); got != `{"id":"tool_1","input":{"city":"NYC"},"name":"get_weather","type":"tool_use"}` {
		t.Fatalf("unexpected tool_use block: %s", got)
	}
}

func TestPlaceholderToolFilteredFromResponse(t *testing.T) {
	buf := encodeFrame("toolUseEvent", `{"name":"no_tool_available","toolUseId":"t0","input":"{}"}`)
	events := parseEventStreamFrames(buf)
	text, calls := aggregateEvents(events, &toolNameMaps{})
	msg := aggregateToClaudeMessage(text, calls, "claude-sonnet-4-5", []byte("{}"))
	for _, block := range msg.Content {
		if string(block) != "" && containsPlaceholder(string(block)) {
			t.Fatalf("placeholder tool leaked into response: %s", block)
		}
	}
	if msg.StopReason != "end_turn" {
		t.Fatalf("expected end_turn after dropping placeholder, got %q", msg.StopReason)
	}
}

func containsPlaceholder(s string) bool {
	return len(s) > 0 && (s == kiroPlaceholderToolName ||
		(len(s) >= len(kiroPlaceholderToolName) && indexOf(s, kiroPlaceholderToolName) >= 0))
}

func indexOf(haystack, needle string) int {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return i
		}
	}
	return -1
}
