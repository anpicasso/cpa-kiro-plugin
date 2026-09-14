package kiro

import "encoding/json"

// cwEventKind classifies a decoded CodeWhisperer stream event.
type cwEventKind int

const (
	cwEventContent      cwEventKind = iota // assistant text delta
	cwEventReasoning                       // reasoning/thinking text delta
	cwEventToolUse                         // tool call start (name + toolUseId, optional partial input)
	cwEventToolUseInput                    // tool call input continuation (toolUseId + input fragment)
)

// cwEvent is one decoded event from the AWS event-stream response.
type cwEvent struct {
	Kind      cwEventKind
	Text      string // content / reasoning text, or input fragment
	Name      string // tool name (toolUse)
	ToolUseID string // tool call id (toolUse / toolUseInput)
	Stop      bool   // tool call stop flag
}

// framePayload is the subset of a frame's JSON payload we care about.
type framePayload struct {
	Content        string          `json:"content"`
	Text           string          `json:"text"`
	Name           string          `json:"name"`
	ToolUseID      string          `json:"toolUseId"`
	Input          json.RawMessage `json:"input"`
	Stop           bool            `json:"stop"`
	FollowupPrompt json.RawMessage `json:"followupPrompt"`
}

// parseEventStreamFrames decodes an AWS event-stream response body into events.
// Frame layout: [4B totalLen][4B headersLen][4B preludeCRC][headers][payload][4B msgCRC],
// all big-endian. The event type is read from the frame's :event-type header, with a
// payload-shape fallback for frames without it.
func parseEventStreamFrames(buffer []byte) []cwEvent {
	events, _ := consumeEventStreamFrames(buffer)
	return events
}

func parseKiroEventBody(buffer []byte) []cwEvent {
	if events := parseEventStreamFrames(buffer); len(events) > 0 {
		return events
	}
	var scanner kiroJSONEventScanner
	return scanner.feed(buffer)
}

// kiroJSONEventScanner extracts the JSON event bodies from the Kiro runtime
// response without assuming its outer AWS event-stream framing. The runtime
// has changed framing in the wild; its event JSON remains the stable contract.
type kiroJSONEventScanner struct {
	pending []byte
}

func (s *kiroJSONEventScanner) feed(chunk []byte) []cwEvent {
	s.pending = append(s.pending, chunk...)
	events := make([]cwEvent, 0, 4)
	for {
		start := -1
		for i, b := range s.pending {
			if b == '{' {
				start = i
				break
			}
		}
		if start < 0 {
			s.pending = nil
			return events
		}
		if start > 0 {
			s.pending = s.pending[start:]
		}
		end, ok := jsonObjectEnd(s.pending)
		if !ok {
			return events
		}
		var payload framePayload
		if json.Unmarshal(s.pending[:end], &payload) == nil {
			if event, ok := classifyFrame("", payload); ok {
				events = append(events, event...)
			}
		}
		s.pending = s.pending[end:]
	}
}

func jsonObjectEnd(buffer []byte) (int, bool) {
	depth := 0
	inString, escaped := false, false
	for i, b := range buffer {
		if inString {
			if escaped {
				escaped = false
			} else if b == '\\' {
				escaped = true
			} else if b == '"' {
				inString = false
			}
			continue
		}
		switch b {
		case '"':
			inString = true
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return i + 1, true
			}
		}
	}
	return 0, false
}

// consumeEventStreamFrames decodes complete frames and retains a trailing partial
// frame for the next host stream read.
func consumeEventStreamFrames(buffer []byte) ([]cwEvent, []byte) {
	events := make([]cwEvent, 0, 16)
	offset := 0
	for {
		if len(buffer)-offset < 12 {
			return events, append([]byte(nil), buffer[offset:]...)
		}
		totalLen := int(beUint32(buffer, offset))
		headersLen := int(beUint32(buffer, offset+4))

		// Invalid prelude: drop one byte and resync (tolerant like the reference).
		if totalLen < 16 || totalLen > 16*1024*1024 || headersLen > totalLen-16 {
			offset++
			continue
		}
		if len(buffer)-offset < totalLen {
			return events, append([]byte(nil), buffer[offset:]...)
		}

		frameStart := offset
		headersStart := frameStart + 12
		payloadStart := headersStart + headersLen
		payloadEnd := frameStart + totalLen - 4 // trailing 4B message CRC
		eventType := readEventTypeHeader(buffer, headersStart, headersLen)
		payload := buffer[payloadStart:payloadEnd]
		offset += totalLen

		var parsed framePayload
		if err := json.Unmarshal(payload, &parsed); err != nil {
			continue
		}

		if ev, ok := classifyFrame(eventType, parsed); ok {
			events = append(events, ev...)
		}
	}
}

// classifyFrame maps an event type + payload to zero or more cwEvents.
func classifyFrame(eventType string, p framePayload) ([]cwEvent, bool) {
	switch eventType {
	case "assistantResponseEvent":
		if p.Content != "" && len(p.FollowupPrompt) == 0 {
			return []cwEvent{{Kind: cwEventContent, Text: p.Content}}, true
		}
	case "reasoningContentEvent":
		if p.Text != "" {
			return []cwEvent{{Kind: cwEventReasoning, Text: p.Text}}, true
		}
	case "toolUseEvent":
		return classifyToolUse(p)
	default:
		// No / unknown event-type header: fall back to payload shape.
		if p.Content != "" && len(p.FollowupPrompt) == 0 {
			return []cwEvent{{Kind: cwEventContent, Text: p.Content}}, true
		}
		if p.Text != "" {
			return []cwEvent{{Kind: cwEventReasoning, Text: p.Text}}, true
		}
		return classifyToolUse(p)
	}
	return nil, false
}

// classifyToolUse distinguishes tool call start vs input continuation.
func classifyToolUse(p framePayload) ([]cwEvent, bool) {
	if p.Name != "" && p.ToolUseID != "" {
		return []cwEvent{{
			Kind:      cwEventToolUse,
			Name:      p.Name,
			ToolUseID: p.ToolUseID,
			Text:      normalizeToolInput(p.Input),
			Stop:      p.Stop,
		}}, true
	}
	if len(p.Input) > 0 && p.Name == "" {
		return []cwEvent{{
			Kind:      cwEventToolUseInput,
			ToolUseID: p.ToolUseID,
			Text:      normalizeToolInput(p.Input),
			Stop:      p.Stop,
		}}, true
	}
	return nil, false
}

// normalizeToolInput renders a tool input value as a string fragment. Kiro sends
// input either as a JSON string fragment or as a JSON object; strings are unquoted
// so fragments concatenate into the full JSON argument text.
func normalizeToolInput(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var asString string
	if err := json.Unmarshal(raw, &asString); err == nil {
		return asString
	}
	return string(raw)
}

// readEventTypeHeader reads the :event-type value from an event-stream frame's
// header block. Header entry: [1B nameLen][name][1B valueType]; string values (7)
// are [2B valueLen][value]. Returns "" when absent or on any parse issue.
func readEventTypeHeader(buffer []byte, start, headersLen int) string {
	p := start
	end := start + headersLen
	for p < end {
		if p+1 > len(buffer) || p >= end {
			break
		}
		nameLen := int(buffer[p])
		p++
		if p+nameLen > len(buffer) || p+nameLen > end {
			break
		}
		name := string(buffer[p : p+nameLen])
		p += nameLen
		if p+1 > len(buffer) || p >= end {
			break
		}
		valueType := buffer[p]
		p++
		if valueType != 7 {
			// Non-string header type; Kiro frames use string headers only.
			break
		}
		if p+2 > len(buffer) {
			break
		}
		valueLen := int(beUint16(buffer, p))
		p += 2
		if p+valueLen > len(buffer) {
			break
		}
		value := string(buffer[p : p+valueLen])
		p += valueLen
		if name == ":event-type" {
			return value
		}
	}
	return ""
}

func beUint32(b []byte, off int) uint32 {
	return uint32(b[off])<<24 | uint32(b[off+1])<<16 | uint32(b[off+2])<<8 | uint32(b[off+3])
}

func beUint16(b []byte, off int) uint16 {
	return uint16(b[off])<<8 | uint16(b[off+1])
}
