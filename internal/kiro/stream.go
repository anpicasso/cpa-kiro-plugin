package kiro

import (
	"encoding/json"
	"strings"
)

// executorStreamResponse mirrors the host's rpcExecutorStreamResponse. When
// Chunks is non-empty the host forwards them in order (see rpc_client_stream.go),
// so a plugin can emit a full SSE sequence synchronously without the async
// host.stream.emit path.
type executorStreamResponse struct {
	Headers map[string][]string   `json:"headers,omitempty"`
	Chunks  []executorStreamChunk `json:"chunks,omitempty"`
}

// executorStreamChunk mirrors pluginapi.ExecutorStreamChunk (PascalCase JSON).
type executorStreamChunk struct {
	Payload []byte `json:"Payload,omitempty"`
}

// buildClaudeStreamChunks renders aggregated text + tool calls as a standard
// Claude Messages SSE sequence, one SSE event per chunk:
// message_start → (content_block_start/delta/stop)* → message_delta → message_stop.
func buildClaudeStreamChunks(text string, calls []toolCall, model string, inputTokens int) []executorStreamChunk {
	chunks := make([]executorStreamChunk, 0, 8)
	add := func(event string, data any) {
		body, _ := json.Marshal(data)
		var sb strings.Builder
		sb.WriteString("event: ")
		sb.WriteString(event)
		sb.WriteString("\ndata: ")
		sb.Write(body)
		sb.WriteString("\n\n")
		chunks = append(chunks, executorStreamChunk{Payload: []byte(sb.String())})
	}

	msgID := randomMessageID()
	add("message_start", map[string]any{
		"type": "message_start",
		"message": map[string]any{
			"id": msgID, "type": "message", "role": "assistant", "model": model,
			"content": []any{}, "stop_reason": nil, "stop_sequence": nil,
			"usage": map[string]any{"input_tokens": inputTokens, "output_tokens": 0},
		},
	})

	index := 0
	if strings.TrimSpace(text) != "" {
		add("content_block_start", map[string]any{
			"type": "content_block_start", "index": index,
			"content_block": map[string]any{"type": "text", "text": ""},
		})
		add("content_block_delta", map[string]any{
			"type": "content_block_delta", "index": index,
			"delta": map[string]any{"type": "text_delta", "text": text},
		})
		add("content_block_stop", map[string]any{"type": "content_block_stop", "index": index})
		index++
	}

	for _, tc := range calls {
		add("content_block_start", map[string]any{
			"type": "content_block_start", "index": index,
			"content_block": map[string]any{"type": "tool_use", "id": tc.id, "name": tc.name, "input": map[string]any{}},
		})
		add("content_block_delta", map[string]any{
			"type": "content_block_delta", "index": index,
			"delta": map[string]any{"type": "input_json_delta", "partial_json": string(tc.input)},
		})
		add("content_block_stop", map[string]any{"type": "content_block_stop", "index": index})
		index++
	}

	stopReason := "end_turn"
	if len(calls) > 0 {
		stopReason = "tool_use"
	}
	add("message_delta", map[string]any{
		"type":  "message_delta",
		"delta": map[string]any{"stop_reason": stopReason, "stop_sequence": nil},
		"usage": map[string]any{"output_tokens": estimateTokens(len(text))},
	})
	add("message_stop", map[string]any{"type": "message_stop"})
	return chunks
}

// claudeStreamWriter converts Kiro events to Claude SSE as they arrive.
// It intentionally forwards structured tool calls only; bracket-style fallback
// calls stay text because detecting them online would delay the text stream.
type claudeStreamWriter struct {
	emit        func([]byte) error
	model       string
	inputTokens int
	maps        *toolNameMaps
	index       int
	block       string
	toolID      string
	hasTool     bool
	outputBytes int
}

func newClaudeStreamWriter(model string, inputTokens int, maps *toolNameMaps, emit func([]byte) error) *claudeStreamWriter {
	return &claudeStreamWriter{model: model, inputTokens: inputTokens, maps: maps, emit: emit}
}

func (w *claudeStreamWriter) send(event string, data any) error {
	body, errMarshal := json.Marshal(data)
	if errMarshal != nil {
		return errMarshal
	}
	var sb strings.Builder
	sb.WriteString("event: ")
	sb.WriteString(event)
	sb.WriteString("\ndata: ")
	sb.Write(body)
	sb.WriteString("\n\n")
	return w.emit([]byte(sb.String()))
}

func (w *claudeStreamWriter) start() error {
	return w.send("message_start", map[string]any{
		"type": "message_start",
		"message": map[string]any{
			"id": randomMessageID(), "type": "message", "role": "assistant", "model": w.model,
			"content": []any{}, "stop_reason": nil, "stop_sequence": nil,
			"usage": map[string]any{"input_tokens": w.inputTokens, "output_tokens": 0},
		},
	})
}

func (w *claudeStreamWriter) closeBlock() error {
	if w.block == "" {
		return nil
	}
	if err := w.send("content_block_stop", map[string]any{"type": "content_block_stop", "index": w.index}); err != nil {
		return err
	}
	w.index++
	w.block, w.toolID = "", ""
	return nil
}

func (w *claudeStreamWriter) text(text string) error {
	if text == "" {
		return nil
	}
	if w.block != "text" {
		if err := w.closeBlock(); err != nil {
			return err
		}
		if err := w.send("content_block_start", map[string]any{
			"type": "content_block_start", "index": w.index,
			"content_block": map[string]any{"type": "text", "text": ""},
		}); err != nil {
			return err
		}
		w.block = "text"
	}
	w.outputBytes += len(text)
	return w.send("content_block_delta", map[string]any{
		"type": "content_block_delta", "index": w.index,
		"delta": map[string]any{"type": "text_delta", "text": text},
	})
}

func (w *claudeStreamWriter) toolStart(ev cwEvent) error {
	if ev.Name == kiroPlaceholderToolName {
		return nil
	}
	if err := w.closeBlock(); err != nil {
		return err
	}
	if err := w.send("content_block_start", map[string]any{
		"type": "content_block_start", "index": w.index,
		"content_block": map[string]any{"type": "tool_use", "id": ev.ToolUseID, "name": w.maps.fromKiro(ev.Name), "input": map[string]any{}},
	}); err != nil {
		return err
	}
	w.block, w.toolID, w.hasTool = "tool", ev.ToolUseID, true
	if err := w.toolInput(ev); err != nil {
		return err
	}
	if ev.Stop {
		return w.closeBlock()
	}
	return nil
}

func (w *claudeStreamWriter) toolInput(ev cwEvent) error {
	id := ev.ToolUseID
	if id == "" {
		id = w.toolID
	}
	if w.block != "tool" || id == "" || id != w.toolID {
		return nil
	}
	if ev.Text != "" {
		if err := w.send("content_block_delta", map[string]any{
			"type": "content_block_delta", "index": w.index,
			"delta": map[string]any{"type": "input_json_delta", "partial_json": ev.Text},
		}); err != nil {
			return err
		}
	}
	if ev.Stop {
		return w.closeBlock()
	}
	return nil
}

func (w *claudeStreamWriter) write(ev cwEvent) error {
	switch ev.Kind {
	case cwEventContent:
		return w.text(ev.Text)
	case cwEventToolUse:
		return w.toolStart(ev)
	case cwEventToolUseInput:
		return w.toolInput(ev)
	}
	return nil
}

func (w *claudeStreamWriter) finish() error {
	if err := w.closeBlock(); err != nil {
		return err
	}
	stopReason := "end_turn"
	if w.hasTool {
		stopReason = "tool_use"
	}
	if err := w.send("message_delta", map[string]any{
		"type":  "message_delta",
		"delta": map[string]any{"stop_reason": stopReason, "stop_sequence": nil},
		"usage": map[string]any{"output_tokens": estimateTokens(w.outputBytes)},
	}); err != nil {
		return err
	}
	return w.send("message_stop", map[string]any{"type": "message_stop"})
}
