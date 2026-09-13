package kiro

import (
	"encoding/json"
	"strings"
)

const (
	originAIEditor          = "AI_EDITOR"
	chatTriggerManual       = "MANUAL"
	kiroPlaceholderToolName = "no_tool_available"
	maxToolNameLength       = 64
	maxToolDescriptionLen   = 9216
)

// ---- Claude Messages request shapes (executor input format = "claude") ----

type claudeRequest struct {
	Model    string          `json:"model"`
	System   json.RawMessage `json:"system"`
	Messages []claudeMessage `json:"messages"`
	Tools    []claudeTool    `json:"tools"`
}

type claudeMessage struct {
	Role    string          `json:"role"`
	Content json.RawMessage `json:"content"`
}

type claudeBlock struct {
	Type      string             `json:"type"`
	Text      string             `json:"text"`
	ID        string             `json:"id"`
	Name      string             `json:"name"`
	Input     json.RawMessage    `json:"input"`
	ToolUseID string             `json:"tool_use_id"`
	Content   json.RawMessage    `json:"content"`
	Thinking  string             `json:"thinking"`
	Source    *claudeImageSource `json:"source"`
}

// claudeImageSource is the source of a Claude image block (base64-encoded).
type claudeImageSource struct {
	Type      string `json:"type"`
	MediaType string `json:"media_type"`
	Data      string `json:"data"`
}

type claudeTool struct {
	Name        string          `json:"name"`
	Description string          `json:"description"`
	InputSchema json.RawMessage `json:"input_schema"`
}

// ---- CodeWhisperer request shapes ----

type cwRequest struct {
	ConversationState cwConversationState `json:"conversationState"`
	ProfileArn        string              `json:"profileArn,omitempty"`
}

type cwConversationState struct {
	ChatTriggerType string           `json:"chatTriggerType"`
	ConversationID  string           `json:"conversationId"`
	History         []cwHistoryItem  `json:"history,omitempty"`
	CurrentMessage  cwCurrentMessage `json:"currentMessage"`
}

type cwCurrentMessage struct {
	UserInputMessage cwUserInputMessage `json:"userInputMessage"`
}

type cwHistoryItem struct {
	UserInputMessage         *cwUserInputMessage `json:"userInputMessage,omitempty"`
	AssistantResponseMessage *cwAssistantMessage `json:"assistantResponseMessage,omitempty"`
}

type cwUserInputMessage struct {
	Content                 string              `json:"content"`
	ModelID                 string              `json:"modelId"`
	Origin                  string              `json:"origin"`
	Images                  []cwImage           `json:"images,omitempty"`
	UserInputMessageContext *cwUserInputContext `json:"userInputMessageContext,omitempty"`
}

// cwImage is a CodeWhisperer image attachment: format is the media subtype
// (e.g. "png"), source.bytes carries the base64-encoded image data.
type cwImage struct {
	Format string        `json:"format"`
	Source cwImageSource `json:"source"`
}

type cwImageSource struct {
	Bytes string `json:"bytes"`
}

type cwUserInputContext struct {
	ToolResults []cwToolResult `json:"toolResults,omitempty"`
	Tools       []cwTool       `json:"tools,omitempty"`
}

type cwToolResult struct {
	Content   []cwTextContent `json:"content"`
	Status    string          `json:"status"`
	ToolUseID string          `json:"toolUseId"`
}

type cwTextContent struct {
	Text string `json:"text"`
}

type cwAssistantMessage struct {
	Content  string      `json:"content"`
	ToolUses []cwToolUse `json:"toolUses,omitempty"`
}

type cwToolUse struct {
	Input     any    `json:"input"`
	Name      string `json:"name"`
	ToolUseID string `json:"toolUseId"`
}

type cwTool struct {
	ToolSpecification cwToolSpec `json:"toolSpecification"`
}

type cwToolSpec struct {
	Name        string        `json:"name"`
	Description string        `json:"description"`
	InputSchema cwInputSchema `json:"inputSchema"`
}

type cwInputSchema struct {
	JSON json.RawMessage `json:"json"`
}

// toolNameMaps translates between original tool names and Kiro-safe short names.
type toolNameMaps struct {
	toKiroMap   map[string]string
	fromKiroMap map[string]string
}

func (m *toolNameMaps) toKiro(name string) string {
	if m != nil {
		if alias, ok := m.toKiroMap[name]; ok {
			return alias
		}
	}
	return shortenToolName(name)
}

func (m *toolNameMaps) fromKiro(name string) string {
	if m != nil {
		if original, ok := m.fromKiroMap[name]; ok {
			return original
		}
	}
	return name
}

func buildToolNameMaps(tools []claudeTool) *toolNameMaps {
	maps := &toolNameMaps{toKiroMap: map[string]string{}, fromKiroMap: map[string]string{}}
	for _, tool := range tools {
		if tool.Name == "" {
			continue
		}
		alias := shortenToolName(tool.Name)
		maps.toKiroMap[tool.Name] = alias
		if alias != tool.Name {
			maps.fromKiroMap[alias] = tool.Name
		}
	}
	return maps
}

// shortenToolName keeps tool names within the upstream length limit: names over
// the limit are truncated and suffixed with a 12-char sha256 prefix for stability.
func shortenToolName(name string) string {
	if len(name) <= maxToolNameLength {
		return name
	}
	hash := sha256Hex(name)[:12]
	prefixLen := maxToolNameLength - len(hash) - 1
	return name[:prefixLen] + "_" + hash
}

type roleMessage struct {
	role   string
	blocks []claudeBlock
}

// buildCodeWhispererRequest converts a Claude Messages request into the
// CodeWhisperer conversationState request. It does NOT inject any identity or
// override prompt; only the client's own system text is forwarded.
func buildCodeWhispererRequest(creq claudeRequest, model string, cred kiroCredential) (*cwRequest, *toolNameMaps) {
	systemText := contentToText(creq.System)
	cwModel := resolveKiroModel(model)
	maps := buildToolNameMaps(creq.Tools)
	toolsCtx := buildToolsContext(creq.Tools, maps)

	merged := mergeAdjacent(claudeMessagesToRoleMessages(creq.Messages))

	history := make([]cwHistoryItem, 0, len(merged))
	startIndex := 0
	prependSystem := false

	if systemText != "" {
		switch {
		case len(merged) >= 1 && merged[0].role == "user" && len(merged) == 1:
			prependSystem = true
		case len(merged) >= 1 && merged[0].role == "user":
			first := buildUserInputMessage(merged[0].blocks, cwModel, maps)
			if first == nil {
				first = &cwUserInputMessage{ModelID: cwModel, Origin: originAIEditor}
			}
			if first.Content != "" {
				first.Content = systemText + "\n\n" + first.Content
			} else {
				first.Content = systemText
			}
			history = append(history, cwHistoryItem{UserInputMessage: first})
			startIndex = 1
		default:
			history = append(history, cwHistoryItem{UserInputMessage: &cwUserInputMessage{
				Content: systemText, ModelID: cwModel, Origin: originAIEditor,
			}})
		}
	}

	// History = all but the last message.
	for i := startIndex; i < len(merged)-1; i++ {
		m := merged[i]
		if m.role == "user" {
			if uim := buildUserInputMessage(m.blocks, cwModel, maps); uim != nil {
				history = append(history, cwHistoryItem{UserInputMessage: uim})
			}
		} else if m.role == "assistant" {
			if arm := buildAssistantMessage(m.blocks, maps); arm != nil {
				history = append(history, cwHistoryItem{AssistantResponseMessage: arm})
			}
		}
	}

	var current *cwUserInputMessage
	if len(merged) > 0 && merged[len(merged)-1].role == "assistant" {
		// currentMessage must be a userInputMessage: move the assistant turn into
		// history and use "Continue" to trigger the next assistant response.
		last := merged[len(merged)-1]
		arm := buildAssistantMessage(last.blocks, maps)
		if arm == nil {
			arm = &cwAssistantMessage{Content: "Continue"}
		}
		history = append(history, cwHistoryItem{AssistantResponseMessage: arm})
		current = &cwUserInputMessage{Content: "Continue", ModelID: cwModel, Origin: originAIEditor}
	} else {
		// Kiro requires history to end with an assistantResponseMessage.
		if len(history) > 0 && history[len(history)-1].AssistantResponseMessage == nil {
			history = append(history, cwHistoryItem{AssistantResponseMessage: &cwAssistantMessage{Content: "Continue"}})
		}
		if len(merged) > 0 {
			current = buildUserInputMessage(merged[len(merged)-1].blocks, cwModel, maps)
		}
		if current == nil {
			current = &cwUserInputMessage{Content: "Continue", ModelID: cwModel, Origin: originAIEditor}
		}
		if prependSystem {
			if current.Content != "" {
				current.Content = systemText + "\n\n" + current.Content
			} else {
				current.Content = systemText
			}
		}
	}

	if len(toolsCtx) > 0 {
		if current.UserInputMessageContext == nil {
			current.UserInputMessageContext = &cwUserInputContext{}
		}
		current.UserInputMessageContext.Tools = toolsCtx
	}

	req := &cwRequest{
		ConversationState: cwConversationState{
			ChatTriggerType: chatTriggerManual,
			ConversationID:  uuidV4(),
			CurrentMessage:  cwCurrentMessage{UserInputMessage: *current},
		},
	}
	if len(history) > 0 {
		req.ConversationState.History = history
	}
	if strings.TrimSpace(cred.ProfileArn) != "" {
		req.ProfileArn = cred.ProfileArn
	}
	return req, maps
}

func claudeMessagesToRoleMessages(messages []claudeMessage) []roleMessage {
	out := make([]roleMessage, 0, len(messages))
	for _, m := range messages {
		out = append(out, roleMessage{role: m.Role, blocks: blocksOf(m.Content)})
	}
	return out
}

func mergeAdjacent(msgs []roleMessage) []roleMessage {
	out := make([]roleMessage, 0, len(msgs))
	for _, m := range msgs {
		if len(out) > 0 && out[len(out)-1].role == m.role {
			out[len(out)-1].blocks = append(out[len(out)-1].blocks, m.blocks...)
			continue
		}
		out = append(out, m)
	}
	return out
}

// buildUserInputMessage builds a CW user message, or nil when the turn is empty
// (no text, tool results, or images) and should be dropped.
func buildUserInputMessage(blocks []claudeBlock, model string, maps *toolNameMaps) *cwUserInputMessage {
	var content strings.Builder
	toolResults := make([]cwToolResult, 0)
	images := make([]cwImage, 0)
	for _, b := range blocks {
		switch b.Type {
		case "text":
			content.WriteString(b.Text)
		case "tool_result":
			toolResults = append(toolResults, cwToolResult{
				Content:   []cwTextContent{{Text: contentToText(b.Content)}},
				Status:    "success",
				ToolUseID: b.ToolUseID,
			})
		case "image":
			if img, ok := toCWImage(b.Source); ok {
				images = append(images, img)
			}
		}
	}

	uim := &cwUserInputMessage{Content: content.String(), ModelID: model, Origin: originAIEditor}
	if len(images) > 0 {
		uim.Images = images
	}
	if len(toolResults) > 0 {
		uim.UserInputMessageContext = &cwUserInputContext{ToolResults: dedupToolResults(toolResults)}
	}
	if strings.TrimSpace(uim.Content) == "" {
		switch {
		case len(toolResults) > 0:
			uim.Content = "Tool results provided."
		case len(images) > 0:
			uim.Content = "Image provided."
		default:
			return nil
		}
	}
	return uim
}

// toCWImage converts a Claude base64 image source into a CodeWhisperer image.
// It reports false when the source is missing data or an unusable media type.
func toCWImage(src *claudeImageSource) (cwImage, bool) {
	if src == nil || strings.TrimSpace(src.Data) == "" {
		return cwImage{}, false
	}
	format := src.MediaType
	if i := strings.LastIndex(format, "/"); i >= 0 {
		format = format[i+1:]
	}
	if strings.TrimSpace(format) == "" {
		return cwImage{}, false
	}
	return cwImage{Format: format, Source: cwImageSource{Bytes: src.Data}}, true
}

// buildAssistantMessage builds a CW assistant message, or nil when empty.
func buildAssistantMessage(blocks []claudeBlock, maps *toolNameMaps) *cwAssistantMessage {
	var content strings.Builder
	toolUses := make([]cwToolUse, 0)
	for _, b := range blocks {
		switch b.Type {
		case "text":
			content.WriteString(b.Text)
		case "tool_use":
			toolUses = append(toolUses, cwToolUse{
				Input:     rawToAny(b.Input),
				Name:      maps.toKiro(b.Name),
				ToolUseID: b.ID,
			})
		}
		// thinking blocks are not yet forwarded (planned for a later milestone).
	}
	if strings.TrimSpace(content.String()) == "" && len(toolUses) == 0 {
		return nil
	}
	arm := &cwAssistantMessage{Content: content.String()}
	if len(toolUses) > 0 {
		arm.ToolUses = toolUses
	}
	return arm
}

// buildToolsContext converts usable Claude tools to CW tools.
func buildToolsContext(tools []claudeTool, maps *toolNameMaps) []cwTool {
	if len(tools) == 0 {
		return nil
	}
	kiroTools := make([]cwTool, 0, len(tools))
	for _, tool := range tools {
		name := strings.ToLower(tool.Name)
		if name == "web_search" || name == "websearch" {
			continue
		}
		if strings.TrimSpace(tool.Description) == "" {
			continue
		}
		desc := tool.Description
		if len(desc) > maxToolDescriptionLen {
			desc = desc[:maxToolDescriptionLen] + "..."
		}
		schema := tool.InputSchema
		if len(schema) == 0 {
			schema = json.RawMessage(`{}`)
		}
		kiroTools = append(kiroTools, cwTool{ToolSpecification: cwToolSpec{
			Name:        maps.toKiro(tool.Name),
			Description: desc,
			InputSchema: cwInputSchema{JSON: schema},
		}})
	}
	if len(kiroTools) == 0 {
		return nil
	}
	return kiroTools
}

func dedupToolResults(results []cwToolResult) []cwToolResult {
	seen := make(map[string]struct{}, len(results))
	out := make([]cwToolResult, 0, len(results))
	for _, r := range results {
		if _, ok := seen[r.ToolUseID]; ok {
			continue
		}
		seen[r.ToolUseID] = struct{}{}
		out = append(out, r)
	}
	return out
}

// ---- helpers ----

// contentToText extracts plain text from a Claude content value (string or blocks).
func contentToText(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return s
	}
	return blocksText(blocksOf(raw))
}

// blocksOf normalizes a Claude content value to blocks; a bare string becomes one text block.
func blocksOf(raw json.RawMessage) []claudeBlock {
	if len(raw) == 0 {
		return nil
	}
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return []claudeBlock{{Type: "text", Text: s}}
	}
	var blocks []claudeBlock
	if err := json.Unmarshal(raw, &blocks); err == nil {
		return blocks
	}
	return nil
}

func blocksText(blocks []claudeBlock) string {
	var sb strings.Builder
	for _, b := range blocks {
		if b.Type == "text" {
			sb.WriteString(b.Text)
		}
	}
	return sb.String()
}

func rawToAny(raw json.RawMessage) any {
	if len(raw) == 0 {
		return map[string]any{}
	}
	var v any
	if err := json.Unmarshal(raw, &v); err == nil {
		return v
	}
	return map[string]any{}
}
