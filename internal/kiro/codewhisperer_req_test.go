package kiro

import (
	"encoding/json"
	"strings"
	"testing"
)

func buildFromJSON(t *testing.T, payload string, cred kiroCredential) *cwRequest {
	t.Helper()
	var creq claudeRequest
	if err := json.Unmarshal([]byte(payload), &creq); err != nil {
		t.Fatalf("unmarshal payload: %v", err)
	}
	req, _ := buildCodeWhispererRequest(creq, creq.Model, cred)
	return req
}

func TestBuildSingleUserWithSystemPrepends(t *testing.T) {
	req := buildFromJSON(t, `{
		"model":"claude-sonnet-4-5",
		"system":"You are helpful.",
		"messages":[{"role":"user","content":"hi"}]
	}`, kiroCredential{})

	cur := req.ConversationState.CurrentMessage.UserInputMessage
	if cur.Content != "You are helpful.\n\nhi" {
		t.Fatalf("system not prepended to current message: %q", cur.Content)
	}
	if len(req.ConversationState.History) != 0 {
		t.Fatalf("expected no history for single-turn, got %d", len(req.ConversationState.History))
	}
	if cur.UserInputMessageContext != nil {
		t.Fatalf("no tools must omit userInputMessageContext, got %+v", cur.UserInputMessageContext)
	}
}

func TestBuildOmitsUnsupportedAgentTaskType(t *testing.T) {
	req := buildFromJSON(t, `{
		"model":"claude-sonnet-4-5",
		"messages":[{"role":"user","content":"hi"}]
	}`, kiroCredential{})
	raw, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}
	if strings.Contains(string(raw), "agentTaskType") {
		t.Fatalf("runtime request must omit agentTaskType: %s", raw)
	}
}

func TestBuildHistoryEndsWithAssistant(t *testing.T) {
	// user, assistant, user -> history should be [user, assistant]; current = last user.
	req := buildFromJSON(t, `{
		"model":"claude-sonnet-4-5",
		"messages":[
			{"role":"user","content":"q1"},
			{"role":"assistant","content":"a1"},
			{"role":"user","content":"q2"}
		]
	}`, kiroCredential{})

	hist := req.ConversationState.History
	if len(hist) == 0 {
		t.Fatalf("expected non-empty history")
	}
	last := hist[len(hist)-1]
	if last.AssistantResponseMessage == nil {
		t.Fatalf("history must end with assistantResponseMessage, got %+v", last)
	}
	if req.ConversationState.CurrentMessage.UserInputMessage.Content != "q2" {
		t.Fatalf("unexpected current content: %q", req.ConversationState.CurrentMessage.UserInputMessage.Content)
	}
}

func TestBuildLastAssistantMovedToHistory(t *testing.T) {
	// Ending on assistant: it moves to history and current becomes "Continue".
	req := buildFromJSON(t, `{
		"model":"claude-sonnet-4-5",
		"messages":[
			{"role":"user","content":"q1"},
			{"role":"assistant","content":"a1"}
		]
	}`, kiroCredential{})

	if req.ConversationState.CurrentMessage.UserInputMessage.Content != "Continue" {
		t.Fatalf("expected Continue current message, got %q", req.ConversationState.CurrentMessage.UserInputMessage.Content)
	}
	hist := req.ConversationState.History
	if len(hist) == 0 || hist[len(hist)-1].AssistantResponseMessage == nil {
		t.Fatalf("assistant turn should be in history")
	}
}

func TestBuildToolResultDedupAndProfileArn(t *testing.T) {
	req := buildFromJSON(t, `{
		"model":"claude-sonnet-4-5",
		"messages":[{"role":"user","content":[
			{"type":"tool_result","tool_use_id":"t1","content":"ok"},
			{"type":"tool_result","tool_use_id":"t1","content":"dup"},
			{"type":"text","text":"done"}
		]}]
	}`, kiroCredential{AuthMethod: "IdC", ProfileArn: "arn:aws:codewhisperer:profile/X"})

	ctx := req.ConversationState.CurrentMessage.UserInputMessage.UserInputMessageContext
	if ctx == nil || len(ctx.ToolResults) != 1 {
		t.Fatalf("expected deduped single tool result, got %+v", ctx)
	}
	if req.ProfileArn != "arn:aws:codewhisperer:profile/X" {
		t.Fatalf("profileArn not attached for IdC auth: %q", req.ProfileArn)
	}
}

func TestBuildModelMapping(t *testing.T) {
	req := buildFromJSON(t, `{
		"model":"claude-opus-4-8",
		"messages":[{"role":"user","content":"hi"}]
	}`, kiroCredential{})
	if got := req.ConversationState.CurrentMessage.UserInputMessage.ModelID; got != "claude-opus-4.8" {
		t.Fatalf("expected mapped modelId claude-opus-4.8, got %q", got)
	}
}

func TestBuildImageInput(t *testing.T) {
	req := buildFromJSON(t, `{
		"model":"claude-sonnet-4-5",
		"messages":[{"role":"user","content":[
			{"type":"image","source":{"type":"base64","media_type":"image/png","data":"aGVsbG8="}}
		]}]
	}`, kiroCredential{})

	cur := req.ConversationState.CurrentMessage.UserInputMessage
	if cur.Content != "Image provided." {
		t.Fatalf("expected image placeholder content, got %q", cur.Content)
	}
	if len(cur.Images) != 1 {
		t.Fatalf("expected one image, got %d", len(cur.Images))
	}
	if cur.Images[0].Format != "png" || cur.Images[0].Source.Bytes != "aGVsbG8=" {
		t.Fatalf("unexpected image conversion: %+v", cur.Images[0])
	}
}

func TestBuildInvalidImageIgnored(t *testing.T) {
	req := buildFromJSON(t, `{
		"model":"claude-sonnet-4-5",
		"messages":[{"role":"user","content":[
			{"type":"image","source":{"type":"base64","media_type":"image/png","data":""}},
			{"type":"text","text":"describe this"}
		]}]
	}`, kiroCredential{})

	cur := req.ConversationState.CurrentMessage.UserInputMessage
	if cur.Content != "describe this" || len(cur.Images) != 0 {
		t.Fatalf("invalid image should be ignored: %+v", cur)
	}
}

func TestBuildHistorySystemPreservesFirstImage(t *testing.T) {
	req := buildFromJSON(t, `{
		"model":"claude-sonnet-4-5",
		"system":"Use the image.",
		"messages":[
			{"role":"user","content":[{"type":"image","source":{"type":"base64","media_type":"image/jpeg","data":"aW1hZ2U="}}]},
			{"role":"assistant","content":"I see it."},
			{"role":"user","content":"What is it?"}
		]
	}`, kiroCredential{})

	first := req.ConversationState.History[0].UserInputMessage
	if first == nil || len(first.Images) != 1 || first.Images[0].Format != "jpeg" {
		t.Fatalf("system merge dropped first image: %+v", first)
	}
	if first.Content != "Use the image.\n\nImage provided." {
		t.Fatalf("unexpected system/image content: %q", first.Content)
	}
}
