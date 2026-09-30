package upstream

import "testing"

func toolCall(id string) map[string]any {
	return map[string]any{
		"id":   id,
		"type": "function",
		"function": map[string]any{
			"name":      "echo",
			"arguments": "{}",
		},
	}
}

func countRole(messages []any, role string) int {
	n := 0
	for _, raw := range messages {
		msg, _ := raw.(map[string]any)
		if msg != nil && msg["role"] == role {
			n++
		}
	}
	return n
}

func TestCleanupOrphanToolCallsDropsResultBeforeCall(t *testing.T) {
	messages := []any{
		map[string]any{"role": "tool", "tool_call_id": "c1", "content": "stale"},
		map[string]any{"role": "assistant", "content": nil, "tool_calls": []any{toolCall("c1")}},
		map[string]any{"role": "user", "content": "continue"},
	}
	out, changed := cleanupOrphanToolCalls(messages)
	if !changed {
		t.Fatal("expected out-of-order tool result to be removed")
	}
	if countRole(out, "tool") != 0 {
		t.Fatalf("out-of-order tool result survived: %#v", out)
	}
	assistant := out[0].(map[string]any)
	if _, ok := assistant["tool_calls"]; ok {
		t.Fatalf("assistant tool_calls without a following result survived: %#v", assistant)
	}
}

func TestCleanupOrphanToolCallsDropsDuplicateResults(t *testing.T) {
	messages := []any{
		map[string]any{"role": "assistant", "content": nil, "tool_calls": []any{toolCall("c1")}},
		map[string]any{"role": "tool", "tool_call_id": "c1", "content": "first"},
		map[string]any{"role": "tool", "tool_call_id": "c1", "content": "duplicate"},
		map[string]any{"role": "user", "content": "continue"},
	}
	out, changed := cleanupOrphanToolCalls(messages)
	if !changed {
		t.Fatal("expected duplicate tool result to be removed")
	}
	if countRole(out, "tool") != 1 {
		t.Fatalf("want one tool result, got %#v", out)
	}
}

func TestCleanupOrphanToolCallsPreservesInterleavedSystemMessage(t *testing.T) {
	messages := []any{
		map[string]any{"role": "assistant", "content": nil, "tool_calls": []any{toolCall("c1"), toolCall("c2")}},
		map[string]any{"role": "tool", "tool_call_id": "c1", "content": "first"},
		map[string]any{"role": "system", "content": "resize notice"},
		map[string]any{"role": "tool", "tool_call_id": "c2", "content": "second"},
		map[string]any{"role": "user", "content": "continue"},
	}
	out, changed := cleanupOrphanToolCalls(messages)
	if !changed {
		t.Fatal("expected system message to be moved behind the tool result block")
	}
	if len(out) != 5 {
		t.Fatalf("output length=%d want 5: %#v", len(out), out)
	}
	if out[1].(map[string]any)["role"] != "tool" || out[2].(map[string]any)["role"] != "tool" || out[3].(map[string]any)["role"] != "system" {
		t.Fatalf("tool results were not kept contiguous: %#v", out)
	}
}

func TestCleanupOrphanToolCallsPreservesStandaloneToolMessage(t *testing.T) {
	messages := []any{map[string]any{"role": "tool", "content": "custom tool text"}}
	out, changed := cleanupOrphanToolCalls(messages)
	if changed || len(out) != 1 || out[0].(map[string]any)["role"] != "tool" {
		t.Fatalf("standalone tool message changed: changed=%v out=%#v", changed, out)
	}
}
