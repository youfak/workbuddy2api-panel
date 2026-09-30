// tool_pairing.go 出站请求体的孤儿 tool_call↔tool 配对清理 + tool 结果块重排
// （吸收参考仓库 sse.ts:91-123 resolveToolPairing 语义，适配网关的 OpenAI wire 消息形态）。
//
// 背景：OpenAI 兼容协议要求带 tool_calls 的 assistant 消息，其每一个 tool_call id
// 都必须有对应的一条 role:tool 结果消息；反之 role:tool 消息也必须有对应的前置
// tool_call。缺任一侧，上游都会以 HTTP 400 拒绝整个请求。
//
// 工具执行失败时（参数非法、超时、工具不存在……）客户端会把 assistant 的 tool_calls
// 持久化进会话历史，却写不回结果消息。这条坏历史随后被每次请求原样重放——上游对之后
// 每一条用户消息都返回 400，整条会话报废。网关是最后一道防线：发出请求前剔除无法配对
// 的条目让会话自愈，宁可丢一轮工具上下文，也好过整条会话死亡。
package upstream

// repackToolResultBlocks 把插在 assistant.tool_calls 与其 tool 结果之间的非 tool 消息
// 挪到整组之后，保证同一批 tool_call 的结果在 wire 上连续。
//
// 背景：Codex 的 image_resize_notice 特性会把 <image_resize_notice> 作为一条
// developer/system 消息插在 tool 输出后面。并行调用时它插在两份 tool 结果中间：
//
//	assistant tool_calls=[c00 c01]
//	tool c00
//	developer <image_resize_notice>   <- 插在中间
//	tool c01
//
// OpenAI 兼容协议要求 tool 结果紧跟 assistant，中间插任何消息都算配对断裂，上游判
// 11148（tool_call_sequence_broken）并顶死整条会话。这里只调顺序、不改内容：
//
//	assistant tool_calls=[c00 c01] | tool c00 | X | tool c01
//	→ assistant tool_calls=[c00 c01] | tool c00 | tool c01 | X
//
// 结果顺序保持不变（同批 tool_call 的原相对顺序 = 结果顺序），不引入新的顺序敏感
// 问题。无插入消息时零改动零分配（返回原 slice）。
func repackToolResultBlocks(messages []any) ([]any, bool) {
	if len(messages) < 3 {
		return messages, false
	}
	out := make([]any, 0, len(messages))
	changed := false
	i := 0
	for i < len(messages) {
		m, ok := messages[i].(map[string]any)
		if !ok || m["role"] != "assistant" {
			out = append(out, messages[i])
			i++
			continue
		}
		tcs, hasCalls := m["tool_calls"].([]any)
		if !hasCalls || len(tcs) == 0 {
			out = append(out, messages[i])
			i++
			continue
		}
		want := map[string]bool{}
		for _, tci := range tcs {
			if tc, ok := tci.(map[string]any); ok {
				if id, _ := tc["id"].(string); id != "" {
					want[id] = true
				}
			}
		}
		// 收集紧随其后（允许被其他消息打断）的同批 tool 结果，按原相对顺序。
		out = append(out, messages[i])
		i++
		var results []any
		var between []any
		sawNonTool := false
		for i < len(messages) {
			mm, ok := messages[i].(map[string]any)
			if !ok {
				break
			}
			role, _ := mm["role"].(string)
			if role == "tool" {
				id, _ := mm["tool_call_id"].(string)
				if !want[id] {
					break
				}
				results = append(results, messages[i])
				if sawNonTool {
					changed = true
				}
				i++
				continue
			}
			if len(results) == 0 {
				break // assistant 后没有结果：交由 cleanupOrphanToolCalls 处理
			}
			// 下一组 assistant.tool_calls 是新的组头，绝不能当插入物吞掉：一旦被收进
			// between，它永远不再被外层循环当作组头处理，它自己那批结果也就永远得不
			// 到重排（真实会话 msg[181] 正是这样漏掉的）。必须 break 交还外层循环。
			if role == "assistant" {
				if next, _ := mm["tool_calls"].([]any); len(next) > 0 {
					break
				}
			}
			// 同批结果尚未收齐时，中间消息视为插入物，暂存待后移。
			between = append(between, messages[i])
			sawNonTool = true
			i++
		}
		out = append(out, results...)
		out = append(out, between...)
	}
	if !changed {
		return messages, false
	}
	return out, true
}

// cleanupOrphanToolCalls 剔除无法配对的 tool_call 与 tool 结果（所有模型，独立于
// deepseek-only 的 sanitize 开关）。语义对齐参考仓库 resolveToolPairing：
//
//   - 收集全线 role:tool 消息的 tool_call_id（结果集）与 assistant.tool_calls[].id（调用集）；
//   - 一批 assistant.tool_calls 按 keepCalls 对称裁剪：只留有结果配对的调用（部分保留
//     不会留下无结果的 tool_call），过滤后为空才删掉整个 tool_calls 键；
//   - role:tool 只在对应 tool_call 被保留时才保留，否则删除整条消息；
//   - 无任何工具流量 → 原 slice 原样返回，changed=false（零分配零改动）。
//
// 这是「让请求通过」的安全网：只要存在合法配对就整段保留这些字段，绝不吞掉正确配对。
// 返回清理后的 slice（无改动时等于原 slice，勿依赖其是否新分配）及是否发生删除。
func cleanupOrphanToolCalls(messages []any) ([]any, bool) {
	if len(messages) == 0 {
		return messages, false
	}
	// 普通的 role:tool 文本（没有 tool_call_id，且请求中没有 assistant.tool_calls）
	// 可能只是客户端自定义消息；没有工具配对流量时保持原样，避免把未知 role 当成
	// 网关错误。只要出现任一带 ID 的工具调用/结果，才进入严格配对清理。
	hasPairTraffic := false
	for _, raw := range messages {
		msg, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		if role, _ := msg["role"].(string); role == "assistant" {
			if tcs, ok := msg["tool_calls"].([]any); ok && len(tcs) > 0 {
				hasPairTraffic = true
				break
			}
		}
		if role, _ := msg["role"].(string); role == "tool" {
			if id, _ := msg["tool_call_id"].(string); id != "" {
				hasPairTraffic = true
				break
			}
		}
	}
	if !hasPairTraffic {
		return messages, false
	}
	changed := false
	kept := make([]any, 0, len(messages))
	for i := 0; i < len(messages); {
		msg, ok := messages[i].(map[string]any)
		if !ok {
			kept = append(kept, messages[i])
			i++
			continue
		}
		role, _ := msg["role"].(string)
		if role != "assistant" {
			if role == "tool" {
				// 结果只能在其所属 assistant.tool_calls 之后出现；任何游离结果
				// 都会触发上游 11148，直接丢弃。
				changed = true
				i++
				continue
			}
			kept = append(kept, messages[i])
			i++
			continue
		}

		tcs, hasCalls := msg["tool_calls"].([]any)
		if !hasCalls || len(tcs) == 0 {
			kept = append(kept, messages[i])
			i++
			continue
		}

		// 以当前 assistant 为边界按顺序配对，不能再用全局 ID 集合：全局集合会
		// 把「先出现的孤儿结果」或「后续批次的同 ID 结果」错误地认成合法配对。
		calls := make([]any, 0, len(tcs))
		callIDs := map[string]bool{}
		for _, rawCall := range tcs {
			call, ok := rawCall.(map[string]any)
			id, valid := "", false
			if ok {
				id, valid = call["id"].(string)
				valid = valid && id != ""
			}
			if !valid || callIDs[id] {
				changed = true
				continue
			}
			callIDs[id] = true
			calls = append(calls, call)
		}

		j := i + 1
		results := make([]any, 0, len(calls))
		resultIDs := map[string]bool{}
		between := make([]any, 0)
		for j < len(messages) {
			next, ok := messages[j].(map[string]any)
			if !ok {
				break
			}
			nextRole, _ := next["role"].(string)
			if nextRole == "tool" {
				id, _ := next["tool_call_id"].(string)
				if !callIDs[id] {
					break
				}
				// 同一 call 的第二个结果也是坏历史；消费并丢弃，避免它
				// 留在输出中继续触发 11148。
				if resultIDs[id] {
					changed = true
					j++
					continue
				}
				resultIDs[id] = true
				results = append(results, messages[j])
				j++
				continue
			}
			// system/developer 是已知的流间噪声，可在结果块内外暂存到末尾；
			// user/assistant 则意味着本批配对已经断开，不能跨轮搬运。
			if nextRole == "system" || nextRole == "developer" {
				between = append(between, messages[j])
				j++
				continue
			}
			break
		}

		if len(results) == 0 {
			delete(msg, "tool_calls")
			changed = true
			kept = append(kept, msg)
			kept = append(kept, between...)
			if len(between) > 0 {
				i = j
			} else {
				i++
			}
			continue
		}
		keptCalls := make([]any, 0, len(calls))
		for _, call := range calls {
			id := call.(map[string]any)["id"].(string)
			if resultIDs[id] {
				keptCalls = append(keptCalls, call)
			}
		}
		if len(keptCalls) != len(tcs) || len(keptCalls) != len(calls) {
			changed = true
		}
		if len(keptCalls) == 0 {
			delete(msg, "tool_calls")
			changed = true
		} else {
			msg["tool_calls"] = keptCalls
		}
		kept = append(kept, msg)
		kept = append(kept, results...)
		if len(between) > 0 {
			changed = true
			kept = append(kept, between...)
		}
		i = j
	}
	if !changed {
		return messages, false
	}
	return kept, true
}
