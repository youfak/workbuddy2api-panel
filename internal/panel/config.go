// config.go 面板配置页接口：读取当前配置、校验并保存（热生效 + 重启项标注）。
//
// 分工：cmd/server 持有 Config 类型与校验逻辑（Load/normalize），此处只做
// HTTP 编排——GET 回显、POST 透传给注入的 SaveConfig 闭包（由 main 完成
// "校验 → 落盘 → 热应用 → 返回需重启字段列表"）。
package panel

import (
	"encoding/json"
	"io"
	"log"
	"net/http"
	"strings"
)

// getConfig 返回当前配置文件内容与路径（前端按 schema 渲染表单）。
func (p *Panel) getConfig(w http.ResponseWriter, r *http.Request) {
	if p.cfg.LoadConfig == nil {
		writeErr(w, http.StatusNotImplemented, "config api not available")
		return
	}
	cfg, err := p.cfg.LoadConfig()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "load config: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":     true,
		"path":   p.cfg.ConfigPath,
		"config": sanitizeConfigForPanel(cfg),
	})
}

func sanitizeConfigForPanel(cfg any) any {
	raw, err := json.Marshal(cfg)
	if err != nil {
		return cfg
	}
	var out map[string]any
	if json.Unmarshal(raw, &out) != nil {
		return cfg
	}
	if panelCfg, ok := out["panel"].(map[string]any); ok {
		delete(panelCfg, "admin_password_hash")
	}
	delete(out, "api_keys")
	return out
}

// saveConfig 保存配置：body 直接是配置 JSON（前端按 schema 组装完整对象）。
// SaveConfig 闭包内部完成校验+落盘+热应用；校验失败返回 400 且不写盘。
func (p *Panel) saveConfig(w http.ResponseWriter, r *http.Request) {
	p.configMu.Lock()
	defer p.configMu.Unlock()
	if p.cfg.SaveConfig == nil {
		writeErr(w, http.StatusNotImplemented, "config api not available")
		return
	}
	raw, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "read body: "+err.Error())
		return
	}
	var submitted map[string]json.RawMessage
	if json.Unmarshal(raw, &submitted) == nil {
		if _, ok := submitted["api_key"]; ok {
			writeErr(w, http.StatusBadRequest, "api_key is no longer supported; use WebUI API key management")
			return
		}
		if _, ok := submitted["api_keys"]; ok {
			writeErr(w, http.StatusBadRequest, "api_keys must be managed through the WebUI key management endpoints")
			return
		}
		if panelRaw, ok := submitted["panel"]; ok {
			var panelCfg map[string]json.RawMessage
			if json.Unmarshal(panelRaw, &panelCfg) == nil {
				if _, ok := panelCfg["admin_password_hash"]; ok {
					writeErr(w, http.StatusBadRequest, "panel admin password must be changed through the login setup endpoint")
					return
				}
			}
		}
	}
	restartRequired, err := p.cfg.SaveConfig(raw)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if restartRequired == nil {
		restartRequired = []string{}
	}
	log.Printf("panel: 配置已保存（热生效完成；需重启字段 %d 个）", len(restartRequired))
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":               true,
		"restart_required": restartRequired,
	})
}

func (p *Panel) listAPIKeys(w http.ResponseWriter, r *http.Request) {
	if p.cfg.ListAPIKeys == nil {
		writeErr(w, http.StatusNotImplemented, "api key management is not available")
		return
	}
	keys, err := p.cfg.ListAPIKeys()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "load api keys: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "keys": keys})
}

func (p *Panel) createAPIKey(w http.ResponseWriter, r *http.Request) {
	p.configMu.Lock()
	defer p.configMu.Unlock()
	if p.cfg.CreateAPIKey == nil {
		writeErr(w, http.StatusNotImplemented, "api key generation is not available")
		return
	}
	var body struct {
		Name string `json:"name"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<12)).Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	name := strings.TrimSpace(body.Name)
	if name == "" || len(name) > 64 {
		writeErr(w, http.StatusBadRequest, "api key name must be 1 to 64 characters")
		return
	}
	item, key, err := p.cfg.CreateAPIKey(name)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "create api key: "+err.Error())
		return
	}
	if !strings.HasPrefix(key, "sk-") || len(key) <= len("sk-") {
		writeErr(w, http.StatusInternalServerError, "generated api key has invalid format")
		return
	}
	log.Printf("panel: AI API 密钥已通过 WebUI 生成并热生效")
	writeJSON(w, http.StatusCreated, map[string]any{"ok": true, "key": key, "item": item})
}

func (p *Panel) deleteAPIKey(w http.ResponseWriter, r *http.Request) {
	p.configMu.Lock()
	defer p.configMu.Unlock()
	if p.cfg.DeleteAPIKey == nil {
		writeErr(w, http.StatusNotImplemented, "api key management is not available")
		return
	}
	id := r.PathValue("id")
	if !validAPIKeyID(id) {
		writeErr(w, http.StatusBadRequest, "invalid api key id")
		return
	}
	if err := p.cfg.DeleteAPIKey(id); err != nil {
		writeErr(w, http.StatusInternalServerError, "delete api key: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func validAPIKeyID(id string) bool {
	if len(id) != 24 {
		return false
	}
	for _, c := range id {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}
