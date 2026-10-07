package server

import (
	"io"
	"net/http"
	"net/http/httptest"

	"github.com/linguo2625469/workbuddy2api-panel/internal/apikey"
	"github.com/linguo2625469/workbuddy2api-panel/internal/livecfg"
)

// /v1/* 是 fail closed 的：api_keys 为空时一律 401。绝大多数用例验证的是网关行为
// 而不是鉴权，所以这里统一注入一枚测试密钥：
//   - testV1Handler 代替 NewHandler 构造 handler
//   - v1Req 代替 httptest.NewRequest 构造 /v1 请求（自动带 Authorization）
//
// 需要验证鉴权本身的用例（TestAPIKeyAuth）仍直接用 NewHandler / httptest.NewRequest。
var testV1Record, testV1Key = mustTestV1Key()

func mustTestV1Key() (apikey.Record, string) {
	rec, key, err := apikey.Create("test-v1")
	if err != nil {
		panic("create test API key: " + err.Error())
	}
	return rec, key
}

// testV1Handler 等价于 NewHandler，但在 cfg.Live 缺省时装入一枚测试密钥。
// 快照同时补齐 loadLive() 回退会填的两个字段，保证原先依赖 Config 回退的用例
// （软冷却基数、调用来源记录）语义不变。
func testV1Handler(cfg Config) *Handler {
	if cfg.Live == nil {
		cfg.Live = livecfg.New(livecfg.Snapshot{
			APIKeys:          []apikey.Record{testV1Record},
			SoftCooldown:     cfg.SoftCooldown,
			RecordClientInfo: cfg.RecordClientInfo,
		})
	}
	return NewHandler(cfg)
}

// v1Req 构造带测试密钥的 /v1 请求。
func v1Req(method, target string, body io.Reader) *http.Request {
	req := httptest.NewRequest(method, target, body)
	req.Header.Set("Authorization", "Bearer "+testV1Key)
	return req
}
