package panel

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/linguo2625469/workbuddy2api-panel/internal/apikey"
)

func newTestPanel() *Panel {
	return New(Config{Version: "test"})
}

// 面板安全响应头必须覆盖：页面、静态脚本、鉴权失败响应。
func TestSecurityHeadersOnAllPanelResponses(t *testing.T) {
	p := newTestPanel()
	paths := []struct{ method, path string }{
		{"GET", "/panel/"},
		{"GET", "/panel/app.js"},
		{"GET", "/panel/api/overview"}, // 401（未提供 key）
		{"POST", "/panel/api/config"},  // 401
		{"GET", "/panel/api/nonexistent"},
	}
	for _, c := range paths {
		rec := httptest.NewRecorder()
		p.ServeHTTP(rec, httptest.NewRequest(c.method, c.path, nil))
		h := rec.Header()
		if got := h.Get("Content-Security-Policy"); got == "" {
			t.Errorf("%s %s: missing CSP", c.method, c.path)
		}
		if h.Get("X-Content-Type-Options") != "nosniff" {
			t.Errorf("%s %s: X-Content-Type-Options=%q", c.method, c.path, h.Get("X-Content-Type-Options"))
		}
		if h.Get("X-Frame-Options") != "DENY" {
			t.Errorf("%s %s: X-Frame-Options=%q", c.method, c.path, h.Get("X-Frame-Options"))
		}
		if h.Get("Referrer-Policy") != "no-referrer" {
			t.Errorf("%s %s: Referrer-Policy=%q", c.method, c.path, h.Get("Referrer-Policy"))
		}
	}
}

// CSP 必须禁止内联脚本与 iframe 嵌套（严格策略的核心约束）。
func TestCSPDisallowsInlineScriptAndFraming(t *testing.T) {
	p := newTestPanel()
	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, httptest.NewRequest("GET", "/panel/", nil))
	csp := rec.Header().Get("Content-Security-Policy")

	for _, must := range []string{
		"script-src 'self'",
		"frame-ancestors 'none'",
		"base-uri 'none'",
		"default-src 'none'",
	} {
		if !strings.Contains(csp, must) {
			t.Errorf("CSP missing %q; got: %s", must, csp)
		}
	}
	if strings.Contains(csp, "script-src 'self' 'unsafe-inline'") || strings.Contains(csp, "script-src 'unsafe-inline'") {
		t.Errorf("CSP must not allow unsafe-inline scripts; got: %s", csp)
	}
}

// 页面必须引用外部脚本（内联脚本会被上面的 CSP 拦掉，页面将完全不可用）。
func TestIndexReferencesExternalScript(t *testing.T) {
	p := newTestPanel()
	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, httptest.NewRequest("GET", "/panel/", nil))
	body := rec.Body.String()

	if !strings.Contains(body, `<script src="app.js"></script>`) {
		t.Error("index.html must load app.js externally (inline script is blocked by CSP)")
	}
	// 反例保护：出现内联 <script>...</script> 内容块即为回归
	if strings.Contains(body, "<script>\n") || strings.Contains(body, "<script> ") {
		t.Error("index.html still contains an inline <script> block; CSP would block it")
	}
}

// app.js 必须能作为同源脚本取到且类型正确（否则页面白屏）。
func TestAppScriptServed(t *testing.T) {
	p := newTestPanel()
	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, httptest.NewRequest("GET", "/panel/app.js", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("code=%d want 200", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.Contains(ct, "javascript") {
		t.Errorf("Content-Type=%q want javascript", ct)
	}
	if !strings.Contains(rec.Body.String(), "'use strict'") {
		t.Error("app.js body looks wrong")
	}
}

// UID 白名单：拒绝路径穿越与异常字符，放行真实 UUID 形态。
func TestValidUID(t *testing.T) {
	ok := []string{
		"248890d9-bb26-4131-87a7-4ec74d472344",
		"abc_123-XYZ",
		"a",
	}
	bad := []string{
		"",
		"../../evil",
		"x/../../y",
		`..\..\evil`,
		"a/b",
		"a\\b",
		"uid with space",
		"uid\nnewline",
		"uid\x00null",
		"café",
		strings.Repeat("a", 65), // 超长
	}
	for _, u := range ok {
		if !validUID(u) {
			t.Errorf("validUID(%q) = false, want true", u)
		}
	}
	for _, u := range bad {
		if validUID(u) {
			t.Errorf("validUID(%q) = true, want false", u)
		}
	}
}

// 面板不接受 Bearer AI 密钥，未登录请求必须被拒绝。
func TestAuthLayerBehavior(t *testing.T) {
	p := newTestPanel()
	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, httptest.NewRequest("GET", "/panel/api/overview", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("no session: code=%d want 401", rec.Code)
	}
	rec2 := httptest.NewRecorder()
	req2 := httptest.NewRequest("GET", "/panel/api/nonexistent", nil)
	req2.Header.Set("Authorization", "Bearer sk-ai-only")
	p.ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusNotFound {
		t.Fatalf("unknown path code=%d want 404", rec2.Code)
	}
}

func TestPanelSessionRejectsAPIKeyAndExpiresOnLogout(t *testing.T) {
	var savedHash string; _ = savedHash
	p := New(Config{
		SavePanelPassword: func(hash string) error {
			savedHash = hash
			return nil
		},
	})

	apiKeyRequest := httptest.NewRequest(http.MethodGet, "/panel/api/overview", nil)
	apiKeyRequest.Header.Set("Authorization", "Bearer sk-ai-only")
	apiKeyResult := httptest.NewRecorder()
	p.ServeHTTP(apiKeyResult, apiKeyRequest)
	if apiKeyResult.Code != http.StatusUnauthorized {
		t.Fatalf("api key reached panel: code=%d", apiKeyResult.Code)
	}

	setup := httptest.NewRequest(http.MethodPost, "/panel/api/auth/setup", bytes.NewBufferString(`{"password":"correct-horse-battery-staple"}`))
	setup.RemoteAddr = "127.0.0.1:41000"
	setupResult := httptest.NewRecorder()
	p.ServeHTTP(setupResult, setup)
	if setupResult.Code != http.StatusOK || savedHash == "" {
		t.Fatalf("setup code=%d body=%s hash=%q", setupResult.Code, setupResult.Body.String(), savedHash)
	}
	cookies := setupResult.Result().Cookies()
	if len(cookies) != 1 || !cookies[0].HttpOnly || cookies[0].SameSite != http.SameSiteStrictMode {
		t.Fatalf("unsafe login cookie: %+v", cookies)
	}

	withSession := httptest.NewRequest(http.MethodGet, "/panel/api/config", nil)
	withSession.AddCookie(cookies[0])
	withSessionResult := httptest.NewRecorder()
	p.ServeHTTP(withSessionResult, withSession)
	if withSessionResult.Code == http.StatusUnauthorized {
		t.Fatalf("session cookie was rejected: %s", withSessionResult.Body.String())
	}

	logout := httptest.NewRequest(http.MethodPost, "/panel/api/auth/logout", nil)
	logout.AddCookie(cookies[0])
	logoutResult := httptest.NewRecorder()
	p.ServeHTTP(logoutResult, logout)
	if logoutResult.Code != http.StatusOK {
		t.Fatalf("logout code=%d body=%s", logoutResult.Code, logoutResult.Body.String())
	}

	afterLogout := httptest.NewRequest(http.MethodGet, "/panel/api/config", nil)
	afterLogout.AddCookie(cookies[0])
	afterLogoutResult := httptest.NewRecorder()
	p.ServeHTTP(afterLogoutResult, afterLogout)
	if afterLogoutResult.Code != http.StatusUnauthorized {
		t.Fatalf("logged-out session code=%d want 401", afterLogoutResult.Code)
	}
}

func TestPanelSetupAllowsRemoteManagement(t *testing.T) {
	p := New(Config{SavePanelPassword: func(string) error { return nil }})
	req := httptest.NewRequest(http.MethodPost, "/panel/api/auth/setup", bytes.NewBufferString(`{"password":"correct-horse-battery-staple"}`))
	req.RemoteAddr = "198.51.100.10:41000"
	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("remote setup code=%d body=%s", rec.Code, rec.Body.String())
	}
}

func TestPanelSetupRejectsShortPasswordWithClearMessage(t *testing.T) {
	p := New(Config{SavePanelPassword: func(string) error { return nil }})
	req := httptest.NewRequest(http.MethodPost, "/panel/api/auth/setup", bytes.NewBufferString(`{"password":"short"}`))
	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "至少 12 个字符") {
		t.Fatalf("short password response: code=%d body=%s", rec.Code, rec.Body.String())
	}
}

func TestAPIKeyManagerReturnsPlaintextOnlyOnCreate(t *testing.T) {
	var records []apikey.Record
	p := New(Config{
		SavePanelPassword: func(string) error { return nil },
		ListAPIKeys:       func() ([]apikey.PublicRecord, error) { return apikey.Public(records), nil },
		CreateAPIKey: func(name string) (apikey.PublicRecord, string, error) {
			record, plain, err := apikey.Create(name)
			if err != nil {
				return apikey.PublicRecord{}, "", err
			}
			records = append(records, record)
			return apikey.Public([]apikey.Record{record})[0], plain, nil
		},
	})
	setup := httptest.NewRequest(http.MethodPost, "/panel/api/auth/setup", bytes.NewBufferString(`{"password":"correct-horse-battery-staple"}`))
	setup.RemoteAddr = "127.0.0.1:41000"
	setupResult := httptest.NewRecorder()
	p.ServeHTTP(setupResult, setup)
	cookie := setupResult.Result().Cookies()[0]

	create := httptest.NewRequest(http.MethodPost, "/panel/api/api-keys", bytes.NewBufferString(`{"name":"cli"}`))
	create.AddCookie(cookie)
	createResult := httptest.NewRecorder()
	p.ServeHTTP(createResult, create)
	if createResult.Code != http.StatusCreated {
		t.Fatalf("create code=%d body=%s", createResult.Code, createResult.Body.String())
	}
	var created struct {
		Key  string              `json:"key"`
		Item apikey.PublicRecord `json:"item"`
	}
	if err := json.Unmarshal(createResult.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(created.Key, "sk-") || created.Item.Masked == created.Key {
		t.Fatalf("created=%+v", created)
	}

	list := httptest.NewRequest(http.MethodGet, "/panel/api/api-keys", nil)
	list.AddCookie(cookie)
	listResult := httptest.NewRecorder()
	p.ServeHTTP(listResult, list)
	if listResult.Code != http.StatusOK || strings.Contains(listResult.Body.String(), created.Key) || strings.Contains(listResult.Body.String(), records[0].Hash) {
		t.Fatalf("list leaked key material: code=%d body=%s", listResult.Code, listResult.Body.String())
	}
}

func TestConfigResponseDoesNotExposeKeyHashes(t *testing.T) {
	p := New(Config{
		LoadConfig: func() (any, error) {
			return map[string]any{
				"api_keys": []map[string]string{{"id": "0123456789abcdef01234567", "hash": "secret-hash"}},
				"panel":    map[string]string{"admin_password_hash": "secret-password-hash"},
			}, nil
		},
	})
	p.sessions["test-session"] = panelSession{expiresAt: time.Now().Add(time.Hour)}
	req := httptest.NewRequest(http.MethodGet, "/panel/api/config", nil)
	req.AddCookie(&http.Cookie{Name: panelSessionCookie, Value: "test-session"})
	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || strings.Contains(rec.Body.String(), "secret-hash") || strings.Contains(rec.Body.String(), "secret-password-hash") {
		t.Fatalf("config response leaked secret: code=%d body=%s", rec.Code, rec.Body.String())
	}
}

func TestAuthChangePassword(t *testing.T) {
	var savedHash string
	_ = savedHash
	p := New(Config{
		SavePanelPassword: func(hash string) error {
			savedHash = hash
			return nil
		},
	})

	// 1. 初始化密码
	setup := httptest.NewRequest(http.MethodPost, "/panel/api/auth/setup", bytes.NewBufferString(`{"password":"initial-password-123"}`))
	setupResult := httptest.NewRecorder()
	p.ServeHTTP(setupResult, setup)
	if setupResult.Code != http.StatusOK {
		t.Fatalf("setup failed: %d %s", setupResult.Code, setupResult.Body.String())
	}
	cookie := setupResult.Result().Cookies()[0]

	// 2. 未登录修改密码 -> 401
	unauthReq := httptest.NewRequest(http.MethodPost, "/panel/api/auth/password", bytes.NewBufferString(`{"oldPassword":"initial-password-123","newPassword":"new-password-456"}`))
	unauthRec := httptest.NewRecorder()
	p.ServeHTTP(unauthRec, unauthReq)
	if unauthRec.Code != http.StatusUnauthorized {
		t.Fatalf("unauth want 401, got %d", unauthRec.Code)
	}

	// 3. 旧密码错误 -> 401
	wrongOldReq := httptest.NewRequest(http.MethodPost, "/panel/api/auth/password", bytes.NewBufferString(`{"oldPassword":"wrong-password-999","newPassword":"new-password-456"}`))
	wrongOldReq.AddCookie(cookie)
	wrongOldRec := httptest.NewRecorder()
	p.ServeHTTP(wrongOldRec, wrongOldReq)
	if wrongOldRec.Code != http.StatusUnauthorized || !strings.Contains(wrongOldRec.Body.String(), "当前管理密码错误") {
		t.Fatalf("wrong old password want 401 error, got %d: %s", wrongOldRec.Code, wrongOldRec.Body.String())
	}

	// 4. 新密码过短 -> 400
	shortReq := httptest.NewRequest(http.MethodPost, "/panel/api/auth/password", bytes.NewBufferString(`{"oldPassword":"initial-password-123","newPassword":"short"}`))
	shortReq.AddCookie(cookie)
	shortRec := httptest.NewRecorder()
	p.ServeHTTP(shortRec, shortReq)
	if shortRec.Code != http.StatusBadRequest {
		t.Fatalf("short new password want 400, got %d", shortRec.Code)
	}

	// 5. 成功修改密码 -> 200，并签发新会话 Cookie
	okReq := httptest.NewRequest(http.MethodPost, "/panel/api/auth/password", bytes.NewBufferString(`{"oldPassword":"initial-password-123","newPassword":"new-password-456"}`))
	okReq.AddCookie(cookie)
	okRec := httptest.NewRecorder()
	p.ServeHTTP(okRec, okReq)
	if okRec.Code != http.StatusOK {
		t.Fatalf("change password failed: %d %s", okRec.Code, okRec.Body.String())
	}
	newCookies := okRec.Result().Cookies()
	if len(newCookies) != 1 {
		t.Fatalf("expected new session cookie on change password")
	}

	// 6. 使用新 Cookie 能够正常访问
	cfgReq := httptest.NewRequest(http.MethodGet, "/panel/api/config", nil)
	cfgReq.AddCookie(newCookies[0])
	cfgRec := httptest.NewRecorder()
	p.ServeHTTP(cfgRec, cfgReq)
	if cfgRec.Code == http.StatusUnauthorized {
		t.Fatalf("new session cookie was rejected")
	}

	// 7. 使用新密码能够正常登录
	loginReq := httptest.NewRequest(http.MethodPost, "/panel/api/auth/login", bytes.NewBufferString(`{"password":"new-password-456"}`))
	loginRec := httptest.NewRecorder()
	p.ServeHTTP(loginRec, loginReq)
	if loginRec.Code != http.StatusOK {
		t.Fatalf("login with new password failed: %d %s", loginRec.Code, loginRec.Body.String())
	}

	// 8. 使用旧密码不能再登录
	oldLoginReq := httptest.NewRequest(http.MethodPost, "/panel/api/auth/login", bytes.NewBufferString(`{"password":"initial-password-123"}`))
	oldLoginRec := httptest.NewRecorder()
	p.ServeHTTP(oldLoginRec, oldLoginReq)
	if oldLoginRec.Code != http.StatusUnauthorized {
		t.Fatalf("login with old password should fail, got: %d", oldLoginRec.Code)
	}
}
