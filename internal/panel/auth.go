package panel

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const (
	panelSessionCookie = "wb2api_panel_session"
	panelSessionTTL    = 12 * time.Hour
	passwordIterations = 210000
	passwordKeyLength  = 32
)

type panelSession struct {
	expiresAt time.Time
}

type passwordRequest struct {
	Password string `json:"password"`
}

// withSession 是面板与 /status 共用的管理会话闸门。AI API 密钥不参与此路径。
func (p *Panel) withSession(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !p.hasSession(r) {
			writeErr(w, http.StatusUnauthorized, "panel_login_required")
			return
		}
		next(w, r)
	}
}

// WithSession 供主路由保护非 AI 的管理端点（当前为 /status）。
func (p *Panel) WithSession(next http.HandlerFunc) http.HandlerFunc {
	return p.withSession(next)
}

func (p *Panel) authStatus(w http.ResponseWriter, r *http.Request) {
	p.authMu.Lock()
	configured := p.panelPasswordHash != ""
	p.cleanupSessionsLocked(time.Now())
	_, authenticated := p.sessionLocked(r, time.Now())
	p.authMu.Unlock()
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":            true,
		"configured":    configured,
		"authenticated": authenticated,
	})
}

// authSetup 只在尚未配置管理密码时可调用，成功后立即关闭首次设置入口。
func (p *Panel) authSetup(w http.ResponseWriter, r *http.Request) {
	password, err := readPassword(r)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := validatePanelPassword(password); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}

	p.configMu.Lock()
	defer p.configMu.Unlock()
	p.authMu.Lock()
	if p.panelPasswordHash != "" {
		p.authMu.Unlock()
		writeErr(w, http.StatusConflict, "panel_password_already_configured")
		return
	}
	p.authMu.Unlock()
	if p.cfg.SavePanelPassword == nil {
		writeErr(w, http.StatusNotImplemented, "panel login setup is not available")
		return
	}
	hash, err := hashPanelPassword(password)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "hash panel password: "+err.Error())
		return
	}
	if err := p.cfg.SavePanelPassword(hash); err != nil {
		writeErr(w, http.StatusInternalServerError, "save panel password: "+err.Error())
		return
	}
	p.authMu.Lock()
	p.panelPasswordHash = hash
	p.sessions = map[string]panelSession{}
	p.authMu.Unlock()
	if err := p.createSession(w, r); err != nil {
		writeErr(w, http.StatusInternalServerError, "create panel session: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (p *Panel) authLogin(w http.ResponseWriter, r *http.Request) {
	password, err := readPassword(r)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	p.authMu.Lock()
	hash := p.panelPasswordHash
	p.authMu.Unlock()
	if hash == "" {
		writeErr(w, http.StatusConflict, "panel_setup_required")
		return
	}
	if !verifyPanelPassword(password, hash) {
		writeErr(w, http.StatusUnauthorized, "invalid_panel_password")
		return
	}
	if err := p.createSession(w, r); err != nil {
		writeErr(w, http.StatusInternalServerError, "create panel session: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (p *Panel) authLogout(w http.ResponseWriter, r *http.Request) {
	// 面板当前只有一个管理员密码，退出时清掉全部内存会话，确保任何已发出的
	// Cookie 都不能继续访问管理接口。
	p.authMu.Lock()
	p.sessions = map[string]panelSession{}
	p.authMu.Unlock()
	http.SetCookie(w, &http.Cookie{
		Name: panelSessionCookie, Value: "", Path: "/", MaxAge: -1,
		HttpOnly: true, SameSite: http.SameSiteStrictMode, Secure: r.TLS != nil,
	})
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (p *Panel) hasSession(r *http.Request) bool {
	p.authMu.Lock()
	defer p.authMu.Unlock()
	now := time.Now()
	p.cleanupSessionsLocked(now)
	_, ok := p.sessionLocked(r, now)
	return ok
}

func (p *Panel) panelLoginConfigured() bool {
	p.authMu.Lock()
	defer p.authMu.Unlock()
	return p.panelPasswordHash != ""
}

func (p *Panel) sessionLocked(r *http.Request, now time.Time) (panelSession, bool) {
	cookie, err := r.Cookie(panelSessionCookie)
	if err != nil || cookie.Value == "" {
		return panelSession{}, false
	}
	sess, ok := p.sessions[cookie.Value]
	if !ok || !sess.expiresAt.After(now) {
		return panelSession{}, false
	}
	return sess, true
}

func (p *Panel) cleanupSessionsLocked(now time.Time) {
	for id, sess := range p.sessions {
		if !sess.expiresAt.After(now) {
			delete(p.sessions, id)
		}
	}
}

func (p *Panel) createSession(w http.ResponseWriter, r *http.Request) error {
	id, err := randomPanelSessionID()
	if err != nil {
		return err
	}
	now := time.Now()
	p.authMu.Lock()
	p.cleanupSessionsLocked(now)
	p.sessions[id] = panelSession{expiresAt: now.Add(panelSessionTTL)}
	p.authMu.Unlock()
	http.SetCookie(w, &http.Cookie{
		Name:     panelSessionCookie,
		Value:    id,
		Path:     "/",
		MaxAge:   int(panelSessionTTL.Seconds()),
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		Secure:   r.TLS != nil,
	})
	return nil
}

func readPassword(r *http.Request) (string, error) {
	raw, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		return "", fmt.Errorf("read password: %w", err)
	}
	var body passwordRequest
	if err := json.Unmarshal(raw, &body); err != nil {
		return "", fmt.Errorf("parse password: %w", err)
	}
	return body.Password, nil
}

func validatePanelPassword(password string) error {
	if len(password) < 12 || len(password) > 256 {
		return fmt.Errorf("panel password must be 12 to 256 bytes")
	}
	if strings.TrimSpace(password) == "" {
		return fmt.Errorf("panel password must not be blank")
	}
	return nil
}

func hashPanelPassword(password string) (string, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	hash := pbkdf2SHA256([]byte(password), salt, passwordIterations, passwordKeyLength)
	return "pbkdf2-sha256$" + strconv.Itoa(passwordIterations) + "$" +
		base64.RawStdEncoding.EncodeToString(salt) + "$" + base64.RawStdEncoding.EncodeToString(hash), nil
}

func verifyPanelPassword(password, encoded string) bool {
	parts := strings.Split(encoded, "$")
	if len(parts) != 4 || parts[0] != "pbkdf2-sha256" {
		return false
	}
	iterations, err := strconv.Atoi(parts[1])
	if err != nil || iterations < 100000 || iterations > 1000000 {
		return false
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[2])
	if err != nil || len(salt) < 16 {
		return false
	}
	want, err := base64.RawStdEncoding.DecodeString(parts[3])
	if err != nil || len(want) != passwordKeyLength {
		return false
	}
	got := pbkdf2SHA256([]byte(password), salt, iterations, len(want))
	return subtle.ConstantTimeCompare(got, want) == 1
}

func pbkdf2SHA256(password, salt []byte, iterations, keyLen int) []byte {
	blocks := (keyLen + sha256.Size - 1) / sha256.Size
	out := make([]byte, 0, blocks*sha256.Size)
	for block := 1; block <= blocks; block++ {
		mac := hmac.New(sha256.New, password)
		mac.Write(salt)
		mac.Write([]byte{byte(block >> 24), byte(block >> 16), byte(block >> 8), byte(block)})
		u := mac.Sum(nil)
		t := append([]byte(nil), u...)
		for i := 1; i < iterations; i++ {
			mac = hmac.New(sha256.New, password)
			mac.Write(u)
			u = mac.Sum(nil)
			for j := range t {
				t[j] ^= u[j]
			}
		}
		out = append(out, t...)
	}
	return out[:keyLen]
}

func randomPanelSessionID() (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}
