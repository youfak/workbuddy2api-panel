package panel

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"testing"
	"time"
)

func TestValidPhone(t *testing.T) {
	for _, tc := range []struct {
		phone string
		want  bool
	}{
		{"13800138000", true},
		{"23800138000", false},
		{"1380013800", false},
		{"138001380000", false},
		{"1380013800a", false},
	} {
		if got := validPhone(tc.phone); got != tc.want {
			t.Errorf("validPhone(%q)=%v want %v", tc.phone, got, tc.want)
		}
	}
}

func TestPhonePKCE(t *testing.T) {
	verifier, challenge, err := phonePKCE()
	if err != nil {
		t.Fatal(err)
	}
	if verifier == "" || challenge == "" || verifier == challenge {
		t.Fatalf("invalid PKCE values verifier=%q challenge=%q", verifier, challenge)
	}
}

func TestPhoneAccountFromToken(t *testing.T) {
	payload, err := json.Marshal(map[string]string{
		"sub": "user-123", "enterpriseId": "ent-1", "nickname": "测试账号",
		"iss": "https://www.codebuddy.cn/auth/realms/copilot",
	})
	if err != nil {
		t.Fatal(err)
	}
	token := "e30." + base64.RawURLEncoding.EncodeToString(payload) + ".sig"
	acct, err := phoneAccountFromToken(token, "13800138000")
	if err != nil {
		t.Fatal(err)
	}
	if acct.UID != "user-123" || acct.EnterpriseID != "ent-1" || acct.Nickname != "测试账号" || acct.Domain != "www.codebuddy.cn" {
		t.Fatalf("unexpected account: %+v", acct)
	}
}

func TestPhoneAccountFromTokenRequiresUID(t *testing.T) {
	payload, _ := json.Marshal(map[string]string{"nickname": "无 UID"})
	token := "e30." + base64.RawURLEncoding.EncodeToString(payload) + ".sig"
	if _, err := phoneAccountFromToken(token, "13800138000"); err == nil {
		t.Fatal("expected missing UID error")
	}
}

func TestCleanupPhoneLogins(t *testing.T) {
	p := &Panel{phoneLogins: map[string]phoneLoginSession{
		"old": {created: time.Now().Add(-phoneLoginTTL - time.Second)},
		"new": {created: time.Now()},
	}}
	p.cleanupPhoneLoginsLocked(time.Now())
	if _, ok := p.phoneLogins["old"]; ok {
		t.Fatal("expired phone login was not removed")
	}
	if _, ok := p.phoneLogins["new"]; !ok {
		t.Fatal("active phone login was removed")
	}
}

func TestPhoneSMSRateLimit(t *testing.T) {
	p := &Panel{smsRates: map[string]smsRate{}}
	now := time.Now()
	if ok, _ := p.allowPhoneSMS("13800138000", "127.0.0.1", now); !ok {
		t.Fatal("first SMS request must be allowed")
	}
	if ok, retry := p.allowPhoneSMS("13800138000", "127.0.0.1", now.Add(time.Second)); ok || retry <= 0 {
		t.Fatalf("cooldown bypassed: ok=%v retry=%d", ok, retry)
	}
	if ok, _ := p.allowPhoneSMS("13800138000", "127.0.0.1", now.Add(phoneSMSCooldown)); !ok {
		t.Fatal("SMS request after cooldown must be allowed")
	}
	if ok, _ := p.allowPhoneSMS("13800138000", "127.0.0.1", now.Add(2*phoneSMSCooldown)); !ok {
		t.Fatal("third SMS request in the hour must be allowed")
	}
	if ok, retry := p.allowPhoneSMS("13800138000", "127.0.0.1", now.Add(3*phoneSMSCooldown)); ok || retry <= 0 {
		t.Fatalf("hourly phone cap bypassed: ok=%v retry=%d", ok, retry)
	}

	bySource := &Panel{smsRates: map[string]smsRate{}}
	for i := 0; i < phoneSMSPerIP; i++ {
		if ok, _ := bySource.allowPhoneSMS(fmt.Sprintf("phone-%d", i), "198.51.100.10", now); !ok {
			t.Fatalf("source request %d must be allowed", i)
		}
	}
	if ok, retry := bySource.allowPhoneSMS("phone-over-limit", "198.51.100.10", now); ok || retry <= 0 {
		t.Fatalf("hourly source cap bypassed: ok=%v retry=%d", ok, retry)
	}
}
