package httpauth

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func req(authz string) *http.Request {
	r := httptest.NewRequest("GET", "/", nil)
	if authz != "" {
		r.Header.Set("Authorization", authz)
	}
	return r
}

func TestBearerToken(t *testing.T) {
	cases := []struct {
		name  string
		authz string
		want  string
		valid bool
	}{
		{"正确 Bearer", "Bearer sk-abc123", "sk-abc123", true},
		{"缺 Authorization 头", "", "", false},
		{"缺 Bearer 前缀", "sk-abc123", "", false},
		{"前缀大小写不符", "bearer sk-abc123", "", false},
		{"多余空格保留为令牌内容", "Bearer  sk-abc123", " sk-abc123", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, ok := BearerToken(req(c.authz))
			if got != c.want || ok != c.valid {
				t.Errorf("BearerToken(%q) = %q, %v; want %q, %v", c.authz, got, ok, c.want, c.valid)
			}
		})
	}
}
