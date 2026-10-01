// Package httpauth provides strict Bearer token parsing for AI requests.
package httpauth

import (
	"net/http"
	"strings"
)

// bearerPrefix 认证方案前缀（大小写敏感，与 HTTP 规范及既有实现一致）。
const bearerPrefix = "Bearer "

// BearerToken extracts a token with an exact Bearer scheme prefix. Callers
// validate it against the managed AI key collection.
func BearerToken(r *http.Request) (string, bool) {
	authz := r.Header.Get("Authorization")
	if !strings.HasPrefix(authz, bearerPrefix) {
		return "", false
	}
	return authz[len(bearerPrefix):], true
}
