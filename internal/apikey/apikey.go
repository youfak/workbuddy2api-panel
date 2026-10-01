// Package apikey manages AI API keys without persisting their plaintext form.
package apikey

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"strings"
	"time"
)

// Record is the persisted representation of one AI API key. Hash is never
// returned by the WebUI; Masked is sufficient for operators to identify it.
type Record struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Hash      string    `json:"hash"`
	Masked    string    `json:"masked"`
	CreatedAt time.Time `json:"created_at"`
}

// PublicRecord excludes the password-equivalent hash from WebUI responses.
type PublicRecord struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Masked    string    `json:"masked"`
	CreatedAt time.Time `json:"created_at"`
}

func Create(name string) (Record, string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return Record{}, "", err
	}
	idRaw := make([]byte, 12)
	if _, err := rand.Read(idRaw); err != nil {
		return Record{}, "", err
	}
	plain := "sk-" + base64.RawURLEncoding.EncodeToString(raw)
	sum := sha256.Sum256([]byte(plain))
	return Record{
		ID:        hex.EncodeToString(idRaw),
		Name:      strings.TrimSpace(name),
		Hash:      hex.EncodeToString(sum[:]),
		Masked:    mask(plain),
		CreatedAt: time.Now().UTC(),
	}, plain, nil
}

func Verify(key string, records []Record) bool {
	if !strings.HasPrefix(key, "sk-") {
		return false
	}
	sum := sha256.Sum256([]byte(key))
	got := hex.EncodeToString(sum[:])
	matched := 0
	for _, record := range records {
		matched |= subtle.ConstantTimeCompare([]byte(got), []byte(record.Hash))
	}
	return matched == 1
}

func Public(records []Record) []PublicRecord {
	out := make([]PublicRecord, 0, len(records))
	for _, record := range records {
		out = append(out, PublicRecord{ID: record.ID, Name: record.Name, Masked: record.Masked, CreatedAt: record.CreatedAt})
	}
	return out
}

func mask(key string) string {
	if len(key) <= 7 {
		return "sk-***"
	}
	return key[:3] + "..." + key[len(key)-4:]
}
