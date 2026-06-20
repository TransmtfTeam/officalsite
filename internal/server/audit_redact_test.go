package server

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestRedactAuditState(t *testing.T) {
	in := `{"ID":"u1","Email":"a@b.com","PassHash":"$2a$secret","TOTPSecret":"ABCDEF","Role":"admin","Nested":{"SecretHash":"hush","ClientSecret":"cs"},"Items":[{"smtp_pass":"p","keep":"ok"}]}`
	out := redactAuditState(in)

	for _, leaked := range []string{"$2a$secret", "ABCDEF", "hush", "cs", `"p"`} {
		if strings.Contains(out, leaked) {
			t.Fatalf("redacted output still contains secret %q: %s", leaked, out)
		}
	}
	// Non-secret fields must survive.
	var m map[string]any
	if err := json.Unmarshal([]byte(out), &m); err != nil {
		t.Fatalf("redacted output is not valid JSON: %v", err)
	}
	if m["Email"] != "a@b.com" || m["Role"] != "admin" {
		t.Fatalf("non-secret fields were altered: %s", out)
	}
	if !strings.Contains(out, "***") {
		t.Fatalf("expected masked values in output: %s", out)
	}
}

func TestRedactAuditStatePassThrough(t *testing.T) {
	// Empty and non-JSON inputs are returned unchanged.
	if got := redactAuditState(""); got != "" {
		t.Fatalf("empty input changed: %q", got)
	}
	if got := redactAuditState("not json"); got != "not json" {
		t.Fatalf("non-json input changed: %q", got)
	}
}
