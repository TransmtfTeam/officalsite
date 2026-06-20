package server

import (
	"encoding/json"
	"strings"
)

// auditSecretKeyParts are substrings (lower-cased) of any JSON key whose value
// must be masked before an audit-log before/after state is returned by the API.
// Audit writes serialize full store structs / settings maps that can include
// credentials; the rollback path still reads the raw DB value, so masking here
// only affects what the audit-log API exposes.
var auditSecretKeyParts = []string{
	"passhash", "pass_hash", "password", "secret", "totp", "smtp_pass", "resend",
}

// redactAuditState parses a stored audit state JSON blob and masks any
// credential-bearing fields. Non-JSON or empty input is returned unchanged.
func redactAuditState(raw string) string {
	if strings.TrimSpace(raw) == "" {
		return raw
	}
	var v any
	if err := json.Unmarshal([]byte(raw), &v); err != nil {
		return raw
	}
	redactAuditValue(v)
	out, err := json.Marshal(v)
	if err != nil {
		return raw
	}
	return string(out)
}

func redactAuditValue(v any) {
	switch t := v.(type) {
	case map[string]any:
		for k, val := range t {
			if auditKeyIsSecret(k) {
				if val != nil && val != "" {
					t[k] = "***"
				}
				continue
			}
			redactAuditValue(val)
		}
	case []any:
		for _, item := range t {
			redactAuditValue(item)
		}
	}
}

func auditKeyIsSecret(key string) bool {
	lk := strings.ToLower(key)
	for _, p := range auditSecretKeyParts {
		if strings.Contains(lk, p) {
			return true
		}
	}
	return false
}
