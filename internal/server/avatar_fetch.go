package server

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// avatarFetchOpts is a standalone upload-opt for downloaded OAuth avatars,
// slightly more permissive than PublicAvatarOpts but still safe.
var avatarFetchOpts = UploadOpts{
	MaxBytes: 5 * 1024 * 1024,
	AllowedMIME: map[string]string{
		"image/png":  ".png",
		"image/jpeg": ".jpg",
		"image/webp": ".webp",
		"image/gif":  ".gif",
	},
}

// downloadAndSaveAvatar fetches the remote avatar URL and stores it locally
// as uploads/avatars/<userID><ext>. Returns the local "/uploads/..." URL,
// or falls back to the remote URL on any error (never fatal to login).
func downloadAndSaveAvatar(ctx context.Context, userID, remoteURL string) (string, error) {
	remoteURL = strings.TrimSpace(remoteURL)
	if remoteURL == "" {
		return "", fmt.Errorf("empty url")
	}
	u, err := url.Parse(remoteURL)
	if err != nil || !u.IsAbs() {
		return remoteURL, fmt.Errorf("invalid url: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return remoteURL, fmt.Errorf("unsupported scheme")
	}

	cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(cctx, http.MethodGet, remoteURL, nil)
	if err != nil {
		return remoteURL, err
	}
	req.Header.Set("User-Agent", "teamindex-oidc-avatar/1.0")
	req.Header.Set("Accept", "image/*")

	client := &http.Client{Timeout: 12 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return remoteURL, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return remoteURL, fmt.Errorf("status %d", resp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, avatarFetchOpts.MaxBytes+1))
	if err != nil {
		return remoteURL, err
	}
	if int64(len(data)) > avatarFetchOpts.MaxBytes {
		return remoteURL, fmt.Errorf("avatar too large")
	}
	if len(data) == 0 {
		return remoteURL, fmt.Errorf("empty body")
	}
	mime := http.DetectContentType(data)
	ext, ok := avatarFetchOpts.AllowedMIME[mime]
	if !ok {
		return remoteURL, fmt.Errorf("unsupported mime: %s", mime)
	}

	uploadDir := filepath.Join("uploads", "avatars")
	if err := os.MkdirAll(uploadDir, 0o755); err != nil {
		return remoteURL, err
	}
	for _, e := range allKnownExts {
		_ = os.Remove(filepath.Join(uploadDir, userID+e))
	}
	target := filepath.Join(uploadDir, userID+ext)
	if err := os.WriteFile(target, data, 0o644); err != nil {
		return remoteURL, err
	}
	return "/uploads/avatars/" + userID + ext, nil
}

// absolutizeLocalURL turns a "/uploads/..." path into "<issuer>/uploads/...".
// If already absolute, returns as-is.
func absolutizeLocalURL(issuer, local string) string {
	local = strings.TrimSpace(local)
	if local == "" {
		return ""
	}
	if strings.HasPrefix(local, "http://") || strings.HasPrefix(local, "https://") || strings.HasPrefix(local, "data:") {
		return local
	}
	if !strings.HasPrefix(local, "/") {
		return local
	}
	return strings.TrimRight(issuer, "/") + local
}
