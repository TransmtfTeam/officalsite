package server

import (
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
)

// UploadOpts controls a file upload through saveUploadedImage.
type UploadOpts struct {
	MaxBytes    int64
	AllowedMIME map[string]string // mime -> file extension (with leading dot)
}

var (
	// MemberAdminImageOpts: 5MB, allow common raster + svg + gif. For
	// member/admin-only uploads (project images, site icon, friend link icon).
	MemberAdminImageOpts = UploadOpts{
		MaxBytes: 5 * 1024 * 1024,
		AllowedMIME: map[string]string{
			"image/png":     ".png",
			"image/jpeg":    ".jpg",
			"image/webp":    ".webp",
			"image/gif":     ".gif",
			"image/svg+xml": ".svg",
			"image/x-icon":  ".ico",
			"image/vnd.microsoft.icon": ".ico",
		},
	}
	// PublicAvatarOpts: 1MB, common formats for any user (avatars).
	PublicAvatarOpts = UploadOpts{
		MaxBytes: 1 * 1024 * 1024,
		AllowedMIME: map[string]string{
			"image/png":  ".png",
			"image/jpeg": ".jpg",
			"image/webp": ".webp",
			"image/gif":  ".gif",
		},
	}
)

// MIMEAllowedExts returns the set of allowed extensions for an opts.
func (o UploadOpts) extOf(mime string) (string, bool) {
	ext, ok := o.AllowedMIME[mime]
	return ext, ok
}

// allKnownExts lists all extensions referenced by any preset, used to clean
// up older files for the same baseName.
var allKnownExts = []string{".png", ".jpg", ".jpeg", ".webp", ".gif", ".svg", ".ico"}

// readUploadFile reads at most opts.MaxBytes+1 bytes from f and returns
// either the full payload or an error if too large / empty.
func readUploadFile(f multipart.File, opts UploadOpts) ([]byte, error) {
	limited := io.LimitReader(f, opts.MaxBytes+1)
	data, err := io.ReadAll(limited)
	if err != nil {
		return nil, fmt.Errorf("读取文件失败")
	}
	if int64(len(data)) > opts.MaxBytes {
		return nil, fmt.Errorf("文件过大（最大 %dKB）", opts.MaxBytes/1024)
	}
	if len(data) == 0 {
		return nil, fmt.Errorf("文件为空")
	}
	return data, nil
}

// detectAllowedMIME runs http.DetectContentType plus a small set of
// SVG-detection heuristics (DetectContentType returns text/* for SVG).
func detectAllowedMIME(data []byte, opts UploadOpts) (string, error) {
	mime := http.DetectContentType(data)
	// http.DetectContentType returns text/xml or text/plain for SVG. Try to
	// recognise SVG when the caller allows it.
	if _, svgOK := opts.AllowedMIME["image/svg+xml"]; svgOK {
		head := data
		if len(head) > 256 {
			head = head[:256]
		}
		s := string(head)
		// Tolerate BOM / leading whitespace.
		// Look for "<svg" or "<?xml" + "svg" later. Either is good enough.
		if containsCI(s, "<svg") || (containsCI(s, "<?xml") && containsCI(string(data[:min(len(data), 1024)]), "<svg")) {
			mime = "image/svg+xml"
		}
	}
	if _, ok := opts.AllowedMIME[mime]; !ok {
		return "", fmt.Errorf("不支持的文件格式：%s", mime)
	}
	return mime, nil
}

func containsCI(s, sub string) bool {
	if len(sub) == 0 {
		return true
	}
	if len(s) < len(sub) {
		return false
	}
	// Simple ASCII case-insensitive contains.
	ls, lsub := len(s), len(sub)
	for i := 0; i+lsub <= ls; i++ {
		match := true
		for j := 0; j < lsub; j++ {
			a, b := s[i+j], sub[j]
			if a >= 'A' && a <= 'Z' {
				a += 'a' - 'A'
			}
			if b >= 'A' && b <= 'Z' {
				b += 'a' - 'A'
			}
			if a != b {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}

// saveUploadedImage validates, persists and returns a public-facing
// "/uploads/<dir>/<baseName><ext>" URL. It removes any existing file with
// the same baseName (regardless of extension) before writing the new one.
//
// dir must not contain path separators. baseName likewise.
func saveUploadedImage(file multipart.File, dir, baseName string, opts UploadOpts) (string, error) {
	if dir == "" || baseName == "" {
		return "", errors.New("invalid upload target")
	}
	data, err := readUploadFile(file, opts)
	if err != nil {
		return "", err
	}
	mime, err := detectAllowedMIME(data, opts)
	if err != nil {
		return "", err
	}
	ext, _ := opts.extOf(mime)

	uploadDir := filepath.Join("uploads", dir)
	if err := os.MkdirAll(uploadDir, 0o755); err != nil {
		return "", fmt.Errorf("创建目录失败：%v", err)
	}
	// Remove all known-extension files for this baseName.
	for _, e := range allKnownExts {
		_ = os.Remove(filepath.Join(uploadDir, baseName+e))
	}
	target := filepath.Join(uploadDir, baseName+ext)
	if err := os.WriteFile(target, data, 0o644); err != nil {
		return "", fmt.Errorf("保存文件失败：%v", err)
	}
	return "/uploads/" + dir + "/" + baseName + ext, nil
}

// removeUploadByBaseName removes any file under uploads/<dir>/<baseName>.* on
// best-effort basis (used when clearing avatars / icons).
func removeUploadByBaseName(dir, baseName string) {
	if dir == "" || baseName == "" {
		return
	}
	for _, e := range allKnownExts {
		_ = os.Remove(filepath.Join("uploads", dir, baseName+e))
	}
}
