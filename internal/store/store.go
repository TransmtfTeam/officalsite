package store

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	_ "embed"
	"encoding/hex"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"
	_ "github.com/lib/pq"
	"golang.org/x/crypto/bcrypt"
)

//go:embed schema.sql
var schemaSQL string

// ── Models ─────────────────────────────────────────────────────

type User struct {
	ID                string
	Email             string
	PassHash          string
	DisplayName       string
	AvatarURL         string
	Role              string // user | member | admin
	Active            bool
	TOTPSecret        string
	TOTPPendingSecret string
	TOTPEnabled       bool
	CreatedAt         time.Time
}

func (u *User) IsAdmin()  bool { return u.Role == "admin" }
func (u *User) IsMember() bool { return u.Role == "member" || u.Role == "admin" }
func (u *User) RoleLabel() string {
	switch u.Role {
	case "admin":  return "管理员"
	case "member": return "成员"
	default:       return "用户"
	}
}

type OAuthClient struct {
	ID           string
	ClientID     string
	SecretHash   string
	Name         string
	Description  string
	RedirectURIs []string
	Scopes       []string
	CreatedAt    time.Time
}

type AuthCode struct {
	Code        string
	ClientID    string
	UserID      string
	RedirectURI string
	Scopes      []string
	Challenge   string
	Method      string
	Nonce       string
	ExpiresAt   time.Time
	Used        bool
}

type AccessToken struct {
	ID        string
	UserID    string
	ClientID  string
	Scopes    []string
	ExpiresAt time.Time
}

type RefreshToken struct {
	ID        string
	UserID    string
	ClientID  string
	Scopes    []string
	ExpiresAt time.Time
}

type Project struct {
	ID        string
	Slug      string
	NameZH    string
	NameEN    string
	DescZH    string
	DescEN    string
	Status    string
	URL       string
	Tags      string // raw JSON
	Featured  bool
	SortOrder int
	CreatedAt time.Time
	UpdatedAt time.Time
}

// ── External OIDC Provider ───────────────────────────────────────

type OIDCProvider struct {
	ID           string
	Name         string
	Slug         string
	Icon         string
	ClientID     string
	ClientSecret string
	IssuerURL    string
	Scopes       string
	Enabled      bool
	CreatedAt    time.Time
}

// ── User Identity (external provider link) ───────────────────────

type UserIdentity struct {
	ID        string
	UserID    string
	Provider  string
	Subject   string
	CreatedAt time.Time
}

// ── OIDC RP login state ──────────────────────────────────────────

type OIDCState struct {
	State     string
	Provider  string
	Nonce     string
	Verifier  string
	Redirect  string
	ExpiresAt time.Time
}

type Login2FAChallenge struct {
	ID        string
	UserID    string
	Redirect  string
	ExpiresAt time.Time
}

// ── Store ───────────────────────────────────────────────────────

type Store struct{ db *sql.DB }

func Connect(dsn string) (*sql.DB, error) {
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(20)
	db.SetMaxIdleConns(5)
	return db, db.Ping()
}

func New(db *sql.DB) *Store { return &Store{db: db} }

func (s *Store) Migrate(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, schemaSQL)
	return err
}

// ── Settings ────────────────────────────────────────────────────

func (s *Store) GetSetting(ctx context.Context, key string) string {
	var v string
	s.db.QueryRowContext(ctx, `SELECT value FROM settings WHERE key=$1`, key).Scan(&v)
	return v
}

func (s *Store) SetSetting(ctx context.Context, key, value string) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO settings(key,value) VALUES($1,$2) ON CONFLICT(key) DO UPDATE SET value=EXCLUDED.value`,
		key, value)
	return err
}

// setSettingDefault inserts only when the key does not yet exist.
func (s *Store) setSettingDefault(ctx context.Context, key, value string) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO settings(key,value) VALUES($1,$2) ON CONFLICT(key) DO NOTHING`,
		key, value)
	return err
}

// EnsureDefaults writes built-in default settings on first run.
// Existing values are never overwritten.
func (s *Store) EnsureDefaults(ctx context.Context) error {
	defaults := map[string]string{
		"site_name":       "Team TransMTF",
		"contact_email":   "contact@transmtf.com",
		"tos_content":     defaultTOS,
		"privacy_content": defaultPrivacy,
	}
	for k, v := range defaults {
		if err := s.setSettingDefault(ctx, k, v); err != nil {
			return err
		}
	}
	return nil
}

const defaultTOS = `<h3 style="margin-bottom:.8rem">服务条款</h3>
<p style="color:#888;margin-bottom:1.5rem">最后更新：2025 年</p>

<h4>1. 接受条款</h4>
<p>使用 Team TransMTF 提供的任何服务（包括但不限于网站、身份认证系统及相关 API），即表示您同意遵守本服务条款。若您不同意，请停止使用本服务。</p>

<h4>2. 服务说明</h4>
<p>Team TransMTF 是一个面向跨性别群体及盟友的开放社区平台，提供：</p>
<ul>
  <li>用户账号与身份管理服务（OIDC / OAuth2）</li>
  <li>团队项目信息展示</li>
  <li>社区资源导航</li>
</ul>

<h4>3. 账号责任</h4>
<p>您有责任保管好自己的账号凭据。禁止共享账号或冒充他人。若发现账号被盗用，请立即联系我们。</p>

<h4>4. 行为准则</h4>
<p>使用本服务时，您同意不从事以下行为：</p>
<ul>
  <li>骚扰、歧视或伤害其他用户（尤其是跨性别群体成员）</li>
  <li>传播仇恨言论、虚假信息或违法内容</li>
  <li>尝试破解、滥用或干扰服务正常运行</li>
  <li>通过自动化手段批量注册账号或滥用 API</li>
</ul>

<h4>5. 第三方登录</h4>
<p>若您选择使用第三方账号（如 Twitter/X、Google 等）登录，您同时受到该平台服务条款的约束。我们仅获取必要的身份信息（用户 ID、邮箱、昵称）。</p>

<h4>6. 服务变更与终止</h4>
<p>我们保留随时修改或终止服务的权利，并会提前通过站内公告通知用户。</p>

<h4>7. 免责声明</h4>
<p>本服务按"现状"提供，不对服务的持续可用性、准确性或适用性作任何明示或暗示的保证。</p>

<h4>8. 联系我们</h4>
<p>如有任何疑问，请通过 <a href="mailto:contact@transmtf.com">contact@transmtf.com</a> 联系我们。</p>`

const defaultPrivacy = `<h3 style="margin-bottom:.8rem">隐私政策</h3>
<p style="color:#888;margin-bottom:1.5rem">最后更新：2025 年</p>

<h4>1. 我们收集的信息</h4>
<p>在您注册或使用本服务时，我们可能收集以下信息：</p>
<ul>
  <li><strong>账号信息</strong>：邮箱地址、显示名称、头像 URL</li>
  <li><strong>身份验证信息</strong>：经过 bcrypt 哈希处理的密码（明文密码从不存储）</li>
  <li><strong>第三方身份</strong>：使用外部 OIDC 登录时，我们存储提供商名称与您在该平台的用户 ID（subject）</li>
  <li><strong>会话信息</strong>：登录状态（存储于数据库，7 天有效期）</li>
  <li><strong>OAuth2 授权记录</strong>：您授权给第三方应用的令牌信息</li>
</ul>

<h4>2. 信息使用方式</h4>
<p>收集到的信息仅用于：</p>
<ul>
  <li>验证您的身份并维持登录状态</li>
  <li>向您授权的第三方应用提供身份信息（通过 OIDC / OAuth2 标准协议）</li>
  <li>显示您的个人资料（昵称、头像）</li>
  <li>发送与账号安全相关的必要通知</li>
</ul>

<h4>3. 信息共享</h4>
<p>我们不会出售您的个人信息。以下情况除外：</p>
<ul>
  <li><strong>您主动授权的应用</strong>：当您通过 OIDC 授权第三方应用时，该应用将根据您授权的 Scope 获取相应信息（如邮箱、昵称）</li>
  <li><strong>法律要求</strong>：在法律明确要求的情况下配合相关机构</li>
</ul>

<h4>4. 数据安全</h4>
<ul>
  <li>密码使用 bcrypt 单向哈希，无法还原明文</li>
  <li>访问令牌以 SHA-256 哈希形式存储，明文仅在签发时传输一次</li>
  <li>会话 Cookie 使用 HMAC-SHA256 签名，防止伪造</li>
  <li>数据库存储在 Docker 隔离网络中，不直接对外暴露</li>
</ul>

<h4>5. 数据保留</h4>
<ul>
  <li>会话在 7 天后自动过期</li>
  <li>访问令牌有效期为 1 小时，刷新令牌有效期为 30 天</li>
  <li>删除账号后，相关数据将被级联删除</li>
</ul>

<h4>6. 您的权利</h4>
<p>您有权：查看您的个人信息、修改显示名称与头像、删除账号（请联系管理员）、撤销对第三方应用的授权（在个人资料页面操作）。</p>

<h4>7. 联系我们</h4>
<p>如有任何隐私相关问题，请通过 <a href="mailto:contact@transmtf.com">contact@transmtf.com</a> 联系我们。</p>`

func (s *Store) GetAllSettings(ctx context.Context) map[string]string {
	rows, err := s.db.QueryContext(ctx, `SELECT key,value FROM settings`)
	if err != nil {
		return map[string]string{}
	}
	defer rows.Close()
	m := map[string]string{}
	for rows.Next() {
		var k, v string
		rows.Scan(&k, &v)
		m[k] = v
	}
	return m
}

// ── Users ────────────────────────────────────────────────────────

const userCols = `id,email,password_hash,display_name,avatar_url,role,active,totp_secret,totp_pending_secret,totp_enabled,created_at`

func scanUser(row interface{ Scan(...any) error }) (*User, error) {
	u := &User{}
	err := row.Scan(
		&u.ID, &u.Email, &u.PassHash, &u.DisplayName, &u.AvatarURL, &u.Role, &u.Active,
		&u.TOTPSecret, &u.TOTPPendingSecret, &u.TOTPEnabled, &u.CreatedAt,
	)
	return u, err
}

func (s *Store) EnsureAdmin(ctx context.Context, email, password string) error {
	_, err := s.GetUserByEmail(ctx, email)
	if err == nil {
		return nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	_, err = s.CreateUser(ctx, email, password, "Administrator", "admin")
	return err
}

func (s *Store) CreateUser(ctx context.Context, email, password, displayName, role string) (*User, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return nil, err
	}
	id := uuid.New().String()
	_, err = s.db.ExecContext(ctx,
		`INSERT INTO users(id,email,password_hash,display_name,role) VALUES($1,$2,$3,$4,$5)`,
		id, strings.ToLower(strings.TrimSpace(email)), string(hash), displayName, role)
	if err != nil {
		return nil, err
	}
	return s.GetUserByID(ctx, id)
}

func (s *Store) GetUserByID(ctx context.Context, id string) (*User, error) {
	return scanUser(s.db.QueryRowContext(ctx, `SELECT `+userCols+` FROM users WHERE id=$1`, id))
}

func (s *Store) GetUserByEmail(ctx context.Context, email string) (*User, error) {
	return scanUser(s.db.QueryRowContext(ctx, `SELECT `+userCols+` FROM users WHERE email=$1`, strings.ToLower(email)))
}

func (s *Store) ListUsers(ctx context.Context) ([]*User, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+userCols+` FROM users ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*User
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

func (s *Store) UpdateUser(ctx context.Context, id, displayName, role string, active bool) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE users SET display_name=$1,role=$2,active=$3,updated_at=now() WHERE id=$4`,
		displayName, role, active, id)
	return err
}

func (s *Store) UpdatePassword(ctx context.Context, id, newPass string) error {
	h, err := bcrypt.GenerateFromPassword([]byte(newPass), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, `UPDATE users SET password_hash=$1,updated_at=now() WHERE id=$2`, string(h), id)
	return err
}

func (s *Store) SavePendingTOTPSecret(ctx context.Context, id, secret string) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE users SET totp_pending_secret=$1,updated_at=now() WHERE id=$2`,
		secret, id,
	)
	return err
}

func (s *Store) EnableTOTP(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, `
		UPDATE users
		SET totp_secret=totp_pending_secret, totp_pending_secret='', totp_enabled=true, updated_at=now()
		WHERE id=$1 AND totp_pending_secret <> ''
	`, id)
	return err
}

func (s *Store) DisableTOTP(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, `
		UPDATE users
		SET totp_secret='', totp_pending_secret='', totp_enabled=false, updated_at=now()
		WHERE id=$1
	`, id)
	return err
}

func (s *Store) DeleteUser(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM users WHERE id=$1`, id)
	return err
}

func (s *Store) CountUsers(ctx context.Context) int {
	var n int
	s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM users`).Scan(&n)
	return n
}

func (s *Store) VerifyPassword(u *User, password string) bool {
	return bcrypt.CompareHashAndPassword([]byte(u.PassHash), []byte(password)) == nil
}

// ── Sessions ─────────────────────────────────────────────────────

func (s *Store) CreateSession(ctx context.Context, userID string) (string, error) {
	id := uuid.New().String()
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO sessions(id,user_id,expires_at) VALUES($1,$2,$3)`,
		id, userID, time.Now().Add(7*24*time.Hour))
	return id, err
}

func (s *Store) GetSessionUser(ctx context.Context, sessionID string) (*User, error) {
	var userID string
	var exp time.Time
	err := s.db.QueryRowContext(ctx, `SELECT user_id,expires_at FROM sessions WHERE id=$1`, sessionID).Scan(&userID, &exp)
	if err != nil {
		return nil, err
	}
	if time.Now().After(exp) {
		s.DeleteSession(ctx, sessionID)
		return nil, sql.ErrNoRows
	}
	return s.GetUserByID(ctx, userID)
}

func (s *Store) DeleteSession(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE id=$1`, id)
	return err
}

// ── OAuth Clients ─────────────────────────────────────────────────

func (s *Store) CreateClient(ctx context.Context, name, description string, redirectURIs, scopes []string) (clientID, secret string, err error) {
	id := uuid.New().String()
	clientID = "tmtf_" + RandomHex(12)
	secret = RandomHex(32)
	h, err := bcrypt.GenerateFromPassword([]byte(secret), bcrypt.DefaultCost)
	if err != nil {
		return "", "", err
	}
	_, err = s.db.ExecContext(ctx,
		`INSERT INTO oauth_clients(id,client_id,client_secret_hash,name,description,redirect_uris,scopes) VALUES($1,$2,$3,$4,$5,$6,$7)`,
		id, clientID, string(h), name, description,
		strings.Join(redirectURIs, "\n"), strings.Join(scopes, " "))
	return clientID, secret, err
}

func scanClient(row interface{ Scan(...any) error }) (*OAuthClient, error) {
	c := &OAuthClient{}
	var uris, scopes string
	err := row.Scan(&c.ID, &c.ClientID, &c.SecretHash, &c.Name, &c.Description, &uris, &scopes, &c.CreatedAt)
	if err != nil {
		return nil, err
	}
	c.RedirectURIs = splitLines(uris)
	c.Scopes = strings.Fields(scopes)
	return c, nil
}

const clientCols = `id,client_id,client_secret_hash,name,description,redirect_uris,scopes,created_at`

func (s *Store) GetClientByClientID(ctx context.Context, clientID string) (*OAuthClient, error) {
	return scanClient(s.db.QueryRowContext(ctx, `SELECT `+clientCols+` FROM oauth_clients WHERE client_id=$1`, clientID))
}

func (s *Store) GetClientByID(ctx context.Context, id string) (*OAuthClient, error) {
	return scanClient(s.db.QueryRowContext(ctx, `SELECT `+clientCols+` FROM oauth_clients WHERE id=$1`, id))
}

func (s *Store) ListClients(ctx context.Context) ([]*OAuthClient, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+clientCols+` FROM oauth_clients ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*OAuthClient
	for rows.Next() {
		c, err := scanClient(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

func (s *Store) CountClients(ctx context.Context) int {
	var n int
	s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM oauth_clients`).Scan(&n)
	return n
}

func (s *Store) DeleteClient(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM oauth_clients WHERE id=$1`, id)
	return err
}

func (s *Store) VerifyClientSecret(c *OAuthClient, secret string) bool {
	return bcrypt.CompareHashAndPassword([]byte(c.SecretHash), []byte(secret)) == nil
}

// ── Auth Codes ────────────────────────────────────────────────────

func (s *Store) CreateAuthCode(ctx context.Context, code, clientID, userID, redirectURI string, scopes []string, challenge, method, nonce string) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO auth_codes(code,client_id,user_id,redirect_uri,scopes,code_challenge,code_challenge_method,nonce,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
		code, clientID, userID, redirectURI, strings.Join(scopes, " "),
		challenge, method, nonce, time.Now().Add(10*time.Minute))
	return err
}

func (s *Store) ConsumeAuthCode(ctx context.Context, code string) (*AuthCode, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	ac := &AuthCode{}
	var scopes string
	err = tx.QueryRowContext(ctx,
		`SELECT code,client_id,user_id,redirect_uri,scopes,code_challenge,code_challenge_method,nonce,expires_at,used FROM auth_codes WHERE code=$1 FOR UPDATE`,
		code).Scan(&ac.Code, &ac.ClientID, &ac.UserID, &ac.RedirectURI, &scopes,
		&ac.Challenge, &ac.Method, &ac.Nonce, &ac.ExpiresAt, &ac.Used)
	if err != nil {
		return nil, err
	}
	if ac.Used || time.Now().After(ac.ExpiresAt) {
		return nil, errors.New("code invalid or expired")
	}
	if _, err = tx.ExecContext(ctx, `UPDATE auth_codes SET used=true WHERE code=$1`, code); err != nil {
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	ac.Scopes = strings.Fields(scopes)
	return ac, nil
}

// ── Tokens ───────────────────────────────────────────────────────

func (s *Store) CreateAccessToken(ctx context.Context, userID, clientID string, scopes []string) (string, error) {
	raw := RandomHex(32)
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO access_tokens(id,token_hash,user_id,client_id,scopes,expires_at) VALUES($1,$2,$3,$4,$5,$6)`,
		uuid.New().String(), sha256hex(raw), userID, clientID,
		strings.Join(scopes, " "), time.Now().Add(time.Hour))
	return raw, err
}

func (s *Store) GetAccessToken(ctx context.Context, raw string) (*AccessToken, error) {
	t := &AccessToken{}
	var scopes string
	err := s.db.QueryRowContext(ctx,
		`SELECT id,user_id,client_id,scopes,expires_at FROM access_tokens WHERE token_hash=$1`,
		sha256hex(raw)).Scan(&t.ID, &t.UserID, &t.ClientID, &scopes, &t.ExpiresAt)
	if err != nil {
		return nil, err
	}
	if time.Now().After(t.ExpiresAt) {
		return nil, sql.ErrNoRows
	}
	t.Scopes = strings.Fields(scopes)
	return t, nil
}

func (s *Store) RevokeAccessToken(ctx context.Context, raw string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM access_tokens WHERE token_hash=$1`, sha256hex(raw))
	return err
}

func (s *Store) CreateRefreshToken(ctx context.Context, userID, clientID string, scopes []string) (string, error) {
	raw := RandomHex(32)
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO refresh_tokens(id,token_hash,user_id,client_id,scopes,expires_at) VALUES($1,$2,$3,$4,$5,$6)`,
		uuid.New().String(), sha256hex(raw), userID, clientID,
		strings.Join(scopes, " "), time.Now().Add(30*24*time.Hour))
	return raw, err
}

func (s *Store) GetRefreshToken(ctx context.Context, raw string) (*RefreshToken, error) {
	t := &RefreshToken{}
	var scopes string
	err := s.db.QueryRowContext(ctx,
		`SELECT id,user_id,client_id,scopes,expires_at FROM refresh_tokens WHERE token_hash=$1`,
		sha256hex(raw)).Scan(&t.ID, &t.UserID, &t.ClientID, &scopes, &t.ExpiresAt)
	if err != nil {
		return nil, err
	}
	if time.Now().After(t.ExpiresAt) {
		return nil, sql.ErrNoRows
	}
	t.Scopes = strings.Fields(scopes)
	return t, nil
}

func (s *Store) RevokeRefreshToken(ctx context.Context, raw string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM refresh_tokens WHERE token_hash=$1`, sha256hex(raw))
	return err
}

// ── Projects ─────────────────────────────────────────────────────

const projCols = `id,slug,name_zh,name_en,desc_zh,desc_en,status,url,tags,featured,sort_order,created_at,updated_at`

func scanProject(row interface{ Scan(...any) error }) (*Project, error) {
	p := &Project{}
	err := row.Scan(&p.ID, &p.Slug, &p.NameZH, &p.NameEN, &p.DescZH, &p.DescEN,
		&p.Status, &p.URL, &p.Tags, &p.Featured, &p.SortOrder, &p.CreatedAt, &p.UpdatedAt)
	return p, err
}

func (s *Store) ListProjects(ctx context.Context) ([]*Project, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+projCols+` FROM projects ORDER BY featured DESC, sort_order ASC, created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Project
	for rows.Next() {
		p, err := scanProject(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

func (s *Store) GetProject(ctx context.Context, id string) (*Project, error) {
	return scanProject(s.db.QueryRowContext(ctx, `SELECT `+projCols+` FROM projects WHERE id=$1`, id))
}

func (s *Store) CreateProject(ctx context.Context, p *Project) error {
	p.ID = uuid.New().String()
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO projects(id,slug,name_zh,name_en,desc_zh,desc_en,status,url,tags,featured,sort_order) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`,
		p.ID, p.Slug, p.NameZH, p.NameEN, p.DescZH, p.DescEN, p.Status, p.URL, p.Tags, p.Featured, p.SortOrder)
	return err
}

func (s *Store) UpdateProject(ctx context.Context, p *Project) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE projects SET slug=$1,name_zh=$2,name_en=$3,desc_zh=$4,desc_en=$5,status=$6,url=$7,tags=$8,featured=$9,sort_order=$10,updated_at=now() WHERE id=$11`,
		p.Slug, p.NameZH, p.NameEN, p.DescZH, p.DescEN, p.Status, p.URL, p.Tags, p.Featured, p.SortOrder, p.ID)
	return err
}

func (s *Store) DeleteProject(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM projects WHERE id=$1`, id)
	return err
}

func (s *Store) CountProjects(ctx context.Context) int {
	var n int
	s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM projects`).Scan(&n)
	return n
}

// ── UpdateUserAvatar ─────────────────────────────────────────────

func (s *Store) UpdateUserAvatar(ctx context.Context, id, avatarURL string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE users SET avatar_url=$1, updated_at=now() WHERE id=$2`, avatarURL, id)
	return err
}

// ── OIDC Provider CRUD ───────────────────────────────────────────

func (s *Store) CreateOIDCProvider(ctx context.Context, name, slug, icon, clientID, clientSecret, issuerURL, scopes string) error {
	id := uuid.New().String()
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO oidc_providers(id,name,slug,icon,client_id,client_secret,issuer_url,scopes) VALUES($1,$2,$3,$4,$5,$6,$7,$8)`,
		id, name, slug, icon, clientID, clientSecret, issuerURL, scopes)
	return err
}

func (s *Store) ListOIDCProviders(ctx context.Context) ([]*OIDCProvider, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id,name,slug,icon,client_id,client_secret,issuer_url,scopes,enabled,created_at FROM oidc_providers ORDER BY created_at`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*OIDCProvider
	for rows.Next() {
		p := &OIDCProvider{}
		if err := rows.Scan(&p.ID, &p.Name, &p.Slug, &p.Icon, &p.ClientID, &p.ClientSecret, &p.IssuerURL, &p.Scopes, &p.Enabled, &p.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

func (s *Store) ListEnabledOIDCProviders(ctx context.Context) ([]*OIDCProvider, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id,name,slug,icon,client_id,client_secret,issuer_url,scopes,enabled,created_at FROM oidc_providers WHERE enabled=true ORDER BY created_at`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*OIDCProvider
	for rows.Next() {
		p := &OIDCProvider{}
		if err := rows.Scan(&p.ID, &p.Name, &p.Slug, &p.Icon, &p.ClientID, &p.ClientSecret, &p.IssuerURL, &p.Scopes, &p.Enabled, &p.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

func (s *Store) GetOIDCProviderBySlug(ctx context.Context, slug string) (*OIDCProvider, error) {
	p := &OIDCProvider{}
	err := s.db.QueryRowContext(ctx,
		`SELECT id,name,slug,icon,client_id,client_secret,issuer_url,scopes,enabled,created_at FROM oidc_providers WHERE slug=$1`,
		slug).Scan(&p.ID, &p.Name, &p.Slug, &p.Icon, &p.ClientID, &p.ClientSecret, &p.IssuerURL, &p.Scopes, &p.Enabled, &p.CreatedAt)
	return p, err
}

func (s *Store) GetOIDCProviderByID(ctx context.Context, id string) (*OIDCProvider, error) {
	p := &OIDCProvider{}
	err := s.db.QueryRowContext(ctx,
		`SELECT id,name,slug,icon,client_id,client_secret,issuer_url,scopes,enabled,created_at FROM oidc_providers WHERE id=$1`,
		id).Scan(&p.ID, &p.Name, &p.Slug, &p.Icon, &p.ClientID, &p.ClientSecret, &p.IssuerURL, &p.Scopes, &p.Enabled, &p.CreatedAt)
	return p, err
}

func (s *Store) UpdateOIDCProvider(ctx context.Context, id, name, icon, clientID, clientSecret, issuerURL, scopes string, enabled bool) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE oidc_providers SET name=$1,icon=$2,client_id=$3,client_secret=$4,issuer_url=$5,scopes=$6,enabled=$7 WHERE id=$8`,
		name, icon, clientID, clientSecret, issuerURL, scopes, enabled, id)
	return err
}

func (s *Store) DeleteOIDCProvider(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM oidc_providers WHERE id=$1`, id)
	return err
}

func (s *Store) CountOIDCProviders(ctx context.Context) int {
	var n int
	s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM oidc_providers WHERE enabled=true`).Scan(&n)
	return n
}

// ── User Identity ────────────────────────────────────────────────

func (s *Store) LinkIdentity(ctx context.Context, userID, provider, subject string) error {
	id := uuid.New().String()
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO user_identities(id,user_id,provider,subject) VALUES($1,$2,$3,$4) ON CONFLICT(provider,subject) DO NOTHING`,
		id, userID, provider, subject)
	return err
}

func (s *Store) GetUserByIdentity(ctx context.Context, provider, subject string) (*User, error) {
	var userID string
	err := s.db.QueryRowContext(ctx,
		`SELECT user_id FROM user_identities WHERE provider=$1 AND subject=$2`,
		provider, subject).Scan(&userID)
	if err != nil {
		return nil, err
	}
	return s.GetUserByID(ctx, userID)
}

// ── OIDC State ───────────────────────────────────────────────────

func (s *Store) CreateOIDCState(ctx context.Context, state, provider, nonce, verifier, redirect string) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO oidc_states(state,provider,nonce,verifier,redirect,expires_at) VALUES($1,$2,$3,$4,$5,$6)`,
		state, provider, nonce, verifier, redirect, time.Now().Add(10*time.Minute))
	return err
}

func (s *Store) ConsumeOIDCState(ctx context.Context, state string) (*OIDCState, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	st := &OIDCState{}
	err = tx.QueryRowContext(ctx,
		`SELECT state,provider,nonce,verifier,redirect,expires_at FROM oidc_states WHERE state=$1 AND expires_at > now() FOR UPDATE`,
		state).Scan(&st.State, &st.Provider, &st.Nonce, &st.Verifier, &st.Redirect, &st.ExpiresAt)
	if err != nil {
		return nil, err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM oidc_states WHERE state=$1`, state); err != nil {
		return nil, err
	}
	return st, tx.Commit()
}

func (s *Store) CreateLogin2FAChallenge(ctx context.Context, userID, redirect string) (string, error) {
	id := uuid.New().String()
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO login_2fa_challenges(id,user_id,redirect,expires_at) VALUES($1,$2,$3,$4)`,
		id, userID, redirect, time.Now().Add(10*time.Minute),
	)
	return id, err
}

func (s *Store) GetLogin2FAChallenge(ctx context.Context, id string) (*Login2FAChallenge, error) {
	ch := &Login2FAChallenge{}
	err := s.db.QueryRowContext(ctx,
		`SELECT id,user_id,redirect,expires_at FROM login_2fa_challenges WHERE id=$1`,
		id,
	).Scan(&ch.ID, &ch.UserID, &ch.Redirect, &ch.ExpiresAt)
	if err != nil {
		return nil, err
	}
	if time.Now().After(ch.ExpiresAt) {
		_, _ = s.db.ExecContext(ctx, `DELETE FROM login_2fa_challenges WHERE id=$1`, id)
		return nil, sql.ErrNoRows
	}
	return ch, nil
}

func (s *Store) ConsumeLogin2FAChallenge(ctx context.Context, id string) (*Login2FAChallenge, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	ch := &Login2FAChallenge{}
	err = tx.QueryRowContext(ctx,
		`SELECT id,user_id,redirect,expires_at FROM login_2fa_challenges WHERE id=$1 FOR UPDATE`,
		id,
	).Scan(&ch.ID, &ch.UserID, &ch.Redirect, &ch.ExpiresAt)
	if err != nil {
		return nil, err
	}
	if time.Now().After(ch.ExpiresAt) {
		_, _ = tx.ExecContext(ctx, `DELETE FROM login_2fa_challenges WHERE id=$1`, id)
		return nil, sql.ErrNoRows
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM login_2fa_challenges WHERE id=$1`, id); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return ch, nil
}

func (s *Store) DeleteLogin2FAChallenge(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM login_2fa_challenges WHERE id=$1`, id)
	return err
}

// ── Helpers ──────────────────────────────────────────────────────

func RandomHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}

func sha256hex(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

func splitLines(s string) []string {
	var out []string
	for _, l := range strings.Split(s, "\n") {
		if t := strings.TrimSpace(l); t != "" {
			out = append(out, t)
		}
	}
	return out
}
