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

var (
	ErrPasswordResetTooSoon      = errors.New("发起找回密码过于频繁")
	ErrPasswordResetTokenExpired = errors.New("找回密码链接已过期")
)

type User struct {
	ID                    string
	Email                 string
	PassHash              string
	DisplayName           string
	AvatarURL             string
	Role                  string // user | member | admin
	Active                bool
	TOTPSecret            string
	TOTPPendingSecret     string
	TOTPEnabled           bool
	CreatedAt             time.Time
	EmailVerified         bool
	RequirePasswordChange bool
}

func HasPassword(u *User) bool { return u != nil && strings.TrimSpace(u.PassHash) != "" }

func (u *User) IsAdmin() bool  { return u.Role == "admin" }
func (u *User) IsMember() bool { return u.Role == "member" || u.Role == "admin" }
func (u *User) RoleLabel() string {
	switch u.Role {
	case "admin":
		return "Administrator"
	case "member":
		return "Member"
	default:
		return "User"
	}
}

type OAuthClient struct {
	ID            string
	ClientID      string
	SecretHash    string
	Name          string
	Description   string
	RedirectURIs  []string
	Scopes        []string
	BaseAccess    string
	AllowedGroups []string
	CreatedAt     time.Time
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

type OIDCProvider struct {
	ID           string
	Name         string
	Slug         string
	ProviderType string
	Icon         string
	ClientID     string
	ClientSecret string
	IssuerURL    string
	AuthorizationURL string
	TokenURL         string
	UserinfoURL      string
	Scopes       string
	Enabled      bool
	AutoRegister bool
	CreatedAt    time.Time
}

type UserIdentity struct {
	ID        string
	UserID    string
	Provider  string
	Subject   string
	CreatedAt time.Time
}

type OIDCState struct {
	State     string
	Provider  string
	UserID    string
	Nonce     string
	Verifier  string
	Redirect  string
	ExpiresAt time.Time
}

type OIDCLinkChallenge struct {
	ID        string
	Provider  string
	Subject   string
	UserID    string
	Redirect  string
	ExpiresAt time.Time
}

type OIDCLoginChallenge struct {
	ID            string
	Provider      string
	Subject       string
	ProfileName   string
	ProfileAvatar string
	ProfileEmail  string
	Redirect      string
	ExpiresAt     time.Time
}

type Login2FAChallenge struct {
	ID        string
	UserID    string
	Redirect  string
	ExpiresAt time.Time
}

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
		"site_name":       "团队站点",
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

const defaultTOS = `<h3 style="margin-bottom:.8rem">Terms of Service</h3>
<p style="color:#888;margin-bottom:1.5rem">Last updated: 2025</p>

<h4>1. Acceptance</h4>
<p>By using Team TransMTF services, you agree to these terms.</p>

<h4>2. Account and Security</h4>
<p>Keep your credentials secure. Do not share accounts or misuse the service.</p>

<h4>3. Conduct</h4>
<p>No harassment, discrimination, illegal content, or attempts to disrupt the service.</p>

<h4>4. Service Changes</h4>
<p>We may update or discontinue parts of the service when necessary.</p>

<h4>5. Contact</h4>
<p>For questions, contact <a href="mailto:contact@transmtf.com">contact@transmtf.com</a>.</p>`

const defaultPrivacy = `<h3 style="margin-bottom:.8rem">Privacy Policy</h3>
<p style="color:#888;margin-bottom:1.5rem">Last updated: 2025</p>

<h4>1. Data We Collect</h4>
<p>We may collect account data, session data, and OAuth2/OIDC authorization data.</p>

<h4>2. Why We Use It</h4>
<p>To authenticate users, secure accounts, deliver platform features, and send essential notices.</p>

<h4>3. Sharing</h4>
<p>We do not sell personal data. We share only with your authorization or legal requirement.</p>

<h4>4. Security</h4>
<p>Passwords and tokens use secure hashing/signing mechanisms.</p>

<h4>5. Contact</h4>
<p>For privacy questions, contact <a href="mailto:contact@transmtf.com">contact@transmtf.com</a>.</p>`

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

const userCols = `id,email,password_hash,display_name,avatar_url,role,active,totp_secret,totp_pending_secret,totp_enabled,created_at,email_verified,require_password_change`

func scanUser(row interface{ Scan(...any) error }) (*User, error) {
	u := &User{}
	err := row.Scan(
		&u.ID, &u.Email, &u.PassHash, &u.DisplayName, &u.AvatarURL, &u.Role, &u.Active,
		&u.TOTPSecret, &u.TOTPPendingSecret, &u.TOTPEnabled, &u.CreatedAt, &u.EmailVerified,
		&u.RequirePasswordChange,
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
	return s.CreateUserWithEmailVerified(ctx, email, password, displayName, role, true)
}

func (s *Store) CreateUserWithEmailVerified(ctx context.Context, email, password, displayName, role string, emailVerified bool) (*User, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return nil, err
	}
	id := uuid.New().String()
	_, err = s.db.ExecContext(ctx,
		`INSERT INTO users(id,email,password_hash,display_name,role,email_verified) VALUES($1,$2,$3,$4,$5,$6)`,
		id, strings.ToLower(strings.TrimSpace(email)), string(hash), displayName, role, emailVerified)
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

func (s *Store) SetRequirePasswordChange(ctx context.Context, userID string, required bool) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE users SET require_password_change=$1,updated_at=now() WHERE id=$2`,
		required, userID)
	return err
}

func (s *Store) SetEmailVerified(ctx context.Context, userID string, verified bool) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE users SET email_verified=$1,updated_at=now() WHERE id=$2`,
		verified, userID)
	return err
}

func (s *Store) ClearPassword(ctx context.Context, userID string) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE users SET password_hash='',updated_at=now() WHERE id=$1`,
		userID)
	return err
}

func (s *Store) UpdatePasswordAndClearFlag(ctx context.Context, userID, newPass string) error {
	h, err := bcrypt.GenerateFromPassword([]byte(newPass), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx,
		`UPDATE users SET password_hash=$1,require_password_change=false,updated_at=now() WHERE id=$2`,
		string(h), userID)
	return err
}

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

func (s *Store) CreateClient(ctx context.Context, name, description string, redirectURIs, scopes []string) (clientID, secret string, err error) {
	id := uuid.New().String()
	clientID = "tmtf_" + RandomHex(12)
	secret = RandomHex(32)
	h, err := bcrypt.GenerateFromPassword([]byte(secret), bcrypt.DefaultCost)
	if err != nil {
		return "", "", err
	}
	_, err = s.db.ExecContext(ctx,
		`INSERT INTO oauth_clients(id,client_id,client_secret_hash,name,description,redirect_uris,scopes,base_access) VALUES($1,$2,$3,$4,$5,$6,$7,$8)`,
		id, clientID, string(h), name, description,
		strings.Join(redirectURIs, "\n"), strings.Join(scopes, " "), "user")
	return clientID, secret, err
}

func scanClient(row interface{ Scan(...any) error }) (*OAuthClient, error) {
	c := &OAuthClient{}
	var uris, scopes, baseAccess, allowedGroups string
	err := row.Scan(&c.ID, &c.ClientID, &c.SecretHash, &c.Name, &c.Description, &uris, &scopes, &baseAccess, &allowedGroups, &c.CreatedAt)
	if err != nil {
		return nil, err
	}
	c.RedirectURIs = splitLines(uris)
	c.Scopes = strings.Fields(scopes)
	c.BaseAccess = strings.TrimSpace(strings.ToLower(baseAccess))
	if c.BaseAccess == "" {
		c.BaseAccess = "legacy"
	}
	c.AllowedGroups = splitFields(allowedGroups)
	return c, nil
}

const clientCols = `id,client_id,client_secret_hash,name,description,redirect_uris,scopes,base_access,allowed_groups,created_at`

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
		return nil, errors.New("授权码无效或已过期")
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

func (s *Store) UpdateUserAvatar(ctx context.Context, id, avatarURL string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE users SET avatar_url=$1, updated_at=now() WHERE id=$2`, avatarURL, id)
	return err
}

func (s *Store) CreateOIDCProvider(ctx context.Context, name, slug, providerType, icon, clientID, clientSecret, issuerURL, authorizationURL, tokenURL, userinfoURL, scopes string, autoRegister bool) error {
	id := uuid.New().String()
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO oidc_providers(id,name,slug,provider_type,icon,client_id,client_secret,issuer_url,authorization_url,token_url,userinfo_url,scopes,auto_register) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`,
		id, name, slug, providerType, icon, clientID, clientSecret, issuerURL, authorizationURL, tokenURL, userinfoURL, scopes, autoRegister)
	return err
}

func (s *Store) ListOIDCProviders(ctx context.Context) ([]*OIDCProvider, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id,name,slug,provider_type,icon,client_id,client_secret,issuer_url,authorization_url,token_url,userinfo_url,scopes,enabled,auto_register,created_at FROM oidc_providers ORDER BY created_at`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*OIDCProvider
	for rows.Next() {
		p := &OIDCProvider{}
		if err := rows.Scan(&p.ID, &p.Name, &p.Slug, &p.ProviderType, &p.Icon, &p.ClientID, &p.ClientSecret, &p.IssuerURL, &p.AuthorizationURL, &p.TokenURL, &p.UserinfoURL, &p.Scopes, &p.Enabled, &p.AutoRegister, &p.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

func (s *Store) ListEnabledOIDCProviders(ctx context.Context) ([]*OIDCProvider, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id,name,slug,provider_type,icon,client_id,client_secret,issuer_url,authorization_url,token_url,userinfo_url,scopes,enabled,auto_register,created_at FROM oidc_providers WHERE enabled=true ORDER BY created_at`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*OIDCProvider
	for rows.Next() {
		p := &OIDCProvider{}
		if err := rows.Scan(&p.ID, &p.Name, &p.Slug, &p.ProviderType, &p.Icon, &p.ClientID, &p.ClientSecret, &p.IssuerURL, &p.AuthorizationURL, &p.TokenURL, &p.UserinfoURL, &p.Scopes, &p.Enabled, &p.AutoRegister, &p.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

func (s *Store) GetOIDCProviderBySlug(ctx context.Context, slug string) (*OIDCProvider, error) {
	p := &OIDCProvider{}
	err := s.db.QueryRowContext(ctx,
		`SELECT id,name,slug,provider_type,icon,client_id,client_secret,issuer_url,authorization_url,token_url,userinfo_url,scopes,enabled,auto_register,created_at FROM oidc_providers WHERE slug=$1`,
		slug).Scan(&p.ID, &p.Name, &p.Slug, &p.ProviderType, &p.Icon, &p.ClientID, &p.ClientSecret, &p.IssuerURL, &p.AuthorizationURL, &p.TokenURL, &p.UserinfoURL, &p.Scopes, &p.Enabled, &p.AutoRegister, &p.CreatedAt)
	return p, err
}

func (s *Store) GetOIDCProviderByID(ctx context.Context, id string) (*OIDCProvider, error) {
	p := &OIDCProvider{}
	err := s.db.QueryRowContext(ctx,
		`SELECT id,name,slug,provider_type,icon,client_id,client_secret,issuer_url,authorization_url,token_url,userinfo_url,scopes,enabled,auto_register,created_at FROM oidc_providers WHERE id=$1`,
		id).Scan(&p.ID, &p.Name, &p.Slug, &p.ProviderType, &p.Icon, &p.ClientID, &p.ClientSecret, &p.IssuerURL, &p.AuthorizationURL, &p.TokenURL, &p.UserinfoURL, &p.Scopes, &p.Enabled, &p.AutoRegister, &p.CreatedAt)
	return p, err
}

func (s *Store) UpdateOIDCProvider(ctx context.Context, id, name, providerType, icon, clientID, clientSecret, issuerURL, authorizationURL, tokenURL, userinfoURL, scopes string, enabled, autoRegister bool) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE oidc_providers SET name=$1,provider_type=$2,icon=$3,client_id=$4,client_secret=$5,issuer_url=$6,authorization_url=$7,token_url=$8,userinfo_url=$9,scopes=$10,enabled=$11,auto_register=$12 WHERE id=$13`,
		name, providerType, icon, clientID, clientSecret, issuerURL, authorizationURL, tokenURL, userinfoURL, scopes, enabled, autoRegister, id)
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

func (s *Store) LinkIdentity(ctx context.Context, userID, provider, subject string) error {
	id := uuid.New().String()
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO user_identities(id,user_id,provider,subject) VALUES($1,$2,$3,$4) ON CONFLICT(provider,subject) DO NOTHING`,
		id, userID, provider, subject)
	return err
}

func (s *Store) GetUserIdentityByUserAndProvider(ctx context.Context, userID, provider string) (*UserIdentity, error) {
	id := &UserIdentity{}
	err := s.db.QueryRowContext(ctx,
		`SELECT id,user_id,provider,subject,created_at FROM user_identities WHERE user_id=$1 AND provider=$2 ORDER BY created_at DESC LIMIT 1`,
		userID, provider,
	).Scan(&id.ID, &id.UserID, &id.Provider, &id.Subject, &id.CreatedAt)
	if err != nil {
		return nil, err
	}
	return id, nil
}

func (s *Store) DeleteUserIdentityByUserAndProvider(ctx context.Context, userID, provider string) (int64, error) {
	res, err := s.db.ExecContext(ctx, `DELETE FROM user_identities WHERE user_id=$1 AND provider=$2`, userID, provider)
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	return n, nil
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

func (s *Store) CreateOIDCState(ctx context.Context, state, provider, userID, nonce, verifier, redirect string) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO oidc_states(state,provider,user_id,nonce,verifier,redirect,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7)`,
		state, provider, userID, nonce, verifier, redirect, time.Now().Add(10*time.Minute))
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
		`SELECT state,provider,user_id,nonce,verifier,redirect,expires_at FROM oidc_states WHERE state=$1 AND expires_at > now() FOR UPDATE`,
		state).Scan(&st.State, &st.Provider, &st.UserID, &st.Nonce, &st.Verifier, &st.Redirect, &st.ExpiresAt)
	if err != nil {
		return nil, err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM oidc_states WHERE state=$1`, state); err != nil {
		return nil, err
	}
	return st, tx.Commit()
}

func (s *Store) CreateOIDCLinkChallenge(ctx context.Context, provider, subject, userID, redirect string) (string, error) {
	id := uuid.New().String()
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO oidc_link_challenges(id,provider,subject,user_id,redirect,expires_at) VALUES($1,$2,$3,$4,$5,$6)`,
		id, provider, subject, userID, redirect, time.Now().Add(10*time.Minute))
	return id, err
}

func (s *Store) GetOIDCLinkChallenge(ctx context.Context, id string) (*OIDCLinkChallenge, error) {
	ch := &OIDCLinkChallenge{}
	err := s.db.QueryRowContext(ctx,
		`SELECT id,provider,subject,user_id,redirect,expires_at FROM oidc_link_challenges WHERE id=$1`,
		id,
	).Scan(&ch.ID, &ch.Provider, &ch.Subject, &ch.UserID, &ch.Redirect, &ch.ExpiresAt)
	if err != nil {
		return nil, err
	}
	if time.Now().After(ch.ExpiresAt) {
		_, _ = s.db.ExecContext(ctx, `DELETE FROM oidc_link_challenges WHERE id=$1`, id)
		return nil, sql.ErrNoRows
	}
	return ch, nil
}

func (s *Store) ConsumeOIDCLinkChallenge(ctx context.Context, id string) (*OIDCLinkChallenge, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	ch := &OIDCLinkChallenge{}
	err = tx.QueryRowContext(ctx,
		`SELECT id,provider,subject,user_id,redirect,expires_at FROM oidc_link_challenges WHERE id=$1 FOR UPDATE`,
		id,
	).Scan(&ch.ID, &ch.Provider, &ch.Subject, &ch.UserID, &ch.Redirect, &ch.ExpiresAt)
	if err != nil {
		return nil, err
	}
	if time.Now().After(ch.ExpiresAt) {
		_, _ = tx.ExecContext(ctx, `DELETE FROM oidc_link_challenges WHERE id=$1`, id)
		return nil, sql.ErrNoRows
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM oidc_link_challenges WHERE id=$1`, id); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return ch, nil
}

func (s *Store) CreateOIDCLoginChallenge(ctx context.Context, provider, subject, profileName, profileAvatar, profileEmail, redirect string) (string, error) {
	id := uuid.New().String()
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO oidc_login_challenges(id,provider,subject,profile_name,profile_avatar,profile_email,redirect,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8)`,
		id, provider, subject, profileName, profileAvatar, profileEmail, redirect, time.Now().Add(15*time.Minute))
	return id, err
}

func (s *Store) GetOIDCLoginChallenge(ctx context.Context, id string) (*OIDCLoginChallenge, error) {
	ch := &OIDCLoginChallenge{}
	err := s.db.QueryRowContext(ctx,
		`SELECT id,provider,subject,profile_name,profile_avatar,profile_email,redirect,expires_at FROM oidc_login_challenges WHERE id=$1`,
		id,
	).Scan(&ch.ID, &ch.Provider, &ch.Subject, &ch.ProfileName, &ch.ProfileAvatar, &ch.ProfileEmail, &ch.Redirect, &ch.ExpiresAt)
	if err != nil {
		return nil, err
	}
	if time.Now().After(ch.ExpiresAt) {
		_, _ = s.db.ExecContext(ctx, `DELETE FROM oidc_login_challenges WHERE id=$1`, id)
		return nil, sql.ErrNoRows
	}
	return ch, nil
}

func (s *Store) ConsumeOIDCLoginChallenge(ctx context.Context, id string) (*OIDCLoginChallenge, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	ch := &OIDCLoginChallenge{}
	err = tx.QueryRowContext(ctx,
		`SELECT id,provider,subject,profile_name,profile_avatar,profile_email,redirect,expires_at FROM oidc_login_challenges WHERE id=$1 FOR UPDATE`,
		id,
	).Scan(&ch.ID, &ch.Provider, &ch.Subject, &ch.ProfileName, &ch.ProfileAvatar, &ch.ProfileEmail, &ch.Redirect, &ch.ExpiresAt)
	if err != nil {
		return nil, err
	}
	if time.Now().After(ch.ExpiresAt) {
		_, _ = tx.ExecContext(ctx, `DELETE FROM oidc_login_challenges WHERE id=$1`, id)
		return nil, sql.ErrNoRows
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM oidc_login_challenges WHERE id=$1`, id); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return ch, nil
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

type Session struct {
	ID        string
	UserID    string
	CreatedAt time.Time
	ExpiresAt time.Time
}

func (s *Store) GetSessionsByUserID(ctx context.Context, userID string) ([]*Session, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id,user_id,created_at,expires_at FROM sessions WHERE user_id=$1 AND expires_at > now() ORDER BY created_at DESC`,
		userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Session
	for rows.Next() {
		sess := &Session{}
		if err := rows.Scan(&sess.ID, &sess.UserID, &sess.CreatedAt, &sess.ExpiresAt); err != nil {
			return nil, err
		}
		out = append(out, sess)
	}
	return out, rows.Err()
}

func (s *Store) GetUserIdentitiesByUserID(ctx context.Context, userID string) ([]*UserIdentity, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id,user_id,provider,subject,created_at FROM user_identities WHERE user_id=$1 ORDER BY created_at DESC`,
		userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*UserIdentity
	for rows.Next() {
		id := &UserIdentity{}
		if err := rows.Scan(&id.ID, &id.UserID, &id.Provider, &id.Subject, &id.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

func (s *Store) GetAccessTokensByUserID(ctx context.Context, userID string) ([]*AccessToken, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id,user_id,client_id,scopes,expires_at FROM access_tokens WHERE user_id=$1 AND expires_at > now() ORDER BY expires_at DESC`,
		userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*AccessToken
	for rows.Next() {
		t := &AccessToken{}
		var scopes string
		if err := rows.Scan(&t.ID, &t.UserID, &t.ClientID, &scopes, &t.ExpiresAt); err != nil {
			return nil, err
		}
		t.Scopes = strings.Fields(scopes)
		out = append(out, t)
	}
	return out, rows.Err()
}

func (s *Store) GetRefreshTokensByUserID(ctx context.Context, userID string) ([]*RefreshToken, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id,user_id,client_id,scopes,expires_at FROM refresh_tokens WHERE user_id=$1 AND expires_at > now() ORDER BY expires_at DESC`,
		userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*RefreshToken
	for rows.Next() {
		t := &RefreshToken{}
		var scopes string
		if err := rows.Scan(&t.ID, &t.UserID, &t.ClientID, &scopes, &t.ExpiresAt); err != nil {
			return nil, err
		}
		t.Scopes = strings.Fields(scopes)
		out = append(out, t)
	}
	return out, rows.Err()
}

func (s *Store) RevokeAccessTokenByID(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM access_tokens WHERE id=$1`, id)
	return err
}

func (s *Store) RevokeRefreshTokenByID(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM refresh_tokens WHERE id=$1`, id)
	return err
}

func (s *Store) UpdateClient(ctx context.Context, id, name, description string, redirectURIs, scopes []string, baseAccess string, allowedGroups []string) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE oauth_clients SET name=$1,description=$2,redirect_uris=$3,scopes=$4,base_access=$5,allowed_groups=$6 WHERE id=$7`,
		name, description, strings.Join(redirectURIs, "\n"), strings.Join(scopes, " "),
		baseAccess, strings.Join(allowedGroups, " "), id)
	return err
}

func (s *Store) ResetClientSecret(ctx context.Context, id string) (string, error) {
	secret := RandomHex(32)
	h, err := bcrypt.GenerateFromPassword([]byte(secret), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	_, err = s.db.ExecContext(ctx, `UPDATE oauth_clients SET client_secret_hash=$1 WHERE id=$2`, string(h), id)
	return secret, err
}

func (s *Store) GetClientAnnouncement(ctx context.Context, clientID string) string {
	var v string
	err := s.db.QueryRowContext(ctx, `
		SELECT ca.content
		FROM client_announcements ca
		JOIN oauth_clients oc ON oc.id = ca.client_id
		WHERE oc.client_id = $1
	`, clientID).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		// Backward compatibility for old rows keyed by oauth_clients.client_id.
		_ = s.db.QueryRowContext(ctx, `SELECT content FROM client_announcements WHERE client_id=$1`, clientID).Scan(&v)
	}
	return v
}

func (s *Store) SetClientAnnouncement(ctx context.Context, clientID, content string) error {
	res, err := s.db.ExecContext(ctx, `
		INSERT INTO client_announcements(client_id,content)
		SELECT id,$2 FROM oauth_clients WHERE client_id=$1
		ON CONFLICT(client_id) DO UPDATE SET content=EXCLUDED.content, updated_at=now()
	`, clientID, content)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

type PasskeyCredential struct {
	ID           string
	UserID       string
	CredentialID string // base64url encoded
	Credential   string // JSON encoded webauthn.Credential
	Name         string
	CreatedAt    time.Time
}

func (s *Store) CreatePasskeyCredential(ctx context.Context, userID, credentialID, credentialData, name string) error {
	id := uuid.New().String()
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO passkey_credentials(id,user_id,credential_id,credential,name) VALUES($1,$2,$3,$4,$5)`,
		id, userID, credentialID, credentialData, name)
	return err
}

func (s *Store) GetPasskeyCredentialsByUserID(ctx context.Context, userID string) ([]*PasskeyCredential, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id,user_id,credential_id,credential,name,created_at FROM passkey_credentials WHERE user_id=$1 ORDER BY created_at DESC`,
		userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*PasskeyCredential
	for rows.Next() {
		c := &PasskeyCredential{}
		if err := rows.Scan(&c.ID, &c.UserID, &c.CredentialID, &c.Credential, &c.Name, &c.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

func (s *Store) GetPasskeyCredentialByCredentialID(ctx context.Context, credentialID string) (*PasskeyCredential, error) {
	c := &PasskeyCredential{}
	err := s.db.QueryRowContext(ctx,
		`SELECT id,user_id,credential_id,credential,name,created_at FROM passkey_credentials WHERE credential_id=$1`,
		credentialID).Scan(&c.ID, &c.UserID, &c.CredentialID, &c.Credential, &c.Name, &c.CreatedAt)
	return c, err
}

func (s *Store) UpdatePasskeyCredential(ctx context.Context, credentialID, credentialData string) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE passkey_credentials SET credential=$1 WHERE credential_id=$2`,
		credentialData, credentialID)
	return err
}

func (s *Store) DeletePasskeyCredential(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM passkey_credentials WHERE id=$1`, id)
	return err
}

func (s *Store) CountPasskeysByUserID(ctx context.Context, userID string) int {
	var n int
	s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM passkey_credentials WHERE user_id=$1`, userID).Scan(&n)
	return n
}

func (s *Store) CreateWebAuthnSession(ctx context.Context, id, data string) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO webauthn_sessions(id,data,expires_at) VALUES($1,$2,$3)`,
		id, data, time.Now().Add(5*time.Minute))
	return err
}

func (s *Store) GetWebAuthnSession(ctx context.Context, id string) (string, error) {
	var data string
	var exp time.Time
	err := s.db.QueryRowContext(ctx,
		`SELECT data,expires_at FROM webauthn_sessions WHERE id=$1`, id).Scan(&data, &exp)
	if err != nil {
		return "", err
	}
	if time.Now().After(exp) {
		s.db.ExecContext(ctx, `DELETE FROM webauthn_sessions WHERE id=$1`, id)
		return "", errors.New("通行密钥会话已过期")
	}
	return data, nil
}

func (s *Store) DeleteWebAuthnSession(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM webauthn_sessions WHERE id=$1`, id)
	return err
}

type CustomRole struct {
	Name        string
	Label       string
	Permissions []string // e.g. ["manage_projects","manage_clients"]
	CreatedAt   time.Time
}

var defaultRoles = map[string]bool{"user": true, "member": true, "admin": true}

func IsDefaultRole(name string) bool { return defaultRoles[name] }

func (s *Store) ListCustomRoles(ctx context.Context) ([]*CustomRole, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT name,label,permissions,created_at FROM custom_roles ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*CustomRole
	for rows.Next() {
		r := &CustomRole{}
		var perms string
		if err := rows.Scan(&r.Name, &r.Label, &perms, &r.CreatedAt); err != nil {
			return nil, err
		}
		r.Permissions = splitFields(perms)
		out = append(out, r)
	}
	return out, rows.Err()
}

func (s *Store) GetCustomRole(ctx context.Context, name string) (*CustomRole, error) {
	r := &CustomRole{}
	var perms string
	err := s.db.QueryRowContext(ctx,
		`SELECT name,label,permissions,created_at FROM custom_roles WHERE name=$1`, name).
		Scan(&r.Name, &r.Label, &perms, &r.CreatedAt)
	if err != nil {
		return nil, err
	}
	r.Permissions = splitFields(perms)
	return r, nil
}

func (s *Store) CreateCustomRole(ctx context.Context, name, label string, permissions []string) error {
	if IsDefaultRole(name) {
		return errors.New("不能使用系统保留名称创建角色")
	}
	perms := strings.Join(permissions, " ")
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO custom_roles(name,label,permissions) VALUES($1,$2,$3)
		 ON CONFLICT(name) DO UPDATE SET label=EXCLUDED.label, permissions=EXCLUDED.permissions`,
		name, label, perms)
	return err
}

func (s *Store) DeleteCustomRole(ctx context.Context, name string) error {
	if IsDefaultRole(name) {
		return errors.New("不能删除内置角色")
	}
	_, err := s.db.ExecContext(ctx, `DELETE FROM custom_roles WHERE name=$1`, name)
	return err
}

// Friend Links

type FriendLink struct {
	ID        string
	Name      string
	URL       string
	Icon      string
	SortOrder int
	CreatedAt time.Time
}

func (s *Store) ListFriendLinks(ctx context.Context) ([]*FriendLink, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id,name,url,icon,sort_order,created_at FROM friend_links ORDER BY sort_order ASC, created_at ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*FriendLink
	for rows.Next() {
		l := &FriendLink{}
		if err := rows.Scan(&l.ID, &l.Name, &l.URL, &l.Icon, &l.SortOrder, &l.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, l)
	}
	return out, rows.Err()
}

func (s *Store) GetFriendLink(ctx context.Context, id string) (*FriendLink, error) {
	l := &FriendLink{}
	err := s.db.QueryRowContext(ctx,
		`SELECT id,name,url,icon,sort_order,created_at FROM friend_links WHERE id=$1`, id).
		Scan(&l.ID, &l.Name, &l.URL, &l.Icon, &l.SortOrder, &l.CreatedAt)
	if err != nil {
		return nil, err
	}
	return l, nil
}

func (s *Store) CreateFriendLink(ctx context.Context, name, url, icon string, sortOrder int) error {
	id := uuid.New().String()
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO friend_links(id,name,url,icon,sort_order) VALUES($1,$2,$3,$4,$5)`,
		id, name, url, icon, sortOrder)
	return err
}

func (s *Store) UpdateFriendLink(ctx context.Context, id, name, url, icon string, sortOrder int) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE friend_links SET name=$1,url=$2,icon=$3,sort_order=$4 WHERE id=$5`,
		name, url, icon, sortOrder, id)
	return err
}

func (s *Store) DeleteFriendLink(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM friend_links WHERE id=$1`, id)
	return err
}

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

func splitFields(s string) []string {
	var out []string
	for _, f := range strings.Fields(s) {
		if f != "" {
			out = append(out, f)
		}
	}
	return out
}

// User email verification

func (s *Store) SetEmailUnverified(ctx context.Context, userID string) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE users SET email_verified=false, updated_at=now() WHERE id=$1`, userID)
	return err
}

func (s *Store) VerifyUserEmail(ctx context.Context, userID string) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE users SET email_verified=true, updated_at=now() WHERE id=$1`, userID)
	return err
}

func (s *Store) CreateEmailVerification(ctx context.Context, userID string) (string, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return "", err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `DELETE FROM email_verifications WHERE user_id=$1`, userID); err != nil {
		return "", err
	}
	token := RandomHex(32)
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO email_verifications(token,user_id,expires_at) VALUES($1,$2,$3)`,
		token, userID, time.Now().Add(24*time.Hour)); err != nil {
		return "", err
	}
	return token, tx.Commit()
}

func (s *Store) ConsumeEmailVerification(ctx context.Context, token string) (*User, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	var userID string
	var exp time.Time
	err = tx.QueryRowContext(ctx,
		`SELECT user_id, expires_at FROM email_verifications WHERE token=$1 FOR UPDATE`,
		token).Scan(&userID, &exp)
	if err != nil {
		return nil, err
	}
	// Always delete the token (expired or valid) so it cannot be reused.
	if _, err := tx.ExecContext(ctx, `DELETE FROM email_verifications WHERE token=$1`, token); err != nil {
		return nil, err
	}
	if time.Now().After(exp) {
		// Commit to make deletion permanent, then surface expiry error.
		_ = tx.Commit()
		return nil, errors.New("验证链接已过期")
	}
	if _, err := tx.ExecContext(ctx, `UPDATE users SET email_verified=true, updated_at=now() WHERE id=$1`, userID); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return s.GetUserByID(ctx, userID)
}

// Password reset (self-service)

func (s *Store) CreatePasswordReset(ctx context.Context, userID string, cooldown, ttl time.Duration) (string, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return "", err
	}
	defer tx.Rollback()

	var last time.Time
	err = tx.QueryRowContext(ctx,
		`SELECT last_requested_at FROM password_reset_cooldowns WHERE user_id=$1 FOR UPDATE`,
		userID).Scan(&last)
	if err == nil {
		if time.Since(last) < cooldown {
			return "", ErrPasswordResetTooSoon
		}
	} else if !errors.Is(err, sql.ErrNoRows) {
		return "", err
	}

	if _, err := tx.ExecContext(ctx, `DELETE FROM password_resets WHERE user_id=$1`, userID); err != nil {
		return "", err
	}
	token := RandomHex(32)
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO password_resets(token,user_id,expires_at) VALUES($1,$2,$3)`,
		token, userID, time.Now().Add(ttl)); err != nil {
		return "", err
	}
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO password_reset_cooldowns(user_id,last_requested_at) VALUES($1,now())
		 ON CONFLICT(user_id) DO UPDATE SET last_requested_at=EXCLUDED.last_requested_at`,
		userID); err != nil {
		return "", err
	}
	if err := tx.Commit(); err != nil {
		return "", err
	}
	return token, nil
}

func (s *Store) ConsumePasswordReset(ctx context.Context, token, newPass string) (*User, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	var userID string
	var exp time.Time
	err = tx.QueryRowContext(ctx,
		`SELECT user_id, expires_at FROM password_resets WHERE token=$1 FOR UPDATE`, token).
		Scan(&userID, &exp)
	if err != nil {
		return nil, err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM password_resets WHERE token=$1`, token); err != nil {
		return nil, err
	}
	if time.Now().After(exp) {
		_ = tx.Commit()
		return nil, ErrPasswordResetTokenExpired
	}

	h, err := bcrypt.GenerateFromPassword([]byte(newPass), bcrypt.DefaultCost)
	if err != nil {
		return nil, err
	}
	if _, err := tx.ExecContext(ctx,
		`UPDATE users SET password_hash=$1,updated_at=now() WHERE id=$2`, string(h), userID); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return s.GetUserByID(ctx, userID)
}

// User Groups

type UserGroup struct {
	ID        string
	Name      string
	Label     string
	CreatedAt time.Time
}

func (s *Store) CreateUserGroup(ctx context.Context, name, label string) error {
	id := uuid.New().String()
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO user_groups(id,name,label) VALUES($1,$2,$3)`, id, name, label)
	return err
}

func (s *Store) ListUserGroups(ctx context.Context) ([]*UserGroup, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id,name,label,created_at FROM user_groups ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*UserGroup
	for rows.Next() {
		g := &UserGroup{}
		if err := rows.Scan(&g.ID, &g.Name, &g.Label, &g.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, g)
	}
	return out, rows.Err()
}

func (s *Store) GetUserGroupByID(ctx context.Context, id string) (*UserGroup, error) {
	g := &UserGroup{}
	err := s.db.QueryRowContext(ctx,
		`SELECT id,name,label,created_at FROM user_groups WHERE id=$1`, id).
		Scan(&g.ID, &g.Name, &g.Label, &g.CreatedAt)
	return g, err
}

func (s *Store) DeleteUserGroup(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM user_groups WHERE id=$1`, id)
	return err
}

func (s *Store) GetGroupMembers(ctx context.Context, groupID string) ([]*User, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT `+userCols+` FROM users WHERE id IN (
			SELECT user_id FROM user_group_members WHERE group_id=$1
		) ORDER BY display_name`, groupID)
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

func (s *Store) GetUserGroups(ctx context.Context, userID string) ([]*UserGroup, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT g.id, g.name, g.label, g.created_at
		 FROM user_groups g
		 JOIN user_group_members m ON m.group_id=g.id
		 WHERE m.user_id=$1 ORDER BY g.name`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*UserGroup
	for rows.Next() {
		g := &UserGroup{}
		if err := rows.Scan(&g.ID, &g.Name, &g.Label, &g.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, g)
	}
	return out, rows.Err()
}

func (s *Store) AddUserToGroup(ctx context.Context, userID, groupID string) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO user_group_members(user_id,group_id) VALUES($1,$2) ON CONFLICT DO NOTHING`,
		userID, groupID)
	return err
}

func (s *Store) RemoveUserFromGroup(ctx context.Context, userID, groupID string) error {
	_, err := s.db.ExecContext(ctx,
		`DELETE FROM user_group_members WHERE user_id=$1 AND group_id=$2`, userID, groupID)
	return err
}

func hasBaseClientAccess(u *User, baseAccess string) bool {
	switch strings.ToLower(strings.TrimSpace(baseAccess)) {
	case "", "user":
		return true
	case "legacy":
		return false
	case "member":
		return u.IsMember()
	case "admin":
		return u.IsAdmin()
	case "none":
		return false
	default:
		return false
	}
}

// UserCanAccessClient returns true when either condition passes:
//   - baseAccess policy matches the user role
//   - user belongs to at least one allowed group
//
// Group membership supports built-ins (admin/member/user) and custom groups by name.
// Admin is treated as belonging to all groups by default.
func (s *Store) UserCanAccessClient(ctx context.Context, u *User, baseAccess string, allowedGroups []string) bool {
	if u == nil {
		return false
	}
	normalizedBase := strings.ToLower(strings.TrimSpace(baseAccess))
	// Backward-compatible mode:
	// - no groups configured => allow any logged-in user
	// - groups configured => rely only on group matching
	if normalizedBase == "legacy" || normalizedBase == "" {
		if len(allowedGroups) == 0 {
			return true
		}
	} else if hasBaseClientAccess(u, normalizedBase) {
		return true
	}
	if len(allowedGroups) == 0 {
		return false
	}
	if u.IsAdmin() {
		return true
	}
	for _, raw := range allowedGroups {
		g := strings.ToLower(strings.TrimSpace(raw))
		if g == "" {
			continue
		}
		switch g {
		case "admin":
			if u.IsAdmin() {
				return true
			}
		case "member":
			if u.IsMember() {
				return true
			}
		case "user":
			return true
		default:
			var count int
			if err := s.db.QueryRowContext(ctx,
				`SELECT COUNT(*) FROM user_group_members m
				 JOIN user_groups g ON g.id=m.group_id
				 WHERE m.user_id=$1 AND g.name=$2`, u.ID, g).Scan(&count); err == nil && count > 0 {
				return true
			}
		}
	}
	return false
}
