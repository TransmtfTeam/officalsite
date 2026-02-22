# Team TransMTF — 官网 & 身份中台

一个 **Go + PostgreSQL + Docker Compose** 一体化系统，同时提供：

- 📄 **公开官网** — 介绍 MTF（跨性别女性）的渐变风格首页 + 团队/项目展示
- 🔐 **OIDC / OAuth2 Provider** — 标准授权服务器，可为第三方应用提供单点登录
- 🔗 **OIDC RP（外部登录）** — 管理员配置 Twitter/X、Google 等提供商，用户一键登录自动注册
- 👥 **用户与权限管理** — 三级角色（管理员 / 成员 / 用户）+ 管理面板
- 📃 **TOS / Privacy** — 服务条款与隐私政策页面，内容由管理员在设置中编辑

---

## 功能概览

### 公开页面
| 路径 | 说明 |
|------|------|
| `/` | 官网首页（MTF 介绍 + 团队项目） |
| `/login` | 登录（邮箱密码 + 外部 OIDC 按钮） |
| `/register` | 注册 |
| `/profile` | 个人资料（需登录） |
| `/tos` | 服务条款 |
| `/privacy` | 隐私政策 |

### OIDC / OAuth2 端点
| 端点 | 说明 |
|------|------|
| `GET /.well-known/openid-configuration` | Discovery 文档 |
| `GET /.well-known/jwks.json` | RSA 公钥集 |
| `GET /oauth2/authorize` | 授权页（需登录） |
| `POST /oauth2/authorize` | 用户确认/拒绝授权 |
| `POST /oauth2/token` | 签发 Token |
| `GET /oauth2/userinfo` | 用户信息 |
| `POST /oauth2/revoke` | 吊销 Token |
| `POST /oauth2/introspect` | Token 自省 |

**支持的 Grant Type：**
- `authorization_code` + PKCE（S256 / plain）
- `refresh_token`（轮换式）
- `client_credentials`（机器对机器）

### 管理面板 `/admin`（仅管理员）
- 用户管理：创建 / 编辑角色 / 启停 / 删除
- OIDC 应用注册：注册客户端、查看 Client ID / Secret
- **外部登录方式**：添加/启停 Twitter/X、Google 等 OIDC 提供商
- 站点设置：网站名称、联系邮箱、公告、TOS / Privacy 内容

### 成员面板 `/member`（成员及以上）
- 项目管理：创建 / 编辑 / 删除首页展示的项目

---

## 技术栈

| 层次 | 技术 |
|------|------|
| 语言 | Go 1.22 |
| HTTP | `net/http`（标准库，方法路由 `"GET /path"`） |
| 数据库 | PostgreSQL 16，`database/sql` + `lib/pq` |
| JWT | `golang-jwt/jwt` v5，RS256 签名 |
| 密码 | bcrypt |
| 容器 | Docker + Docker Compose |
| 前端 | 纯 HTML/CSS（无 JS 框架），embed 打包进二进制 |

---

## 快速开始

### 前置要求
- Docker & Docker Compose
- Go 1.22+（仅首次生成 `go.sum` 时需要）

### 1. 生成依赖文件

```bash
go mod tidy
```

### 2. 配置环境变量

```bash
cp .env.example .env
```

编辑 `.env`：

```env
DB_PASSWORD=your_strong_database_password
ISSUER=https://id.transmtf.com        # 公网可访问的地址，不带末尾斜杠
ADMIN_EMAIL=contact@transmtf.com
ADMIN_PASSWORD=your_strong_admin_password
SESSION_SECRET=openssl rand -hex 32   # 替换为真实随机值
PORT=8080
```

> **生成 SESSION_SECRET：** `openssl rand -hex 32`

### 3. 启动服务

```bash
docker compose up -d --build
```

首次启动会自动：
1. 初始化 PostgreSQL 数据库（执行 schema.sql）
2. 创建 `ADMIN_EMAIL` 对应的管理员账号
3. 生成 RSA-2048 签名密钥并持久化到数据库

### 4. 访问服务

| 地址 | 说明 |
|------|------|
| `http://localhost:8080/` | 官网首页 |
| `http://localhost:8080/login` | 以管理员身份登录 |
| `http://localhost:8080/admin` | 管理面板 |

> **管理员账号** 由 `ADMIN_EMAIL` + `ADMIN_PASSWORD` 环境变量在**首次启动时自动创建**。
> 如果该账号已存在，密码不会被重置（防止意外覆盖）。
> 登录后请立即前往 `/admin/settings` 填写 TOS 和隐私政策内容。

---

## 添加外部登录（OIDC RP）

1. 在对应平台（如 Google Cloud、Twitter Developer Portal）创建 OAuth2 应用
2. 将回调地址设为 `https://你的域名/auth/oidc/{slug}/callback`
3. 登录管理面板 → `/admin/providers` → 填写信息 → 添加
4. 用户登录时会看到对应的"使用 X 登录"按钮
5. 首次登录自动注册为 `user` 角色（管理员可在用户管理中升级）

**Twitter/X 配置要点：**
- 在 Developer Portal 开启 OAuth 2.0 + PKCE + User Context
- Issuer URL：`https://twitter.com`
- Scopes：`openid email`（email 需单独申请权限）
- Callback URL：`https://你的域名/auth/oidc/twitter/callback`

**Google 配置：**
- Issuer URL：`https://accounts.google.com`
- Scopes：`openid email profile`

---

## 注册 OIDC 客户端

1. 以管理员身份登录，进入 `/admin/clients`
2. 填写应用名称、Redirect URI（每行一个）、Scope
3. 提交后页面会 **只显示一次** Client Secret，请立即保存

**客户端配置示例：**

```
Client ID:     tmtf_xxxxxxxxxxxx
Client Secret: xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
Authorization Endpoint: https://id.transmtf.com/oauth2/authorize
Token Endpoint:         https://id.transmtf.com/oauth2/token
JWKS URI:               https://id.transmtf.com/.well-known/jwks.json
Scopes:                 openid profile email
```

---

## 用户角色

| 角色 | 权限 |
|------|------|
| `user` | 登录、查看个人资料、使用 OIDC 授权 |
| `member` | 以上 + 管理网站项目（`/member`） |
| `admin` | 以上 + 用户管理、应用注册、站点设置（`/admin`） |

角色由管理员在 `/admin/users` 中分配。

---

## 项目结构

```
.
├── main.go                        # 入口：embed、解析模板、启动服务
├── Dockerfile                     # 多阶段构建
├── docker-compose.yml             # PostgreSQL + 应用
├── .env.example                   # 环境变量模板
├── internal/
│   ├── config/config.go           # 从环境变量加载配置
│   ├── crypto/keys.go             # RSA 密钥管理 + JWT 签名
│   ├── store/
│   │   ├── schema.sql             # 数据库 Schema（自动 migrate）
│   │   └── store.go               # 全部数据库操作
│   └── server/
│       ├── server.go              # 路由、Session、模板渲染
│       ├── handlers_public.go     # 首页、登录、注册、个人资料
│       ├── handlers_oidc.go       # OIDC/OAuth2 端点
│       ├── handlers_admin.go      # 管理面板
│       └── handlers_member.go     # 成员面板
└── web/
    ├── static/css/app.css         # 样式（trans 主题色 + glassmorphism）
    └── templates/                 # HTML 模板（Go embed 打包）
        ├── base.html
        ├── home.html
        ├── login.html / register.html
        ├── consent.html           # OIDC 授权确认页
        ├── profile.html
        ├── error.html
        ├── admin_*.html
        └── member_*.html
```

---

## 安全说明

- 密码使用 **bcrypt** 哈希存储
- Session Cookie：HMAC-SHA256 签名，`HttpOnly` + `SameSite=Lax`
- Access / Refresh Token：随机值仅以 SHA-256 哈希存入数据库
- RSA 私钥存于数据库 `settings` 表，建议生产环境限制数据库访问权限
- Revoke / Introspect 端点需要客户端认证
- Open Redirect 防护：登录回跳仅允许站内路径（以 `/` 开头）

---

## 联系我们

**contact@transmtf.com**
