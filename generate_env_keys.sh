#!/usr/bin/env sh
set -eu

ENV_FILE="${1:-.env}"
TEMPLATE_FILE=".env.example"

if ! command -v openssl >/dev/null 2>&1; then
  echo "错误：未找到 openssl，请先安装 openssl。" >&2
  exit 1
fi

if [ ! -f "$ENV_FILE" ]; then
  if [ -f "$TEMPLATE_FILE" ]; then
    cp "$TEMPLATE_FILE" "$ENV_FILE"
    echo "已根据 $TEMPLATE_FILE 创建 $ENV_FILE"
  else
    cat > "$ENV_FILE" <<'EOT'
DB_PASSWORD=
ISSUER=https://auth.transmtf.com
ADMIN_EMAIL=contact@transmtf.com
ADMIN_PASSWORD=replace_with_strong_admin_password
SESSION_SECRET=
PORT=8080
EOT
    echo "已创建新的 $ENV_FILE"
  fi
fi

DB_PASSWORD="$(openssl rand -hex 24)"
SESSION_SECRET="$(openssl rand -hex 32)"

set_kv() {
  key="$1"
  value="$2"
  file="$3"

  if grep -q "^${key}=" "$file"; then
    sed -i "s|^${key}=.*|${key}=${value}|" "$file"
  else
    printf '%s=%s\n' "$key" "$value" >> "$file"
  fi
}

set_kv "DB_PASSWORD" "$DB_PASSWORD" "$ENV_FILE"
set_kv "SESSION_SECRET" "$SESSION_SECRET" "$ENV_FILE"

echo "已更新 $ENV_FILE 中的随机密钥："
echo "- DB_PASSWORD"
echo "- SESSION_SECRET"
echo "已保留 ADMIN_EMAIL / ADMIN_PASSWORD 原值，不做修改。"
