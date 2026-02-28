#!/bin/bash
set -e

# 迁移脚本：将 Docker 命名卷 pgdata 迁移到当前目录下的 ./pgdata/
# 用法：在项目根目录下运行 bash migrate-volume.sh

COMPOSE_PROJECT=$(basename "$(pwd)")
VOLUME_NAME="${COMPOSE_PROJECT}_pgdata"
LOCAL_DIR="$(pwd)/pgdata"

echo "==> 检查命名卷 ${VOLUME_NAME} 是否存在..."
if ! docker volume inspect "${VOLUME_NAME}" > /dev/null 2>&1; then
  echo "错误：找不到卷 ${VOLUME_NAME}，请确认项目目录名和卷名是否匹配。"
  echo "当前存在的卷："
  docker volume ls
  exit 1
fi

echo "==> 停止容器（保留卷数据）..."
docker compose down

echo "==> 创建本地目录 ${LOCAL_DIR}..."
mkdir -p "${LOCAL_DIR}"

echo "==> 从命名卷复制数据到 ${LOCAL_DIR}..."
docker run --rm \
  -v "${VOLUME_NAME}:/source" \
  -v "${LOCAL_DIR}:/dest" \
  alpine sh -c "cp -av /source/. /dest/"

echo "==> 启动容器（使用新的绑定挂载）..."
docker compose up -d

echo "==> 等待数据库就绪..."
sleep 5
docker compose ps

echo ""
echo "==> 迁移完成！数据现在存储在 ${LOCAL_DIR}"
echo "==> 确认服务正常后，可以手动删除旧的命名卷："
echo "    docker volume rm ${VOLUME_NAME}"
