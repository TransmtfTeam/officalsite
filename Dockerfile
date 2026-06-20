# ── Stage 1: build the React SPA ──────────────────────────────────────────
FROM node:24-alpine AS web
RUN corepack enable
WORKDIR /web
# Install deps first (cached unless manifest/lockfile change).
COPY web/app/package.json web/app/pnpm-lock.yaml web/app/pnpm-workspace.yaml ./
RUN pnpm install --frozen-lockfile
COPY web/app/ ./
RUN pnpm build           # outputs /web/dist (index.html + hashed assets)

# ── Stage 2: build the Go server (embeds the SPA build) ───────────────────
FROM golang:1.23-alpine AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
# Overlay the freshly built SPA over the committed placeholder before embedding.
COPY --from=web /web/dist ./web/app/dist
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o server .

# ── Stage 3: minimal runtime ──────────────────────────────────────────────
FROM alpine:3.19
RUN apk add --no-cache ca-certificates tzdata
WORKDIR /app
COPY --from=builder /app/server .
EXPOSE 8080
CMD ["./server"]
