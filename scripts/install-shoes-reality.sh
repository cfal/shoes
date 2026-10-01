#!/bin/sh
# Official reference: https://github.com/cfal/shoes#reality-server
set -eu
set -f
umask 077

ACTION=${1:-start}
case "$ACTION" in
  start|status|stop) ;;
  -h|--help)
    printf '%s\n' '用法：sh install-shoes-reality.sh [start|status|stop]' \
      '默认目录：/root/shoes；默认端口：443。' \
      '可选变量：SHOES_DIR、SHOES_PORT、SHOES_DOMAINS（空格分隔的域名）。'
    exit 0 ;;
  *) printf '%s\n' '参数错误：仅支持 start、status、stop。' >&2; exit 1 ;;
esac

say() { printf '%s\n' "$*"; }
die() { say "错误：$*" >&2; exit 1; }
[ "$(id -u)" -eq 0 ] || die '请以 root 运行。'
[ -f /etc/alpine-release ] || die '此脚本用于 Alpine Linux。'
[ "$(uname -m)" = x86_64 ] || die '此脚本需要 x86_64 架构。'

SHOES_DIR=${SHOES_DIR:-/root/shoes}
SHOES_PORT=${SHOES_PORT:-443}
SHOES_DOMAINS=${SHOES_DOMAINS:-'www.microsoft.com www.bing.com www.cloudflare.com www.apple.com www.amazon.com www.yahoo.com github.com www.google.com'}
case "$SHOES_PORT" in ''|*[!0-9]*) die '端口必须是数字。' ;; esac
[ "$SHOES_PORT" -ge 1 ] && [ "$SHOES_PORT" -le 65535 ] || die '端口范围为 1–65535。'

mkdir -p "$SHOES_DIR"
cd "$SHOES_DIR"
SHOES_DIR=$(pwd -P)
BIN="$SHOES_DIR/shoes"
CONFIG="$SHOES_DIR/config.yaml"
STATE="$SHOES_DIR/.shoes-reality"
PIDFILE="$STATE/shoes.pid"
LOGFILE="$SHOES_DIR/shoes.log"
mkdir -p "$STATE"
chmod 700 "$STATE"
mkdir "$STATE/lock" 2>/dev/null || die "另一次操作正在运行；若已退出，请检查后删除 $STATE/lock。"
trap 'rmdir "$STATE/lock" 2>/dev/null || true' 0
trap 'exit 130' 2
trap 'exit 143' 15

owned_process() {
  [ -r "$PIDFILE" ] || return 1
  pid=$(cat "$PIDFILE")
  case "$pid" in ''|*[!0-9]*) return 1 ;; esac
  [ "$pid" -gt 1 ] || return 1
  kill -0 "$pid" 2>/dev/null || return 1
  [ "$(readlink "/proc/$pid/exe" 2>/dev/null || true)" = "$BIN" ] || return 1
  tr '\000' '\n' < "/proc/$pid/cmdline" | grep -Fxq -- "$CONFIG"
}

stop_process() {
  if owned_process; then
    say "停止本脚本启动的 shoes（PID $pid）……"
    kill "$pid" 2>/dev/null || true
    for _ in 1 2 3 4 5; do
      owned_process || break
      sleep 1
    done
    if owned_process; then kill -KILL "$pid" 2>/dev/null || true; fi
  fi
  rm -f "$PIDFILE"
}

show_connection() {
  uuid=$(sed -n 's/^uuid=//p' "$STATE/identity")
  public_key=$(sed -n 's/^public_key=//p' "$STATE/identity")
  short_id=$(sed -n 's/^short_id=//p' "$STATE/identity")
  domain=$(cat "$STATE/domain")
  say ''
  say '连接参数（服务器地址填写你的 VPS 公网 IP）：'
  say "端口：$SHOES_PORT"
  say '协议：VLESS；传输：TCP；安全：REALITY；flow 留空'
  say "UUID：$uuid"
  say "公钥：$public_key"
  say "SNI：$domain"
  say "short ID：$short_id"
  say "配置：$CONFIG"
  say "日志：$LOGFILE"
}

if [ "$ACTION" = stop ]; then stop_process; say '已停止。'; exit 0; fi
if [ "$ACTION" = status ]; then
  owned_process || die '未检测到本脚本启动的 shoes。'
  if [ -f "$STATE/port" ]; then SHOES_PORT=$(cat "$STATE/port"); fi
  say "shoes 正在后台运行，PID：$pid"
  [ -f "$STATE/identity" ] && [ -f "$STATE/domain" ] && show_connection
  exit 0
fi

if [ -f "$CONFIG" ] && ! grep -Fq '# Managed by install-shoes-reality.sh' "$CONFIG"; then
  die "已存在非本脚本管理的 $CONFIG；请另设 SHOES_DIR 或先移走该文件。"
fi

missing=0
for tool in curl openssl ping setsid ss timeout; do
  command -v "$tool" >/dev/null 2>&1 || missing=1
done
[ -f /etc/ssl/certs/ca-certificates.crt ] || missing=1
if [ "$missing" -eq 1 ]; then
  say '安装 curl、证书、OpenSSL、ping、setsid 和网络检查工具……'
  apk add --no-cache curl ca-certificates openssl iputils util-linux iproute2
fi

# Pinned, published musl release; digest comes from GitHub's release asset.
VERSION=v0.2.7
ARCHIVE=shoes-x86_64-unknown-linux-musl.tar.gz
SHA256=e60ccde92490624d9ff399dd58e69d4d6943b33c5cc4f0b0d1509b0c644fbc2a
if [ ! -f "$BIN" ]; then
  say "下载官方 $VERSION Alpine/musl 压缩包……"
  curl --fail --location --retry 3 --connect-timeout 15 --max-time 180 \
    --output "$ARCHIVE.part" \
    "https://github.com/cfal/shoes/releases/download/$VERSION/$ARCHIVE"
  printf '%s  %s\n' "$SHA256" "$ARCHIVE.part" | sha256sum -c - >/dev/null \
    || { rm -f "$ARCHIVE.part"; die '压缩包 SHA-256 校验失败。'; }
  mv "$ARCHIVE.part" "$ARCHIVE"
  tar -xzf "$ARCHIVE" shoes
fi
chmod +x "$BIN"

if [ ! -f "$STATE/identity" ]; then
  say '生成 UUID、REALITY 密钥对和 short ID……'
  uuid=$(cat /proc/sys/kernel/random/uuid)
  key_output=$("$BIN" generate-reality-keypair) || die '密钥生成失败；请确认使用 musl 安装包。'
  private_key=$(printf '%s\n' "$key_output" | sed -n 's/^REALITY private key: *//p')
  public_key=$(printf '%s\n' "$key_output" | sed -n 's/^REALITY public key: *//p')
  short_id=$(cat /proc/sys/kernel/random/uuid | tr -d '-' | cut -c1-16)
else
  uuid=$(sed -n 's/^uuid=//p' "$STATE/identity")
  private_key=$(sed -n 's/^private_key=//p' "$STATE/identity")
  public_key=$(sed -n 's/^public_key=//p' "$STATE/identity")
  short_id=$(sed -n 's/^short_id=//p' "$STATE/identity")
  say '沿用已保存的 UUID 与密钥。'
fi
printf '%s\n' "$uuid" | grep -Eq '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' || die 'UUID 格式异常。'
for key in "$private_key" "$public_key"; do
  printf '%s\n' "$key" | grep -Eq '^[A-Za-z0-9_-]{43}$' || die 'REALITY 密钥格式异常。'
done
printf '%s\n' "$short_id" | grep -Eq '^[0-9a-f]{16}$' || die 'short ID 格式异常。'
if [ ! -f "$STATE/identity" ]; then
  printf 'uuid=%s\nprivate_key=%s\npublic_key=%s\nshort_id=%s\n' \
    "$uuid" "$private_key" "$public_key" "$short_id" > "$STATE/identity.new"
  chmod 600 "$STATE/identity.new"
  mv "$STATE/identity.new" "$STATE/identity"
fi

ping_domain() { ping -4 -c 2 -W 3 "$1" >/dev/null 2>&1; }
tls_probe() {
  timeout 12 openssl s_client -4 -connect "$2" -servername "$1" \
    -tls1_3 -verify_hostname "$1" -verify_return_error \
    -CAfile /etc/ssl/certs/ca-certificates.crt -brief \
    < /dev/null > "$STATE/tls-probe.log" 2>&1
}
listening() {
  owned_process || return 1
  ss -H -lntp "sport = :$SHOES_PORT" 2>/dev/null | grep -Fq "pid=$pid,"
}

start_process() {
  stop_process
  if ss -H -lnt "sport = :$SHOES_PORT" | grep -q .; then
    die "端口 $SHOES_PORT 已被其他程序占用，请设置 SHOES_PORT；日志：$LOGFILE。"
  fi
  setsid sh -c 'printf "%s\n" "$$" > "$1"; shift; exec "$@"' \
    sh "$PIDFILE" "$BIN" --threads 2 --no-reload "$CONFIG" \
    < /dev/null >> "$LOGFILE" 2>&1 &
  for _ in 1 2 3 4 5 6 7 8 9 10; do
    sleep 1
    if listening; then
      sleep 1
      listening && return 0
    fi
  done
  return 1
}

for domain in $SHOES_DOMAINS; do
  case "$domain" in ''|*[!A-Za-z0-9.-]*|.*|-*|*..*) say "忽略无效域名：$domain"; continue ;; esac
  say "检查候选域名：$domain（ping / TCP 443 / TLS 1.3）……"
  if ! ping_domain "$domain" || ! tls_probe "$domain" "$domain:443"; then
    say "$domain 检查失败，改用下一个域名。"
    continue
  fi
  cat > "$STATE/config.new" <<YAML
# Managed by install-shoes-reality.sh
- address: "0.0.0.0:$SHOES_PORT"
  protocol:
    type: tls
    reality_targets:
      "$domain":
        private_key: "$private_key"
        short_ids: ["$short_id"]
        dest: "$domain:443"
        protocol:
          type: vless
          user_id: "$uuid"
          udp_enabled: true
YAML
  chmod 600 "$STATE/config.new"
  "$BIN" --dry-run "$STATE/config.new" > "$STATE/config-check.log" 2>&1 \
    || die "配置校验失败，详情：$STATE/config-check.log。"
  stop_process
  mv "$STATE/config.new" "$CONFIG"
  printf '%s\n' "$domain" > "$STATE/domain"
  printf '%s\n' "$SHOES_PORT" > "$STATE/port"
  started=0
  for attempt in 1 2 3; do
    say "使用 setsid 后台启动 shoes（第 $attempt 次）……"
    if start_process; then started=1; break; fi
    say '后台进程未就绪，准备重试。'
  done
  if [ "$started" -ne 1 ]; then
    stop_process
    die "后台启动失败，详情：$LOGFILE。"
  fi
  say '再次检查目标域名，并通过本地 shoes 验证 TLS 转发……'
  if ping_domain "$domain" && tls_probe "$domain" "127.0.0.1:$SHOES_PORT" && listening; then
    say "shoes 已确认在后台运行，PID：$pid"
    show_connection
    exit 0
  fi
  say "$domain 启动后检查失败，停止当前 shoes 并切换域名。"
  stop_process
done
die '候选域名均未通过检查。请确认 VPS 的 DNS、ICMP 和出站 TCP 443，或设置 SHOES_DOMAINS 后重试。'
