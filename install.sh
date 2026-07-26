#!/usr/bin/env bash
set -euo pipefail

REPOSITORY="${NODEBENCH_REPOSITORY:-floriary0/NodeBench}"
VERSION="${NODEBENCH_VERSION:-latest}"
INSTALL_DIR="${NODEBENCH_INSTALL_DIR:-/usr/local/bin}"
INSTALL_DEPS="${NODEBENCH_INSTALL_DEPS:-1}"

say() {
  printf '[NodeBench] %s\n' "$*"
}

fail() {
  printf '[NodeBench] 错误：%s\n' "$*" >&2
  exit 1
}

if [[ "$(uname -s)" != "Linux" ]]; then
  fail "当前安装器只支持 Linux"
fi

case "$(uname -m)" in
  x86_64 | amd64) ARCH="amd64" ;;
  aarch64 | arm64) ARCH="arm64" ;;
  *) fail "暂不支持架构：$(uname -m)" ;;
esac

if [[ "$(id -u)" -eq 0 ]]; then
  SUDO=()
elif command -v sudo >/dev/null 2>&1; then
  SUDO=(sudo)
else
  fail "请以 root 运行，或先安装 sudo"
fi

install_dependencies() {
  [[ "$INSTALL_DEPS" == "1" ]] || return 0
  say "检查并安装测评依赖"
  if command -v apt-get >/dev/null 2>&1; then
    "${SUDO[@]}" apt-get update
    "${SUDO[@]}" env DEBIAN_FRONTEND=noninteractive apt-get install -y \
      ca-certificates curl tar coreutils openssl
    "${SUDO[@]}" env DEBIAN_FRONTEND=noninteractive apt-get install -y \
      sysbench fio nmap traceroute tmux util-linux || true
  elif command -v dnf >/dev/null 2>&1; then
    "${SUDO[@]}" dnf install -y ca-certificates curl tar coreutils openssl
    "${SUDO[@]}" dnf install -y sysbench fio nmap traceroute tmux util-linux || true
  elif command -v yum >/dev/null 2>&1; then
    "${SUDO[@]}" yum install -y ca-certificates curl tar coreutils openssl
    "${SUDO[@]}" yum install -y sysbench fio nmap traceroute tmux util-linux || true
  elif command -v apk >/dev/null 2>&1; then
    "${SUDO[@]}" apk add --no-cache ca-certificates curl tar coreutils openssl
    "${SUDO[@]}" apk add --no-cache sysbench fio nmap nmap-nping traceroute tmux util-linux || \
      "${SUDO[@]}" apk add --no-cache sysbench fio nmap traceroute tmux util-linux || true
  else
    say "未识别系统包管理器，将只安装 NodeBench 二进制"
  fi
}

install_dependencies

for command_name in curl tar sha256sum; do
  command -v "$command_name" >/dev/null 2>&1 || fail "缺少命令：$command_name"
done

ASSET="nodebench-linux-${ARCH}.tar.gz"
if [[ "$VERSION" == "latest" ]]; then
  RELEASE_BASE="https://github.com/${REPOSITORY}/releases/latest/download"
else
  RELEASE_BASE="https://github.com/${REPOSITORY}/releases/download/${VERSION}"
fi

TEMP_DIR="$(mktemp -d)"
trap 'rm -rf -- "$TEMP_DIR"' EXIT

install_tosutil() {
  [[ "$INSTALL_DEPS" == "1" ]] || return 0
  command -v tosutil >/dev/null 2>&1 && return 0
  local url checksum
  case "$ARCH" in
    amd64)
      url="https://m645b3e1bb36e-mrap.mrap.accesspoint.tos-global.volces.com/linux/amd64/tosutil"
      checksum="de97013fbf179a88fcc8da5035617cbed07e1318871e9af6e076348e879d9386"
      ;;
    arm64)
      url="https://m645b3e1bb36e-mrap.mrap.accesspoint.tos-global.volces.com/linux/arm64/tosutil"
      checksum="4386e0bbf17d2a67fb05bcf90a7a9b6dd39dba8eeb6c2ab84becaca6ee24abcc"
      ;;
  esac
  say "下载并校验 tosutil 单线程测速工具"
  if ! curl -fL --retry 3 --connect-timeout 15 "$url" -o "${TEMP_DIR}/tosutil"; then
    say "提示：tosutil 下载失败，三网带宽模块会跳过"
    return 0
  fi
  if [[ "$(sha256sum "${TEMP_DIR}/tosutil" | awk '{print $1}')" != "$checksum" ]]; then
    say "提示：tosutil 校验失败，出于安全考虑不安装"
    return 0
  fi
  "${SUDO[@]}" install -d -m 0755 "$INSTALL_DIR"
  "${SUDO[@]}" install -m 0755 "${TEMP_DIR}/tosutil" "${INSTALL_DIR}/tosutil"
}

install_tosutil

say "下载 ${ASSET}"
curl -fL --retry 3 --connect-timeout 15 \
  "${RELEASE_BASE}/${ASSET}" -o "${TEMP_DIR}/${ASSET}"
curl -fL --retry 3 --connect-timeout 15 \
  "${RELEASE_BASE}/SHA256SUMS" -o "${TEMP_DIR}/SHA256SUMS"

(
  cd "$TEMP_DIR"
  grep "  ${ASSET}\$" SHA256SUMS > SHA256SUMS.selected ||
    fail "校验文件中没有 ${ASSET}"
  sha256sum -c SHA256SUMS.selected
  tar -xzf "$ASSET"
)

[[ -x "${TEMP_DIR}/nodebench" ]] || fail "Release 包中没有 nodebench"
"${SUDO[@]}" install -d -m 0755 "$INSTALL_DIR"
"${SUDO[@]}" install -m 0755 "${TEMP_DIR}/nodebench" "${INSTALL_DIR}/nodebench"

say "已安装：${INSTALL_DIR}/nodebench"
for dependency in sysbench fio openssl nping traceroute tmux tosutil unshare mount findmnt; do
  if ! command -v "$dependency" >/dev/null 2>&1; then
    say "提示：缺少 ${dependency}，对应测评模块会跳过"
  fi
done

cat <<'EOF'

运行并上传生产报告：

  nodebench \
    --worker-url https://report.nodebench.workers.dev \
    --public-base-url https://report.nodebench.workers.dev

建议先运行 `tmux new -s nodebench`，避免 SSH 断开导致任务中止。
EOF
