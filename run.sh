#!/usr/bin/env bash
set -euo pipefail

REPOSITORY="${NODEBENCH_REPOSITORY:-floriary0/NodeBench}"
RAW_BASE="https://raw.githubusercontent.com/${REPOSITORY}/main"
WORKER_URL="${NODEBENCH_WORKER_URL:-https://report.nodebench.workers.dev}"
PUBLIC_BASE_URL="${NODEBENCH_PUBLIC_BASE_URL:-$WORKER_URL}"
INSTALL_DIR="${NODEBENCH_INSTALL_DIR:-/usr/local/bin}"
SESSION_NAME="${NODEBENCH_TMUX_SESSION:-nodebench}"

say() {
  printf '[NodeBench] %s\n' "$*"
}

TEMP_DIR="$(mktemp -d)"
cleanup() {
  rm -rf -- "$TEMP_DIR"
}
trap cleanup EXIT

if [[ -z "${NODEBENCH_INSTALL_DEPS:-}" ]]; then
  NODEBENCH_INSTALL_DEPS=0
  for dependency in sysbench fio openssl nping traceroute tmux tosutil unshare mount findmnt; do
    if ! command -v "$dependency" >/dev/null 2>&1; then
      NODEBENCH_INSTALL_DEPS=1
      break
    fi
  done
fi

say "安装或更新客户端"
curl -fL --retry 3 --connect-timeout 15 \
  "${RAW_BASE}/install.sh" -o "${TEMP_DIR}/install.sh"
NODEBENCH_REPOSITORY="$REPOSITORY" \
NODEBENCH_VERSION="${NODEBENCH_VERSION:-latest}" \
NODEBENCH_INSTALL_DIR="$INSTALL_DIR" \
NODEBENCH_INSTALL_DEPS="$NODEBENCH_INSTALL_DEPS" \
  bash "${TEMP_DIR}/install.sh"

NODEBENCH_BIN="${INSTALL_DIR}/nodebench"
[[ -x "$NODEBENCH_BIN" ]] || {
  printf '[NodeBench] 错误：安装后找不到 %s\n' "$NODEBENCH_BIN" >&2
  exit 1
}
cleanup
trap - EXIT

if [[ "${NODEBENCH_DRY_RUN:-0}" == "1" ]]; then
  "$NODEBENCH_BIN" --help >/dev/null
  say "一键运行脚本检查通过"
  exit 0
fi

COMMAND=(
  "$NODEBENCH_BIN"
  --worker-url "$WORKER_URL"
  --public-base-url "$PUBLIC_BASE_URL"
  "$@"
)

if [[ "$(id -u)" -ne 0 ]]; then
  if ! command -v sudo >/dev/null 2>&1; then
    printf '[NodeBench] 错误：请以 root 运行，或先安装 sudo\n' >&2
    exit 1
  fi
  COMMAND=(sudo "${COMMAND[@]}")
fi

if [[ -z "${TMUX:-}" && "${NODEBENCH_NO_TMUX:-0}" != "1" ]] &&
  command -v tmux >/dev/null 2>&1 && [[ -t 0 && -t 1 ]]; then
  printf -v COMMAND_LINE '%q ' "${COMMAND[@]}"
  COMMAND_LINE+='; status=$?; printf "\nNodeBench 已结束，退出码：%s\n" "$status"; printf "结果仍保留在当前 tmux 会话中。\n"; exec "${SHELL:-/bin/bash}"'
  say "进入 tmux 会话 ${SESSION_NAME}；SSH 断开后重新执行同一条命令即可恢复"
  say "手动脱离会话：按 Ctrl-b，再按 d"
  exec tmux new-session -A -s "$SESSION_NAME" "$COMMAND_LINE"
fi

if [[ "${NODEBENCH_NO_TMUX:-0}" != "1" ]] && ! command -v tmux >/dev/null 2>&1; then
  say "未安装 tmux；SSH 断开会中止本次测评"
fi

exec "${COMMAND[@]}"
