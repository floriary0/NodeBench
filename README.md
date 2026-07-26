# NodeBench

面向中国用户的 VPS 综合测评客户端。客户端使用 Go 编写，在 VPS 本机完成
系统、性能、TCP 质量和三网回程测评，最终只上传一份经过脱敏与 Schema
校验的 JSON 报告。

生产报告站：

<https://report.nodebench.workers.dev>

> 当前 `v0.2.x` 是可公开试用的开发版本。系统、Sysbench/Fio 性能、全国
> 三网 TCP SYN、国际/CDN 可达性、TCP 回程、IP 风险、常用服务解锁和评分
> 已经可用，三网带宽测速正常预算约 3GB、全局异常硬上限为 12GB。页面会
> 把未采集项目标为“未测”，不会使用模拟数据补位。

## 一键运行

在 VPS 上执行这一条命令即可自动安装或更新客户端、补齐依赖、进入 `tmux`
并开始交互式测评，完成后自动上传生产 Worker：

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/floriary0/NodeBench/main/run.sh)
```

如果 SSH 意外断开，重新执行同一条命令会连接回现有的 `nodebench` tmux
会话。手动脱离但保持后台运行：按 `Ctrl-b`，再按 `d`。

跳过交互、直接接受标准模式：

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/floriary0/NodeBench/main/run.sh) --yes
```

查看最近一次任务状态：

```bash
nodebench --status latest
```

也可以把 `latest` 换成终端中显示的具体报告 ID。

不使用 tmux：

```bash
NODEBENCH_NO_TMUX=1 \
  bash <(curl -fsSL https://raw.githubusercontent.com/floriary0/NodeBench/main/run.sh)
```

## 仅安装

支持 Linux AMD64 (`x86_64`) 和 ARM64 (`aarch64`)：

```bash
curl -fsSL https://raw.githubusercontent.com/floriary0/NodeBench/main/install.sh | sudo bash
```

安装器会：

1. 检测 CPU 架构；
2. 从最新 GitHub Release 下载对应静态二进制；
3. 使用 `SHA256SUMS` 校验文件；
4. 安装到 `/usr/local/bin/nodebench`；
5. 尝试安装 `sysbench`、`fio`、`nping`、`traceroute`、`tosutil` 和
   `tmux`；`tosutil` 使用固定 SHA-256 校验。

不希望安装器修改系统软件包时：

```bash
curl -fsSL https://raw.githubusercontent.com/floriary0/NodeBench/main/install.sh \
  | sudo NODEBENCH_INSTALL_DEPS=0 bash
```

## 手动运行并上传

建议以 root 身份运行，因为 `nping` TCP SYN 探测通常需要原始套接字权限。
为防止 SSH 断开导致测评中止，先进入 `tmux`：

```bash
tmux new -s nodebench
```

然后运行：

```bash
nodebench \
  --worker-url https://report.nodebench.workers.dev \
  --public-base-url https://report.nodebench.workers.dev
```

程序会交互询问是否填写厂商、套餐、价格、带宽、流量、机房和备注。每项都
可以直接回车跳过。在正式开始前会输出统一报告链接；报告默认公开，任何
拿到链接的人都可以查看脱敏后的测评结果。

退出 `tmux` 而不中止任务：按 `Ctrl-b`，再按 `d`。重新连接：

```bash
tmux attach -t nodebench
```

本地结果保存在：

```text
/root/.local/share/nodebench/tasks/<report_id>/
├── report.json
├── report.txt
├── state.json
└── credentials.json
```

任务目录权限为 `0700`，文件权限为 `0600`。上传成功后本地上传密钥会被
清空；公开报告链接不包含任何访问密钥。

## 依赖

| 命令 | 用途 | 缺失时 |
| --- | --- | --- |
| `sysbench` | CPU、内存性能 | 性能部分跳过 |
| `openssl` | AES-256-GCM CPU 吞吐 | AES 性能项跳过 |
| `fio` | 磁盘性能 | 磁盘性能跳过 |
| `nping` | 三网、国际、CDN TCP SYN | TCP 质量跳过 |
| `traceroute` | 三网 TCP 回程 | 回程跳过 |
| `tosutil`、`unshare`、`mount`、`findmnt` | 三网单线程带宽 | 带宽跳过 |
| `tmux` | SSH 断线后保持任务 | 需要保持 SSH 在线 |

客户端还需要访问：

- `https://tcpquality.ibsgss.uk`：获取三网节点目录；
- `whois.cymru.com:43`：批量识别路由 ASN，失败时自动降级；
- `https://api.ipapi.is`：检测 IP 地理、ASN、类型和风险；
- Netflix、YouTube、Prime Video、TikTok、Reddit 和 ChatGPT 的公开入口：
  检测本机原生访问与地区，不发送 NodeBench 报告；
- `https://report.nodebench.workers.dev`：仅测评结束时上传。

## 手动下载

在 [Releases](https://github.com/floriary0/NodeBench/releases/latest) 下载：

- `nodebench-linux-amd64.tar.gz`
- `nodebench-linux-arm64.tar.gz`
- `SHA256SUMS`

## 从源码构建

需要 Go 1.24 或更新版本：

```bash
go test ./...
go build ./cmd/nodebench
```

交叉构建 Linux AMD64：

```bash
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
  go build -trimpath -ldflags="-s -w" -o nodebench ./cmd/nodebench
```

## 隐私原则

- 完整 IP、主机名、MAC、Machine ID、磁盘序列号和真实临时路径不落盘、
  不上传；
- 路由 hop 只保存 `a.b.*.*` 形式；
- 报告默认公开，统一链接只展示已经脱敏的数据；
- 测评期间不连接 NodeBench Worker，完成后只上传最终 JSON；
- 不调用 NodeQuality/TcpQuality 原有排行榜或报告上传接口。

## 当前待完成

- IPv6、多风险源、DNSBL、Disney+、Claude 和 Gemini；
- 非人民币套餐的性价比评分；
- 独立持续状态观察器；
- 更完整的自动依赖适配与发行版兼容测试。
