# Mail2Webhook

[中文](#中文) | [English](#english) 

---

<h2 id="中文">Mail2Webhook (中文)</h2>

一个使用 Go 编写的轻量级、高并发邮件转发工具。支持通过 IMAP 协议拉取邮件，并根据自定义路由规则（来源账号、关键词过滤）转发至飞书 (Feishu)、钉钉 (DingTalk)、企业微信 (WeCom)、Slack、Discord 或自定义 Webhook 平台。随附一个内置的 Web 控制台管理面板。

### **注意：该项目没有编写鉴权功能，没有做包括sql注入等的安全防护，不要开放到公网！！！**

### 核心特性

- **高并发与稳定性**: 每个邮箱账号由独立的 goroutine 轮询。借助 SQLite WAL 模式保证并发环境下的数据读写安全。
- **验证码智能提取**: 自动通过正则表达式嗅探邮件标题与正文中的验证码/动态指令，并将其置顶在推送消息头部。
- **规则路由**: 支持基于发送凭测（按不同账号）和正文/标题关键词的规则过滤。
- **Web 控制台**: 提供内置的可视化面板，供动态管理账号、Webhook 通道和路由规则，无需手动修改配置文件。
- **隐私与安全**: 邮件内容推送完毕后即从本地数据库清除。API 接口对前端请求自动打码脱敏凭证和 Webhook 密钥。支持系统的平滑退出 (Graceful Shutdown)。
- **长文本处理**: 自动清理 HTML 冗余标签，保留 Markdown 核心语法，并在目标平台字数受限时自动执行分块 (Chunk) 发送。

### 快速开始 (Docker)

你可以直接使用预构建的 Docker 镜像一键启动服务。

1. 创建空的 `config.json` 配置文件：
   ```bash
   touch config.json
   ```

2. 运行容器:
   ```bash
   docker run -d \
     --name mail2webhook \
     -p 8080:8080 \
     -v $(pwd)/config.json:/app/config.json \
     -v $(pwd)/messages.db:/app/messages.db \
     -e TZ=Asia/Shanghai \
     --restart unless-stopped \
     trah01/mail2webhook:latest
   ```
   或者使用docker-compose.yaml文件
   ```
   docker compose up -d
   ```

3. 访问控制台: 打开浏览器访问 `http://localhost:8080` 进行可视化配置。

### 支持的 Webhook 通道
- `feishu` (内置交互式富文本卡片)
- `dingtalk` (钉钉 Markdown 消息)
- `wecom` (企业微信 Markdown 消息)
- `slack` (Block Kit 排版)
- `discord` (Embed 排版)
- `custom` (原始 JSON Payload)

### 开发构建

构建需要 Go 1.21+ 环境。

```bash
go mod download
go run main.go
```

---

<h2 id="english">Mail2Webhook (English)</h2>

A lightweight, concurrent email forwarding bot written in Go. Forwards IMAP emails to Feishu, DingTalk, WeCom, Slack, Discord, or custom Webhooks with rule-based routing and a built-in web dashboard.

### **Warning: This project lacks proper authentication and security measures (like protection against SQL injection). DO NOT expose it directly to the public internet!!!**

### Features

- **Concurrency & Stability**: Independent IMAP polling goroutines per account. Safe concurrent data access using SQLite WAL mode.
- **Smart Extraction**: Automatically matches verification codes via regex from email subjects/bodies, hoisting them to the top of the forwarded message for quick access.
- **Rule-based Routing**: Flexible routing of emails based on source accounts and subject keyword filters.
- **Web Dashboard**: Built-in HTTP interface for managing accounts, webhooks, and routing rules dynamically without touching JSON files.
- **Privacy & Security**: Auto-cleans email bodies from the local database post-delivery. API endpoints automatically mask sensitive credentials and webhook secrets. Graceful shutdown handler.
- **Content Formatting**: Cleans HTML payload, preserves basic markdown, and automatically chunks large payloads to bypass target platform limits.

### Quick Start (Docker)

You can run the service directly using the pre-built Docker image.

1. Create an empty `config.json` file:
   ```bash
   touch config.json
   ```

2. Run the container:
   ```bash
   docker run -d \
     --name mail2webhook \
     -p 8080:8080 \
     -v $(pwd)/config.json:/app/config.json \
     -v $(pwd)/messages.db:/app/messages.db \
     -e TZ=Asia/Shanghai \
     --restart unless-stopped \
     trah01/mail2webhook:latest
   ```
   Or use the `docker-compose.yaml` file:
   ```bash
   docker compose up -d
   ```

3. Access the dashboard at `http://localhost:8080` to configure via the web UI.

### Supported Webhooks
- `feishu` (Interactive Cards)
- `dingtalk` (DingTalk Markdown)
- `wecom` (WeCom Markdown)
- `slack` (Block Kit)
- `discord` (Embeds)
- `custom` (Raw JSON payload)

### Development

Requires Go 1.21+.

```bash
go mod download
go run main.go
```
