# CF Panel

部署在 Cloudflare Workers 上的多协议代理订阅管理面板（单文件）。

- **协议**：VLESS / Trojan（WebSocket + TLS）
- **订阅**：`/UUID/sub` —— base64 节点订阅（v2rayN / NekoBox / 小火箭通用）
  - `?format=clash` —— Clash YAML 订阅
  - `?format=singbox` —— sing-box JSON 订阅
  - `?format=text` —— 明文节点链接
- **面板**：`/UUID` —— 图形化配置：优选 IP 管理、订阅一键复制
- **伪装**：未知路径返回普通 nginx 欢迎页，降低指纹特征

## 部署方式一：Dashboard 粘贴（推荐新手）

1. 登录 [Cloudflare Dashboard](https://dash.cloudflare.com/) → **Workers & Pages** → **创建** → **创建 Worker** → **部署**
2. 点 **编辑代码**，删掉编辑器里的默认代码，把 `worker.js` 的全部内容粘贴进去 → **保存并部署**
3. 在 Worker 的 **设置 → 变量** 里添加环境变量：
   - `UUID` = 你的 UUID（[点这里生成](https://1024tools.com/uuid)），**必填**
   - `PREFERRED`（可选）：优选 IP/域名，逗号分隔，格式 `host:port#备注`
     例：`icook.hk:443#香港优选,cloudflare.182682.xyz:443#优选域名`
   - `PROXYIP`（可选）：反代 IP/域名
4. （可选）绑定 KV 实现面板在线改配置：
   **Workers & Pages → KV** 创建命名空间 → 回到 Worker **设置 → 绑定** 添加 KV 命名空间，变量名填 `PANEL_KV`
5. 重新部署。访问 `https://你的worker.workers.dev/UUID` 打开面板

## 部署方式二：wrangler

```bash
npm i -g wrangler
wrangler login
# 修改 wrangler.toml 里的 UUID（和 KV id，如需）
wrangler deploy
```

## 客户端配置

1. 打开面板 `https://你的worker.workers.dev/UUID`，复制订阅地址
2. 在客户端（v2rayN / NekoBox / Shadowrocket / Clash Verge 等）中添加订阅
3. 更新订阅即可看到节点：每个优选 IP 生成一条 VLESS + 一条 Trojan

> 也可以手动添加单个节点：地址 = 任一优选 IP，端口 443，UUID = 你的 UUID，
> 传输 ws + TLS，SNI/Host = 你的 worker 域名，路径 = `/你的UUID`，Trojan 密码即 UUID。

## 安全建议

- 这类项目会被 Cloudflare 滥用检测盯上，**请用新号/小号部署**，不要拿主力号冒险
- 面板路径本身就是 UUID，不要把面板地址公开分享
- 订阅链接包含 UUID，同样不要公开

## 文件说明

| 文件 | 说明 |
|---|---|
| `worker.js` | 全部功能，单文件 |
| `wrangler.toml` | wrangler 部署配置 |
| `README.md` | 本说明 |

## v1 未包含（后续可加）

XHTTP 协议、Telegram 用量通知、节点测活/自动优选、家宽模式
