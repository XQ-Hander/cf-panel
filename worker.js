/**
 * CF Panel v1.0 —— Cloudflare Workers 多协议代理订阅面板（单文件）
 *
 * 功能：
 *  - VLESS / Trojan 双协议代理（WebSocket + TLS）
 *  - /sub 订阅输出：base64 节点链接、Clash YAML、sing-box JSON
 *  - /UUID 图形化面板：优选 IP 管理、订阅一键复制（需绑定 KV 做持久化）
 *  - 未知路径返回伪装页，降低指纹特征
 *
 * 部署（二选一）：
 *  1) Cloudflare Dashboard → Workers & Pages → 创建 Worker → 编辑代码 → 粘贴本文件 → 保存部署
 *  2) wrangler deploy（配合 wrangler.toml）
 *
 * 环境变量：
 *  UUID       必填，你的 UUID（面板路径与订阅鉴权都用它）
 *  PROXYIP    可选，反代 IP/域名，如 proxyip.example.com（直连失败时的备用出站）
 *  PREFERRED  可选，优选 IP/域名，逗号或换行分隔，格式 host:port#备注
 *             例：icook.hk:443#香港优选,1.1.1.1:443#备用
 * KV（可选）：
 *  PANEL_KV   绑定后面板可在线修改优选列表，改完即生效；不绑则只读环境变量
 */
import { connect } from 'cloudflare:sockets';

const enc = new TextEncoder();
const dec = new TextDecoder();

/* ================= 工具函数 ================= */

function normUuid(u) {
  return (u || '').trim().toLowerCase().replace(/-/g, '');
}

function bytesToUuid(b) {
  const h = [...b].map(x => x.toString(16).padStart(2, '0')).join('');
  return `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20)}`;
}

function concatBuf(a, b) {
  const n = new Uint8Array(a.length + b.length);
  n.set(a, 0); n.set(b, a.length);
  return n;
}

function b64ToBytes(s) {
  s = s.replace(/-/g, '+').replace(/_/g, '/');
  while (s.length % 4) s += '=';
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

/* SHA-224 纯 JS 实现（FIPS 180-4），用于 Trojan 密码校验 */
const SHA224_K = [
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];
function sha224hex(str) {
  let h0 = 0xc1059ed8, h1 = 0x367cd507, h2 = 0x3070dd17, h3 = 0xf70e5939,
      h4 = 0xffc00b31, h5 = 0x68581511, h6 = 0x64f98fa7, h7 = 0xbefa4fa4;
  const bytes = enc.encode(str);
  const bitLen = bytes.length * 8;
  const withOne = bytes.length + 1;
  const padLen = (withOne % 64 <= 56) ? (56 - withOne % 64) : (120 - withOne % 64);
  const total = withOne + padLen + 8;
  const msg = new Uint8Array(total);
  msg.set(bytes); msg[bytes.length] = 0x80;
  const dv = new DataView(msg.buffer);
  dv.setUint32(total - 8, Math.floor(bitLen / 0x100000000));
  dv.setUint32(total - 4, bitLen >>> 0);
  const w = new Uint32Array(64);
  const rotr = (x, n) => (x >>> n) | (x << (32 - n));
  for (let off = 0; off < total; off += 64) {
    for (let i = 0; i < 16; i++) w[i] = dv.getUint32(off + i * 4);
    for (let i = 16; i < 64; i++) {
      const s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >>> 3);
      const s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >>> 10);
      w[i] = (w[i - 16] + s0 + w[i - 7] + s1) >>> 0;
    }
    let a = h0, b = h1, c = h2, d = h3, e = h4, f = h5, g = h6, h = h7;
    for (let i = 0; i < 64; i++) {
      const S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
      const ch = (e & f) ^ (~e & g);
      const t1 = (h + S1 + ch + SHA224_K[i] + w[i]) >>> 0;
      const S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
      const maj = (a & b) ^ (a & c) ^ (b & c);
      const t2 = (S0 + maj) >>> 0;
      h = g; g = f; f = e; e = (d + t1) >>> 0; d = c; c = b; b = a; a = (t1 + t2) >>> 0;
    }
    h0 = (h0 + a) >>> 0; h1 = (h1 + b) >>> 0; h2 = (h2 + c) >>> 0; h3 = (h3 + d) >>> 0;
    h4 = (h4 + e) >>> 0; h5 = (h5 + f) >>> 0; h6 = (h6 + g) >>> 0; h7 = (h7 + h) >>> 0;
  }
  return [h0, h1, h2, h3, h4, h5, h6].map(x => x.toString(16).padStart(8, '0')).join('');
}

let _trojanCache = { uuid: '', hex: '' };
function trojanHex(uuid) {
  if (_trojanCache.uuid !== uuid) {
    _trojanCache = { uuid, hex: sha224hex(uuid.trim()) };
  }
  return _trojanCache.hex;
}

/* 内网地址保护：禁止代理到私有/回环地址 */
function isPrivateHost(host) {
  const h = host.replace(/^\[|\]$/g, '');
  if (h === '::1' || h.toLowerCase() === 'localhost') return true;
  const v4 = h.match(/^(\d+)\.(\d+)\.(\d+)\.(\d+)$/);
  if (!v4) return false;
  const [a, b] = [+v4[1], +v4[2]];
  return a === 10 || a === 127 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) || (a === 169 && b === 254);
}

/* ================= 配置 ================= */

const DEFAULT_PREFERRED = [
  { host: 'icook.hk', port: 443, name: '香港优选' },
  { host: 'cloudflare.182682.xyz', port: 443, name: '优选域名' },
  { host: 'bestcf.top', port: 443, name: '优选备用' },
];

function parsePreferred(s) {
  const out = [];
  for (let line of String(s || '').split(/[\n,;]/)) {
    line = line.trim();
    if (!line || line.startsWith('#')) continue;
    let name = '';
    const hi = line.lastIndexOf('#');
    if (hi > 0) { name = line.slice(hi + 1).trim(); line = line.slice(0, hi).trim(); }
    let host = line, port = 443;
    const ci = line.lastIndexOf(':');
    if (ci > 0 && /^\d{1,5}$/.test(line.slice(ci + 1))) {
      port = parseInt(line.slice(ci + 1), 10);
      host = line.slice(0, ci).trim();
    }
    host = host.replace(/^\[|\]$/g, '');
    if (!host) continue;
    out.push({ host, port, name: name || `${host}:${port}` });
  }
  return out;
}

async function getConfig(env) {
  const UUID = (env.UUID || '').trim();
  let preferred = [];
  let fromKV = false;
  try {
    if (env.PANEL_KV) {
      const saved = await env.PANEL_KV.get('cfpanel_config', 'json');
      if (saved && Array.isArray(saved.preferred) && saved.preferred.length) {
        preferred = saved.preferred;
        fromKV = true;
      }
    }
  } catch (e) { /* KV 读取失败则回退 */ }
  if (!preferred.length && env.PREFERRED) preferred = parsePreferred(env.PREFERRED);
  if (!preferred.length) preferred = DEFAULT_PREFERRED;
  return {
    UUID,
    preferred: preferred.slice(0, 200),
    fromKV,
    hasKV: !!env.PANEL_KV,
    proxyIp: (env.PROXYIP || '').trim(),
  };
}

/* ================= 订阅生成 ================= */

function buildNodeLinks(url, cfg) {
  const host = url.hostname; // worker 域名（workers.dev 或自定义域名）
  const uuid = cfg.UUID;
  const wsPath = encodeURIComponent(`/${uuid}`);
  const vless = [], trojan = [], clash = [], singbox = [];
  cfg.preferred.forEach((n, i) => {
    const tag = encodeURIComponent(`${i + 1}-${n.name}`);
    const server = n.host.includes(':') && !n.host.startsWith('[') ? `[${n.host}]` : n.host;
    vless.push(
      `vless://${uuid}@${server}:${n.port}?encryption=none&security=tls&sni=${host}&fp=random&type=ws&host=${host}&path=${wsPath}#${tag}`
    );
    trojan.push(
      `trojan://${uuid}@${server}:${n.port}?security=tls&sni=${host}&fp=random&type=ws&host=${host}&path=${wsPath}#${tag}-t`
    );
    clash.push({
      name: `${i + 1}-${n.name}`,
      type: 'vless', server: n.host, port: n.port, uuid,
      udp: false, tls: true, servername: host, 'client-fingerprint': 'random',
      network: 'ws', 'ws-opts': { path: `/${uuid}`, headers: { Host: host } },
    });
    singbox.push({
      tag: `${i + 1}-${n.name}`, type: 'vless', server: n.host, server_port: n.port,
      uuid, tls: { enabled: true, server_name: host },
      transport: { type: 'ws', path: `/${uuid}`, headers: { Host: host } },
    });
  });
  return { vless, trojan, clash, singbox };
}

function buildClashYaml(url, cfg, links) {
  const names = links.clash.map(c => `"${c.name.replace(/"/g, '')}"`);
  let y = 'proxies:\n';
  for (const c of links.clash) {
    y += `  - name: "${c.name.replace(/"/g, '')}"\n`;
    y += `    type: vless\n    server: ${c.server}\n    port: ${c.port}\n    uuid: ${c.uuid}\n`;
    y += `    udp: false\n    tls: true\n    servername: ${c.servername}\n    client-fingerprint: random\n`;
    y += `    network: ws\n    ws-opts:\n      path: "${c['ws-opts'].path}"\n      headers:\n        Host: ${c['ws-opts'].headers.Host}\n`;
  }
  y += 'proxy-groups:\n';
  y += `  - name: "自动选择"\n    type: url-test\n    proxies: [${names.join(', ')}]\n`;
  y += `    url: "http://www.gstatic.com/generate_204"\n    interval: 300\n`;
  y += `  - name: "手动选择"\n    type: select\n    proxies: ["自动选择", ${names.join(', ')}]\n`;
  y += 'rules:\n  - MATCH,手动选择\n';
  return y;
}

function subscriptionResponse(url, cfg) {
  const format = (url.searchParams.get('format') || 'base64').toLowerCase();
  const links = buildNodeLinks(url, cfg);
  if (format === 'clash' || format === 'yaml') {
    return new Response(buildClashYaml(url, cfg, links), {
      headers: { 'Content-Type': 'text/yaml; charset=utf-8', 'Content-Disposition': 'attachment; filename="clash.yaml"' },
    });
  }
  if (format === 'singbox' || format === 'sb') {
    const conf = {
      outbounds: [
        ...links.singbox,
        { tag: '自动选择', type: 'urltest', outbounds: links.singbox.map(s => s.tag), url: 'http://www.gstatic.com/generate_204', interval: '5m' },
        { tag: 'DIRECT', type: 'direct' },
      ],
      route: { rules: [], final: '自动选择' },
    };
    return new Response(JSON.stringify(conf, null, 2), {
      headers: { 'Content-Type': 'application/json; charset=utf-8', 'Content-Disposition': 'attachment; filename="singbox.json"' },
    });
  }
  if (format === 'text' || format === 'plain') {
    return new Response([...links.vless, ...links.trojan].join('\n'), {
      headers: { 'Content-Type': 'text/plain; charset=utf-8' },
    });
  }
  // 默认：base64（v2rayN / NekoBox / 小火箭通用）
  const all = [...links.vless, ...links.trojan].join('\n');
  const b64 = btoa(String.fromCharCode(...enc.encode(all)));
  return new Response(b64, { headers: { 'Content-Type': 'text/plain; charset=utf-8' } });
}

/* ================= 协议握手解析 ================= */

function tryParseHandshake(head, uuid) {
  const nuuid = normUuid(uuid);
  // —— VLESS：version(1) + uuid(16) + addonLen(1) + addon + cmd(1) + port(2) + atyp(1) + addr
  if (head.length >= 18) {
    const got = normUuid(bytesToUuid(head.slice(1, 17)));
    if (got === nuuid) {
      const m = head[17];
      if (head.length < 24 + m) return { needMore: true };
      const cmd = head[18 + m];
      if (cmd === 2) return { error: 'udp 不支持' };
      if (cmd !== 1) return { error: '未知指令' };
      const port = (head[19 + m] << 8) | head[20 + m];
      const atyp = head[21 + m];
      let host, hlen;
      if (atyp === 1) {
        if (head.length < 26 + m) return { needMore: true };
        host = `${head[22 + m]}.${head[23 + m]}.${head[24 + m]}.${head[25 + m]}`;
        hlen = 26 + m;
      } else if (atyp === 2) {
        const l = head[22 + m];
        if (head.length < 23 + m + l) return { needMore: true };
        host = dec.decode(head.slice(23 + m, 23 + m + l));
        hlen = 23 + m + l;
      } else if (atyp === 3) {
        if (head.length < 38 + m) return { needMore: true };
        const p = [];
        for (let i = 0; i < 8; i++) p.push(((head[22 + m + i * 2] << 8) | head[23 + m + i * 2]).toString(16));
        host = p.join(':');
        hlen = 38 + m;
      } else return { error: '地址类型错误' };
      return { type: 'vless', version: head[0], target: { host, port }, headerLen: hlen };
    }
  }
  // —— Trojan：56 hex(SHA224) + \r\n + socks5地址 + \r\n
  if (head.length >= 58) {
    const hex = dec.decode(head.slice(0, 56));
    if (/^[0-9a-fA-F]{56}$/.test(hex) && head[56] === 13 && head[57] === 10) {
      if (hex.toLowerCase() !== trojanHex(uuid)) return { error: 'Trojan 鉴权失败' };
      const atyp = head[58];
      let host, port, hlen;
      if (atyp === 1) {
        if (head.length < 65) return { needMore: true };
        host = `${head[59]}.${head[60]}.${head[61]}.${head[62]}`;
        port = (head[63] << 8) | head[64];
        hlen = 65;
      } else if (atyp === 3) {
        const l = head[59];
        if (head.length < 62 + l) return { needMore: true };
        host = dec.decode(head.slice(60, 60 + l));
        port = (head[60 + l] << 8) | head[61 + l];
        hlen = 62 + l;
      } else if (atyp === 4) {
        if (head.length < 77) return { needMore: true };
        const p = [];
        for (let i = 0; i < 8; i++) p.push(((head[59 + i * 2] << 8) | head[60 + i * 2]).toString(16));
        host = p.join(':');
        port = (head[75] << 8) | head[76];
        hlen = 77;
      } else return { error: '地址类型错误' };
      if (head[hlen] !== 13 || head[hlen + 1] !== 10) return { error: 'Trojan 头格式错误' };
      return { type: 'trojan', target: { host, port }, headerLen: hlen + 2 };
    }
  }
  if (head.length > 512) return { error: '未知协议' };
  return { needMore: true };
}

/* ================= 代理转发 ================= */

async function handleProxy(request, env, cfg) {
  const pair = new WebSocketPair();
  const [client, server] = Object.values(pair);
  server.accept();
  handleProxySession(server, request, env, cfg).catch(() => {
    try { server.close(); } catch (e) { /* ignore */ }
  });
  return new Response(null, { status: 101, webSocket: client });
}

async function handleProxySession(ws, request, env, cfg) {
  let remote = null;
  const closeAll = () => {
    try { if (ws.readyState === 1) ws.close(); } catch (e) { /* ignore */ }
    try { remote && remote.close(); } catch (e) { /* ignore */ }
  };

  // 入站流：early-data（如有）+ WebSocket 消息
  let early = null;
  const edh = request.headers.get('sec-websocket-protocol');
  if (edh && edh.length < 4096) {
    try { early = b64ToBytes(edh); } catch (e) { /* ignore */ }
  }
  const inbound = new ReadableStream({
    start(c) {
      if (early && early.length) c.enqueue(early.buffer);
      ws.addEventListener('message', ev => { try { c.enqueue(ev.data); } catch (e) { /* ignore */ } });
      ws.addEventListener('close', () => { try { c.close(); } catch (e) { /* ignore */ } closeAll(); });
      ws.addEventListener('error', () => { try { c.error(new Error('ws')); } catch (e) { /* ignore */ } });
    },
  });
  const reader = inbound.getReader();

  // 握手：累积数据直到能解析出协议头
  let head = new Uint8Array(0);
  let hs = null;
  while (!hs) {
    const { done, value } = await reader.read();
    if (done) return closeAll();
    head = concatBuf(head, new Uint8Array(value));
    if (head.length > 8192) return closeAll();
    hs = tryParseHandshake(head, cfg.UUID);
    if (hs && hs.error) return closeAll();
  }

  const { host, port } = hs.target;
  if (!host || !port || isPrivateHost(host)) return closeAll();

  // 连接目标（直连；失败且配置了 PROXYIP 则走反代）
  try {
    remote = connect({ hostname: host, port });
  } catch (e) {
    return closeAll();
  }

  // VLESS：先回 2 字节响应头 [version, 0x00]
  if (hs.type === 'vless') {
    try { ws.send(new Uint8Array([hs.version, 0])); } catch (e) { return closeAll(); }
  }

  const writer = remote.writable.getWriter();
  const wsSend = (d) => {
    try { if (ws.readyState === 1) ws.send(d); } catch (e) { /* ignore */ }
  };

  // 握手后剩余的应用层数据先发给远端
  const rest = head.slice(hs.headerLen);
  try {
    if (rest.length) await writer.write(rest);
  } catch (e) { return closeAll(); }

  // ws → 远端
  (async () => {
    try {
      for (;;) {
        const { done, value } = await reader.read();
        if (done) break;
        await writer.write(value);
      }
    } catch (e) { /* ignore */ }
    try { await writer.close(); } catch (e) { /* ignore */ }
  })();

  // 远端 → ws
  try {
    await remote.readable.pipeTo(new WritableStream({
      write(chunk) { wsSend(chunk); },
      close() { closeAll(); },
      abort() { closeAll(); },
    }));
  } catch (e) { /* ignore */ }
  closeAll();
}

/* ================= 伪装页 ================= */

function fakeSite() {
  return new Response(
    `<!DOCTYPE html><html><head><title>Welcome to nginx!</title></head>` +
    `<body><center><h1>Welcome to nginx!</h1></center>` +
    `<hr><center>nginx/1.24.0</center></body></html>`,
    { status: 404, headers: { 'Content-Type': 'text/html; charset=utf-8', 'Server': 'nginx/1.24.0' } }
  );
}

/* ================= Web 面板 ================= */

function panelPage(url, cfg) {
  const base = `${url.origin}/${cfg.UUID}`;
  const subBase64 = `${base}/sub`;
  const subClash = `${base}/sub?format=clash`;
  const subSingbox = `${base}/sub?format=singbox`;
  const nodeLines = cfg.preferred.map(n => `${n.host}:${n.port}#${n.name}`).join('\n');
  const kvHint = cfg.hasKV
    ? (cfg.fromKV ? '当前优选来自 KV（面板修改已生效）' : 'KV 已绑定，保存后写入 KV')
    : '未绑定 KV：面板为只读，请改环境变量 PREFERRED';
  const html = `<!DOCTYPE html>
<html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>CF Panel</title>
<style>
*{box-sizing:border-box}body{margin:0;background:#0f1420;color:#e8edf5;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,"PingFang SC","Microsoft YaHei",sans-serif}
.wrap{max-width:720px;margin:0 auto;padding:24px 16px 64px}
h1{font-size:22px;margin:8px 0 4px}.sub{color:#8b94a7;font-size:13px;margin-bottom:20px}
.card{background:#171e2e;border:1px solid #263049;border-radius:12px;padding:16px;margin-bottom:16px}
.card h2{font-size:15px;margin:0 0 12px;color:#aeb9d0}
.row{display:flex;gap:8px;margin-bottom:10px;align-items:center}
.row label{width:110px;flex:none;color:#8b94a7;font-size:13px}
.row code{flex:1;background:#0c1120;border:1px solid #263049;border-radius:8px;padding:8px 10px;font-size:12px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
button{background:#3b82f6;border:0;color:#fff;border-radius:8px;padding:8px 14px;font-size:13px;cursor:pointer}
button:hover{background:#2563eb}button.ghost{background:#232c44}
textarea{width:100%;min-height:140px;background:#0c1120;color:#e8edf5;border:1px solid #263049;border-radius:8px;padding:10px;font-size:13px;font-family:monospace}
.hint{font-size:12px;color:#8b94a7;margin-top:8px}
.ok{color:#4ade80;font-size:13px;margin-top:8px;display:none}
.stat{display:flex;gap:16px;font-size:13px;color:#8b94a7}
.stat b{color:#e8edf5}
</style></head><body><div class="wrap">
<h1>CF Panel</h1><div class="sub">Cloudflare Workers 代理订阅管理面板 v1.0</div>
<div class="card"><h2>运行状态</h2><div class="stat">
<span>优选节点 <b>${cfg.preferred.length}</b> 个</span>
<span>出站 <b>${cfg.proxyIp ? 'PROXYIP 已配置' : '直连'}</b></span>
<span>KV <b>${cfg.hasKV ? '已绑定' : '未绑定'}</b></span>
</div></div>
<div class="card"><h2>订阅地址</h2>
<div class="row"><label>通用订阅</label><code>${subBase64}</code><button onclick="copy('${subBase64}')">复制</button></div>
<div class="row"><label>Clash 订阅</label><code>${subClash}</code><button onclick="copy('${subClash}')">复制</button></div>
<div class="row"><label>sing-box 订阅</label><code>${subSingbox}</code><button onclick="copy('${subSingbox}')">复制</button></div>
<div class="hint">通用订阅为 base64 编码，可导入 v2rayN / NekoBox / 小火箭等客户端</div>
</div>
<div class="card"><h2>优选 IP / 域名</h2>
<textarea id="pref" ${cfg.hasKV ? '' : 'disabled'}>${nodeLines.replace(/</g, '&lt;')}</textarea>
<div class="hint">${kvHint}　每行格式：host:port#备注</div>
${cfg.hasKV ? '<div style="margin-top:10px"><button onclick="save()">保存</button></div><div class="ok" id="okmsg">已保存，立即生效</div>' : ''}
</div>
<div class="card"><h2>使用说明</h2>
<div class="hint">1. 客户端添加订阅，把上面的订阅地址填进去<br>2. 协议：VLESS / Trojan，传输：WS + TLS，路径：/${cfg.UUID}<br>3. Trojan 密码即 UUID</div>
</div></div>
<script>
function copy(t){navigator.clipboard.writeText(t).then(()=>alert('已复制'));}
async function save(){
  const v=document.getElementById('pref').value;
  const r=await fetch('${base}/api/config',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({preferred:v})});
  const j=await r.json();
  if(j.ok){document.getElementById('okmsg').style.display='block';setTimeout(()=>document.getElementById('okmsg').style.display='none',2000);}
  else alert('保存失败：'+(j.error||'未知错误'));
}
</script></body></html>`;
  return new Response(html, { headers: { 'Content-Type': 'text/html; charset=utf-8' } });
}

async function apiConfig(request, env, cfg) {
  const u = normUuid(cfg.UUID);
  if (request.method === 'GET') {
    return Response.json({
      ok: true,
      hasKV: cfg.hasKV,
      fromKV: cfg.fromKV,
      preferred: cfg.preferred.map(n => `${n.host}:${n.port}#${n.name}`).join('\n'),
    });
  }
  if (request.method === 'POST') {
    if (!env.PANEL_KV) return Response.json({ ok: false, error: '未绑定 KV（PANEL_KV）' }, { status: 400 });
    let body;
    try { body = await request.json(); } catch (e) { return Response.json({ ok: false, error: '请求格式错误' }, { status: 400 }); }
    const preferred = parsePreferred(body.preferred || '').slice(0, 200);
    if (!preferred.length) return Response.json({ ok: false, error: '优选列表为空' }, { status: 400 });
    await env.PANEL_KV.put('cfpanel_config', JSON.stringify({ preferred, updatedAt: Date.now() }));
    return Response.json({ ok: true, count: preferred.length });
  }
  return new Response('Method Not Allowed', { status: 405 });
}

/* ================= 路由 ================= */

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const uuid = (env.UUID || '').trim();
    if (!uuid) {
      return new Response('请先在环境变量中设置 UUID 后再部署', { status: 500 });
    }
    const nuuid = normUuid(uuid);
    const p = url.pathname;

    // WebSocket 代理：路径 /UUID（鉴权在协议头里做）
    if (request.headers.get('Upgrade') === 'websocket') {
      if (p === `/${uuid}` || p === `/${nuuid}`) {
        const cfg = await getConfig(env);
        return handleProxy(request, env, cfg);
      }
      return new Response('Not Found', { status: 404 });
    }

    const isUuidPath = p === `/${uuid}` || p === `/${nuuid}`;
    const isSubPath = p === `/${uuid}/sub` || p === `/${nuuid}/sub`;
    const isApiPath = p === `/${uuid}/api/config` || p === `/${nuuid}/api/config`;

    if (isUuidPath) {
      const cfg = await getConfig(env);
      return panelPage(url, cfg);
    }
    if (isSubPath) {
      const cfg = await getConfig(env);
      return subscriptionResponse(url, cfg);
    }
    if (isApiPath) {
      const cfg = await getConfig(env);
      return apiConfig(request, env, cfg);
    }
    return fakeSite();
  },
};
