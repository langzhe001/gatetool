#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Cloudflare 边缘优选池刷新 (手动录入版, 不再自动测速)。

节点来源 : 仓库根目录的 preferred_hosts.txt (手动上传/编辑维护),
          一行一个优选 IP 或域名, 这就是节点的最终名单和顺序。
流程   : 读取手动名单 -> 清洗/去重/校验 -> 写入 pool.json (监控页用)
          -> 生成 pool.txt (vless 明文订阅) / pool.yaml (Clash 订阅)

不再拉取 Cloudflare 官方 IP 段、不再随机采样、不再做 TLS 握手测速:
名单里有什么, 订阅里就有什么; 要换节点只改 preferred_hosts.txt 后重跑工作流。

只用标准库, 无第三方依赖。

preferred_hosts.txt 格式:
  # 以 # 开头的行是注释, 空行忽略
  1.2.3.4
  1.2.3.4:8443
  cf.example.com
  cf.example.com:443
  [2606:4700::1]:443
  也可以直接粘贴带 https:// 的域名, 会自动只取域名部分。

环境变量:
  EDT_DOMAIN       必填, 你自己的域名(已托管在 Cloudflare), 用作订阅的 SNI / Host
  EDT_UUID         选填, 你的 edgetunnel UUID; 设置后生成 pool.txt / pool.yaml
  MANUAL_HOSTS     选填, 直接用环境变量给名单 (逗号/空白分隔), 优先于文件
  MANUAL_HOSTS_FILE 选填, 名单文件路径, 默认脚本同目录的 preferred_hosts.txt
  OUT_DIR          选填, 输出目录, 默认脚本所在目录
  SUB_PATH         选填, 覆盖默认的 WS 路径格式 (默认: /随机伪装路径/proxyip=池子节点)
  SUB_FP           选填, TLS fingerprint, 默认 chrome
  SUB_PREFIX       选填, 订阅节点名前缀; 为空则按类型自动命名
                   (IPv4 -> IPv4优选, IPv6 -> IPv6优选, 域名 -> 域名优选)
"""

import ipaddress
import json
import os
import random
import re
import sys
from urllib.parse import quote
from datetime import datetime, timezone, timedelta

BEIJING = timezone(timedelta(hours=8))
DEFAULT_PORT = 443


def log(msg):
    print(msg, flush=True)


def die(msg):
    log(f"[失败] {msg}")
    sys.exit(1)


def parse_entry(raw):
    """把一行手动录入解析成 (host, port); 非法返回 None。

    支持: IPv4 / IPv4:端口 / 域名 / 域名:端口 / IPv6 / [IPv6]:端口 /
          带 https:// 前缀或尾随路径的域名 (只取域名部分)。
    """
    s = raw.strip()
    if not s or s.startswith("#"):
        return None
    s = s.split("#", 1)[0].strip()          # 行内注释
    s = s.split()[0] if s.split() else ""   # 只取第一个字段
    s = s.strip(",;")
    if not s:
        return None
    if "://" in s:                          # 粘贴了完整 URL 时只取主机部分
        s = s.split("://", 1)[1]
    s = s.split("/", 1)[0].strip()
    if not s:
        return None

    host, port = s, DEFAULT_PORT
    if s.startswith("["):                   # [IPv6] 或 [IPv6]:端口
        end = s.find("]")
        if end == -1:
            return None
        host = s[1:end]
        rest = s[end + 1:]
        if rest.startswith(":") and rest[1:].isdigit():
            port = int(rest[1:])
        elif rest:
            return None
    elif s.count(":") == 1:                 # IPv4:端口 或 域名:端口
        h, p = s.rsplit(":", 1)
        if p.isdigit():
            host, port = h, int(p)
    # s.count(":") >= 2 且无括号: 整段就是 IPv6 地址, 端口用默认

    if not (1 <= port <= 65535):
        return None
    try:
        ipaddress.ip_address(host)          # 合法 IP 直接通过
        return host, port
    except ValueError:
        pass
    # 域名校验: 标签由字母数字和连字符组成, 至少含一个点或为已知短域名形式
    if len(host) > 253 or not re.fullmatch(r"[A-Za-z0-9.-]+", host):
        return None
    labels = host.split(".")
    if any(not lb or lb.startswith("-") or lb.endswith("-") for lb in labels):
        return None
    return host, port


def load_manual_hosts():
    """按 MANUAL_HOSTS 环境变量 -> 名单文件的顺序读取手动名单。
    返回 (entries, source_desc); entries = [(host, port), ...], 已去重保序。"""
    raw_items = []
    env_hosts = os.environ.get("MANUAL_HOSTS", "").strip()
    if env_hosts:
        raw_items = re.split(r"[\s,;]+", env_hosts)
        source = "环境变量 MANUAL_HOSTS"
    else:
        path = os.environ.get("MANUAL_HOSTS_FILE", "").strip() or os.path.join(
            os.path.dirname(os.path.abspath(__file__)), "preferred_hosts.txt")
        source = f"文件 {path}"
        if not os.path.exists(path):
            die(f"手动优选名单不存在: {path} — 请在仓库根目录上传 preferred_hosts.txt "
                f"(一行一个优选 IP 或域名), 或设置环境变量 MANUAL_HOSTS")
        with open(path, encoding="utf-8") as f:
            raw_items = f.read().splitlines()

    entries, seen = [], set()
    for raw in raw_items:
        if not raw.strip() or raw.strip().startswith("#"):
            continue
        parsed = parse_entry(raw)
        if parsed is None:
            log(f"[警告] 跳过无法解析的录入: {raw.strip()!r}")
            continue
        key = (parsed[0].lower(), parsed[1])
        if key in seen:
            continue
        seen.add(key)
        entries.append(parsed)
    return entries, source


def host_label(host):
    try:
        return "IPv6优选" if ipaddress.ip_address(host).version == 6 else "IPv4优选"
    except ValueError:
        return "域名优选"


def host_for_url(host):
    return f"[{host}]" if ":" in host else host


# 随机伪装路径词表 (模仿真实网站路径, 后接 /proxyip=池子节点)
_CAMO_WORDS = ["act", "api", "app", "assets", "channel", "classify", "comic",
               "details", "doc", "docs", "download", "favorite", "forum",
               "jump", "knowledge", "list", "magnet", "out", "pdf", "project",
               "service", "static", "store", "video", "view", "search",
               "index", "home", "page", "item", "feed"]


def _random_camo_path():
    n = random.randint(1, 3)
    parts = random.sample(_CAMO_WORDS, n)
    parts = [p + ".html" if random.random() < 0.25 else p for p in parts]
    return "/" + "/".join(parts)


def main():
    sni = os.environ.get("EDT_DOMAIN", "").strip()
    if not sni:
        die("缺少环境变量 EDT_DOMAIN (你的 Cloudflare 域名, 用作订阅 SNI / Host)")
    out_dir = os.environ.get("OUT_DIR", os.path.dirname(os.path.abspath(__file__)))
    os.makedirs(out_dir, exist_ok=True)

    log("== 1/2 读取手动优选名单 (不测速) ==")
    picked, source = load_manual_hosts()
    log(f"来源: {source}; 有效节点 {len(picked)} 个")
    if not picked:
        die("手动优选名单为空 — 请往 preferred_hosts.txt 里一行一个填入优选 IP 或域名后重跑")
    for host, port in picked:
        log(f"  {host}:{port}")

    log("== 2/2 按名单顺序写入池子 ==")
    now = datetime.now(BEIJING).strftime("%Y-%m-%d %H:%M")
    # pool.json 只供监控页用, 不对外发布下载; ip 字段沿用旧名, 值可为 IP 或域名
    json_path = os.path.join(out_dir, "pool.json")
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(
            {
                "updated_at": now,
                "mode": "manual",
                "source": source if source.startswith("环境变量") else "preferred_hosts.txt",
                "sampled": len(picked),
                "reachable": len(picked),
                "entries": [
                    {"ip": host, "port": port, "latency_ms": None}
                    for host, port in picked
                ],
            },
            f, ensure_ascii=False, indent=2,
        )
    log(f"已写入 {json_path} (仅供监控页)")

    # 可选: 生成 vless 订阅 (名单里每个条目一条直连节点)
    #   pool.txt 明文链接 (连接格式), pool.yaml Clash 订阅 (proxies 列表)
    uuid = os.environ.get("EDT_UUID", "").strip()
    if uuid and uuid != "REPLACE_WITH_YOUR_EDT_UUID":
        sub_path_override = os.environ.get("SUB_PATH", "").strip()
        fp = os.environ.get("SUB_FP", "chrome")
        prefix = os.environ.get("SUB_PREFIX", "").strip()
        counters = {}
        proxy_hosts = ",".join(
            f"{host_for_url(h)}:{p}" for h, p in random.sample(picked, min(8, len(picked))))
        nodes = []  # (name, host, port, ws_path)
        link_lines = []
        for host, port in picked:
            label = prefix or host_label(host)
            counters[label] = counters.get(label, 0) + 1
            name = f"{label}-{counters[label]:02d}"
            ws_path = sub_path_override or f"{_random_camo_path()}/proxyip={proxy_hosts}"
            nodes.append((name, host, port, ws_path))
            link_lines.append(
                f"vless://{uuid}@{host_for_url(host)}:{port}?encryption=none&security=tls"
                f"&type=ws&host={sni}&fp={fp}&sni={sni}"
                f"&path={quote(ws_path, safe='')}#{quote(name, safe='')}"
            )
        sub_path = os.path.join(out_dir, "pool.txt")
        with open(sub_path, "w", encoding="utf-8") as f:
            f.write("# Cloudflare 边缘优选订阅 (vless:// 明文, 手动名单刷新)\n")
            f.write(f"# 更新时间: {now} (北京时间)\n")
            f.write(f"# 名单来自 preferred_hosts.txt, SNI={sni}, 共 {len(picked)} 个\n")
            f.write("\n".join(link_lines) + "\n")
        clash_path = os.path.join(out_dir, "pool.yaml")
        with open(clash_path, "w", encoding="utf-8") as f:
            f.write("# Cloudflare 边缘优选 Clash 订阅 (手动名单刷新)\n")
            f.write(f"# 更新时间: {now} (北京时间)\n")
            f.write("proxies:\n")
            for name, host, port, ws_path in nodes:
                f.write(f"  - name: \"{name}\"\n")
                f.write("    type: vless\n")
                f.write(f"    server: {host}\n")
                f.write(f"    port: {port}\n")
                f.write(f"    uuid: {uuid}\n")
                f.write("    tls: true\n")
                f.write(f"    servername: {sni}\n")
                f.write("    client-fingerprint: chrome\n")
                f.write("    network: ws\n")
                f.write("    ws-opts:\n")
                f.write(f"      path: \"{ws_path}\"\n")
                f.write("      headers:\n")
                f.write(f"        Host: {sni}\n")
                f.write("    udp: true\n")
                f.write("    ech-opts:\n")
                f.write("      enable: true\n")
                f.write("      query-server-name: cloudflare-ech.com\n")
        log(f"已写入 {sub_path} / {clash_path} ({len(picked)} 个节点)")
    else:
        log("未设置 EDT_UUID, 跳过 pool.txt/pool.yaml 生成")


if __name__ == "__main__":
    main()
