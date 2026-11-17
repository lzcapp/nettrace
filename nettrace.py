#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""nettrace - traceroute 解析与节点归属诊断工具（无第三方依赖）

用法示例:
  python nettrace.py parse trace_output.txt        解析已保存的 traceroute 输出
  python nettrace.py parse -                       从 stdin 读取
  python nettrace.py trace example.com -T -p 443    主动 traceroute（Mac/Linux TCP 模式）
  python nettrace.py trace 8.8.8.8                 主动 traceroute（默认）
  python nettrace.py trace --hops 20 target        指定最大跳数

说明:
  归属查询走 ipinfo.io 免费接口；结果缓存在 .nettrace_cache.json，重复分析不重复请求。
  离线规则识别私网 / DoD 名义保留段 / ULA / IPv4 映射地址，无需联网即可给出基础判断。
"""

import argparse
import ipaddress
import json
import math
import os
import platform
import re
import subprocess
import sys
import urllib.request
from concurrent.futures import ThreadPoolExecutor

try:
    sys.stdout.reconfigure(encoding="utf-8")
    sys.stderr.reconfigure("utf-8")
except Exception:
    pass

HERE = os.path.dirname(os.path.abspath(__file__))
CACHE_FILE = os.path.join(HERE, ".nettrace_cache.json")
OUT_DIR = os.path.join(HERE, "output")

# (网段, 标签, 是否需要在线查询, 补充说明)
SPECIAL = [
    ("10.0.0.0/8", "RFC1918 私网", False, "内网地址，运营商/企业 NAT 内部"),
    ("172.16.0.0/12", "RFC1918 私网", False, "内网地址"),
    ("192.168.0.0/16", "RFC1918 私网", False, "内网地址"),
    ("100.64.0.0/10", "CGNAT", False, "运营商级 NAT 共享地址段"),
    ("127.0.0.0/8", "回环", False, "本机"),
    ("169.254.0.0/16", "链路本地", False, "DHCP 失败时的自动地址"),
    ("192.0.2.0/24", "文档示例", False, "TEST-NET-1，不可路由"),
    ("198.51.100.0/24", "文档示例", False, "TEST-NET-2，不可路由"),
    ("203.0.113.0/24", "文档示例", False, "TEST-NET-3，不可路由"),
    ("198.18.0.0/15", "基准测试", False, "性能测试专用，不可路由"),
    ("224.0.0.0/4", "组播", False, "组播地址"),
    ("240.0.0.0/4", "保留", False, "保留地址"),
    ("8.0.0.0/8", "DoD 名义保留段", True, "纸面属美国国防部；国内云厂商作正常公网使用，勿据此判定非公网"),
    ("11.0.0.0/8", "DoD 名义保留段", True, "纸面属美国国防部；国内常作网关/公网使用，勿据此判定非公网"),
    ("fc00::/7", "ULA 私有 IPv6", False, "唯一本地地址，私有内网，公网不可查"),
    ("fe80::/10", "IPv6 链路本地", False, "本地链路"),
    ("::1/128", "IPv6 回环", False, "本机"),
    ("2001:db8::/32", "IPv6 文档示例", False, "不可路由"),
]
SPECIAL = [(ipaddress.ip_network(n), lab, online, note) for n, lab, online, note in SPECIAL]


def classify(ip_str):
    """返回 (标签, 是否在线查询, 说明)。"""
    try:
        addr = ipaddress.ip_address(ip_str)
    except ValueError:
        return ("非法地址", False, "")
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped:
        inner = str(addr.ipv4_mapped)
        lab, online, note = classify(inner)
        return ("IPv4 映射", online, "内层 " + inner + ("；" + lab + " " + note if lab else ""))
    for net, lab, online, note in SPECIAL:
        if addr.version == net.version and addr in net:
            return (lab, online, note)
    return ("公网地址", True, "")


def load_cache():
    if os.path.exists(CACHE_FILE):
        try:
            with open(CACHE_FILE, encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            pass
    return {}


def save_cache(cache):
    try:
        with open(CACHE_FILE, "w", encoding="utf-8") as f:
            json.dump(cache, f, ensure_ascii=False, indent=1)
    except Exception as e:
        print("缓存写入失败:", e, file=sys.stderr)


def query_ipinfo(ip):
    url = "https://ipinfo.io/" + ip + "/json"
    req = urllib.request.Request(url, headers={"User-Agent": "nettrace/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            d = json.loads(r.read().decode("utf-8"))
        return {
            "country": d.get("country", ""),
            "region": d.get("region", ""),
            "city": d.get("city", ""),
            "org": d.get("org", ""),
            "loc": d.get("loc", ""),
        }
    except Exception as e:
        return {"error": str(e)}


def enrich(ips, cache, workers=8):
    """并发查询需要在线分析的 IP，返回 ip -> info。"""
    need = []
    info = {}
    for ip in ips:
        lab, online, note = classify(ip)
        if not online:
            info[ip] = {"local_label": lab, "local_note": note}
        else:
            need.append(ip)
    need = [ip for ip in need if ip not in cache]
    if need:
        with ThreadPoolExecutor(max_workers=workers) as ex:
            futs = {ex.submit(query_ipinfo, ip): ip for ip in need}
            for fut in futs:
                pass
            for fut, ip in futs.items():
                cache[ip] = fut.result()
    for ip in ips:
        lab, online, note = classify(ip)
        d = dict(cache.get(ip, {}))
        d["local_label"] = lab
        d["local_note"] = note
        info[ip] = d
    return info


def parse_hops(text):
    """把 traceroute/tracert 文本解析为跳列表。"""
    hops = []
    for raw in text.splitlines():
        toks = raw.split()
        if not toks:
            continue
        head = raw.strip()
        if re.match(r"^(traceroute|tracert)\b", head, re.I) or "hops max" in head or "跟踪" in head:
            continue
        hop_no = int(toks[0]) if re.fullmatch(r"\d+", toks[0]) else None
        ips, lat = [], []
        for i, t in enumerate(toks):
            cand = t.strip("()[],;")
            try:
                ips.append(str(ipaddress.ip_address(cand)))
                continue
            except ValueError:
                pass
            m = re.fullmatch(r"<?(\d+(?:\.\d+)?)", t)
            if m and i + 1 < len(toks) and toks[i + 1].lower() in ("ms", "毫秒"):
                lat.append(float(m.group(1)))
        # 保留无响应跳（全 * * *），否则丢包率统计会失真
        if hop_no is not None or ips or lat:
            hops.append({"hop": hop_no, "ips": ips, "lat": lat})
    return hops


def run_trace(target, proto, port, max_hops):
    system = platform.system()
    if system == "Windows":
        cmd = ["tracert", "-d", "-h", str(max_hops), target]
    else:
        mode = {"T": "-T", "I": "-I", "U": "-U"}[proto]
        cmd = ["traceroute", mode, "-n", "-m", str(max_hops)]
        if proto == "T":
            cmd += ["-p", str(port)]
        cmd.append(target)
        if proto == "T" and hasattr(os, "geteuid") and os.geteuid() != 0:
            cmd.insert(0, "sudo")
    print("执行:", " ".join(cmd), file=sys.stderr)
    try:
        p = subprocess.run(cmd, capture_output=True, timeout=180)
    except FileNotFoundError:
        print("找不到 traceroute/tracert 命令", file=sys.stderr)
        return ""
    out = p.stdout
    try:
        return out.decode("utf-8")
    except UnicodeDecodeError:
        return out.decode("gbk", errors="replace")


def diagnose(hops, info, target):
    """生成智能诊断条目: (级别, 文本)。级别 info/warn/ok。"""
    notes = []
    ip_lat = {}
    for h in hops:
        for ip in h["ips"]:
            ip_lat.setdefault(ip, []).extend(h["lat"])

    for h in hops:
        if len(h["ips"]) > 1:
            notes.append(("info", "第 %s 跳出现 %d 个地址：ECMP / 负载分担，正常现象"
                          % (h["hop"] or "?", len(h["ips"]))))

    for ip, d in info.items():
        org = d.get("org", "") or ""
        country = d.get("country", "") or ""
        city = d.get("city", "") or ""
        lat = min(ip_lat.get(ip, [9999]))
        if ("DoD" in org or "Department of Defense" in org) and lat < 15:
            notes.append(("warn", "%s 被地理库标为 DoD（%s），但延迟仅 %sms；8/11 段在国内由云厂商作公网使用，属纸面注册信息，非真实归属"
                          % (ip, city or "US", fmt(lat))))
        if country and country != "CN" and lat < 8:
            notes.append(("warn", "%s 被标为 %s%s，但延迟仅 %sms，疑似境内节点被错误地理标注"
                          % (ip, city, country, fmt(lat))))
        if d.get("local_label") == "DoD 名义保留段":
            notes.append(("info", "%s 命中 DoD 名义保留段，实际多为国内云/运营商公网地址" % ip))

    uniq = [h for h in hops if not h["ips"]]
    if len(uniq) >= 3:
        notes.append(("info", "存在连续 %d 个不可见跳：中间设备不回 ICMP，不代表链路中断" % len(uniq)))

    if target and hops:
        last = hops[-1]
        if any(ip == target for ip in last["ips"]):
            notes.append(("ok", "已到达目标 %s（第 %s 跳，%s）"
                          % (target, last["hop"] or "?", fmt(min(last["lat"])) if last["lat"] else "?")))
    return notes


def wgs84_to_gcj02(lat, lng):
    """WGS-84 转 GCJ-02（腾讯地图所需坐标系）。境外坐标原样返回。"""
    def out_of_china(la, ln):
        return not (73.66 < ln < 135.05 and 3.86 < la < 53.55)

    if out_of_china(lat, lng):
        return lat, lng

    pi = math.pi
    a = 6378245.0
    ee = 0.00669342162296594323

    def transform_lat(x, y):
        ret = -100.0 + 2.0*x + 3.0*y + 0.2*y*y + 0.1*x*y + 0.2*math.sqrt(abs(x))
        ret += (20.0*math.sin(6.0*x*pi) + 20.0*math.sin(2.0*x*pi)) * 2.0/3.0
        ret += (20.0*math.sin(y*pi) + 40.0*math.sin(y/3.0*pi)) * 2.0/3.0
        ret += (160.0*math.sin(y/12.0*pi) + 320*math.sin(y*pi/30.0)) * 2.0/3.0
        return ret

    def transform_lng(x, y):
        ret = 300.0 + x + 2.0*y + 0.1*x*x + 0.1*x*y + 0.1*math.sqrt(abs(x))
        ret += (20.0*math.sin(6.0*x*pi) + 20.0*math.sin(2.0*x*pi)) * 2.0/3.0
        ret += (20.0*math.sin(x*pi) + 40.0*math.sin(x/3.0*pi)) * 2.0/3.0
        ret += (150.0*math.sin(x/12.0*pi) + 300.0*math.sin(x/30.0*pi)) * 2.0/3.0
        return ret

    dlat = transform_lat(lng - 105.0, lat - 35.0)
    dlng = transform_lng(lng - 105.0, lat - 35.0)
    radlat = lat / 180.0 * pi
    magic = math.sin(radlat)
    magic = 1 - ee * magic * magic
    sqrtmagic = math.sqrt(magic)
    dlat = (dlat * 180.0) / ((a * (1 - ee)) / (magic * sqrtmagic) * pi)
    dlng = (dlng * 180.0) / (a / sqrtmagic * math.cos(radlat) * pi)
    return lat + dlat, lng + dlng


def build_path(hops, info):
    """按跳序提取有坐标的节点，生成地图路径点。跳过私网/无坐标节点。"""
    pts = []
    seen = set()
    for h in hops:
        for ip in h["ips"]:
            d = info.get(ip, {})
            loc = d.get("loc", "")
            label = d.get("local_label", "公网地址")
            if label not in ("公网地址", "DoD 名义保留段", "IPv4 映射"):
                continue
            if not loc or "," not in loc:
                continue
            try:
                lat, lng = [float(x) for x in loc.split(",", 1)]
            except ValueError:
                continue
            glat, glng = wgs84_to_gcj02(lat, lng)
            key = (round(glat, 3), round(glng, 3))
            org = d.get("org", "")
            if org[:2].isdigit():
                org = org.split(" ", 1)[-1]
            city = " ".join(x for x in (d.get("city", ""), d.get("region", ""), d.get("country", "")) if x)
            rec = {
                "ip": ip,
                "hop": h["hop"],
                "lat": round(glat, 6),
                "lng": round(glng, 6),
                "city": city,
                "org": org,
                "ms": min(h["lat"]) if h["lat"] else None,
            }
            # 同一地理位置的连续节点只保留第一个，避免重叠标记
            if key in seen:
                continue
            seen.add(key)
            pts.append(rec)
            break
    return pts


def fmt(x):
    if x is None:
        return "-"
    if isinstance(x, float):
        return ("%.2f" % x).rstrip("0").rstrip(".")
    return str(x)


def print_report(hops, info, notes, target):
    print("\n=== nettrace 报告 ===")
    print("目标: %s | 跳数: %d" % (target or "(解析模式)", len(hops)))
    print("-" * 108)
    print("%-4s %-42s %-18s %s" % ("跳", "节点 IP", "延迟 ms", "归属 / 标注"))
    print("-" * 108)
    for h in hops:
        ips = h["ips"] or ["*"]
        lat = " ".join(fmt(x) for x in h["lat"]) or "* * *"
        for j, ip in enumerate(ips):
            d = info.get(ip, {})
            label = d.get("local_label", "")
            if label and label != "公网地址":
                desc = label
            elif d.get("org"):
                org = d["org"].split(" ", 1)[-1] if d["org"][:2].isdigit() else d["org"]
                desc = (d.get("city", "") + " " + d.get("country", "") + " ").strip() + org
            elif d.get("error"):
                desc = "查询失败: " + d["error"][:40]
            else:
                desc = "-"
            print("%-4s %-42s %-18s %s"
                  % (str(h["hop"] or "") if j == 0 else "",
                     ip[:42], lat if j == 0 else "", desc[:52]))
    print("-" * 108)
    if notes:
        print("\n诊断:")
        for level, text in notes:
            tag = {"info": "i", "warn": "!", "ok": "+"}[level]
            print("  [%s] %s" % (tag, text))
    print()


def write_html(hops, info, notes, target, outfile, path=None):
    import html
    esc = html.escape
    level_cls = {"info": "n-info", "warn": "n-warn", "ok": "n-ok"}
    path = path or []

    # 地图标记与连线数据（JSON 注入前端）
    map_json = json.dumps(path, ensure_ascii=False)
    if path:
        lats = [p["lat"] for p in path]
        lngs = [p["lng"] for p in path]
        center_lat = (min(lats) + max(lats)) / 2
        center_lng = (min(lngs) + max(lngs)) / 2
        span = max(max(lats) - min(lats), max(lngs) - min(lngs))
        zoom = 4 if span > 8 else (5 if span > 4 else (6 if span > 2 else (8 if span > 0.5 else 11)))
    else:
        center_lat, center_lng, zoom = 39.9042, 116.4074, 4

    rows = []
    for h in hops:
        ips = h["ips"] or ["*"]
        lat = " ".join(fmt(x) for x in h["lat"]) or "* * *"
        for j, ip in enumerate(ips):
            d = info.get(ip, {})
            label = d.get("local_label", "")
            if label and label != "公网地址":
                org = esc(label)
                sub = esc(d.get("local_note", ""))
                cls = "tag-local"
            elif d.get("org"):
                org_raw = d["org"]
                org = esc(org_raw.split(" ", 1)[-1] if org_raw[:2].isdigit() else org_raw)
                sub = esc((d.get("city", "") + " " + d.get("region", "") + " " + d.get("country", "")).strip())
                cls = "tag-public"
            elif d.get("error"):
                org, sub, cls = "查询失败", esc(d["error"][:60]), "tag-local"
            else:
                org, sub, cls = "-", "", "tag-local"
            rows.append(
                "<tr><td class='hop'>%s</td><td class='ip'>%s</td><td class='lat'>%s</td>"
                "<td><span class='%s'>%s</span><div class='sub'>%s</div></td></tr>"
                % (esc(str(h["hop"] or "")) if j == 0 else "",
                   esc(ip), esc(lat) if j == 0 else "", cls, org, sub)
            )

    note_html = "".join(
        "<li class='%s'>%s</li>" % (level_cls[lv], esc(t)) for lv, t in notes
    ) or "<li class='n-info'>无特殊诊断项</li>"

    reached = any(lv == "ok" for lv, _ in notes)
    status = "已到达目标" if reached else "未确认到达"
    status_cls = "n-ok" if reached else "n-warn"

    doc = """<!DOCTYPE html>
<html lang="zh-CN"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>nettrace 报告 - TARGET_PLACEHOLDER</title>
<style>
:root{--ink:#1c1b19;--mut:#6f6b63;--line:#dcd8ce;--paper:#faf9f6;--accent:#9b3b2e;--teal:#2c7a7b;}
*{box-sizing:border-box}
body{margin:0;background:var(--paper);color:var(--ink);font-family:-apple-system,"Segoe UI","Microsoft YaHei",sans-serif;font-size:14px;line-height:1.6}
.wrap{max-width:960px;margin:0 auto;padding:48px 32px 80px}
h1{font-family:Georgia,"Times New Roman",serif;font-size:30px;font-weight:400;margin:0 0 6px;letter-spacing:.3px}
.kicker{font-size:12px;letter-spacing:2px;color:var(--accent);text-transform:uppercase;margin-bottom:18px}
.meta{color:var(--mut);font-size:13px;margin-bottom:28px}
.cards{display:flex;gap:14px;flex-wrap:wrap;margin-bottom:32px}
.card{border:1px solid var(--line);background:#fff;padding:14px 18px;min-width:130px}
.card .k{font-size:11px;letter-spacing:1px;color:var(--mut);text-transform:uppercase}
.card .v{font-family:Georgia,serif;font-size:22px;margin-top:4px}
h2{font-family:Georgia,serif;font-size:18px;font-weight:400;margin:34px 0 14px;padding-bottom:8px;border-bottom:1px solid var(--line)}
table{width:100%;border-collapse:collapse;background:#fff}
th{text-align:left;font-size:11px;letter-spacing:1px;text-transform:uppercase;color:var(--mut);font-weight:400;padding:10px 12px;border-bottom:1px solid var(--line)}
td{padding:9px 12px;border-bottom:1px solid #efede7;vertical-align:top}
td.hop{color:var(--mut);width:34px;font-family:Georgia,serif}
td.ip{font-family:ui-monospace,Consolas,monospace;font-size:13px;width:230px;word-break:break-all}
td.lat{font-family:ui-monospace,Consolas,monospace;font-size:12px;color:var(--mut);width:150px}
.sub{font-size:12px;color:var(--mut);margin-top:2px}
.tag-local,.tag-public{display:inline-block;padding:1px 8px;font-size:12px;border-radius:2px}
.tag-local{background:#f0eee7;color:#6f6b63}
.tag-public{background:#e8f1f1;color:var(--teal)}
ul{list-style:none;padding:0;margin:0}
li{padding:9px 12px;border-left:3px solid var(--line);background:#fff;margin-bottom:6px;font-size:13px}
.n-info{border-color:#b9b4a8;color:#5f5b53}
.n-warn{border-color:var(--accent);color:#7d2f24;background:#fdf4f2}
.n-ok{border-color:var(--teal);color:#1f5d5e;background:#f0f8f7}
.foot{margin-top:40px;font-size:12px;color:var(--mut);border-top:1px solid var(--line);padding-top:14px}
#map{width:100%;height:440px;border:1px solid var(--line);background:#eef1ef}
.map-empty{padding:40px;text-align:center;color:var(--mut);font-size:13px}
.legend{font-size:12px;color:var(--mut);margin-top:8px}
.legend b{color:var(--accent);font-weight:400}
</style>
<script type="text/javascript">
window._TMapSecurityConfig = {
    serviceHost: 'http://127.0.0.1:__WB_HTTP_PORT__/_TMapService/_wbt/__WB_TMAP_SECRET__',
};
</script>
<script src="https://map.qq.com/api/gljs?v=1.exp"></script>
</head><body><div class="wrap">
<div class="kicker">nettrace / node analysis</div>
<h1>Traceroute 节点解析报告</h1>
<div class="meta">目标 TARGET_PLACEHOLDER · 生成于 TIME_PLACEHOLDER</div>
<div class="cards">
<div class="card"><div class="k">目标</div><div class="v" style="font-size:17px">TARGET_PLACEHOLDER</div></div>
<div class="card"><div class="k">跳数</div><div class="v">HOP_PLACEHOLDER</div></div>
<div class="card"><div class="k">状态</div><div class="v STATUS_CLS_PLACEHOLDER" style="font-size:17px">STATUS_PLACEHOLDER</div></div>
<div class="card"><div class="k">定位节点</div><div class="v">MAP_PLACEHOLDER</div></div>
</div>
<h2>路径地图</h2>
<div id="map"></div>
<div class="legend">圆点按跳序编号，<b>红线</b>为路径走向；坐标为 ipinfo 城市级定位并转换为 GCJ-02，仅供大致方位参考，非精确路由。</div>
<h2>诊断提示</h2><ul>NOTE_PLACEHOLDER</ul>
<h2>逐跳明细</h2>
<table><thead><tr><th>跳</th><th>节点 IP</th><th>延迟 ms</th><th>归属 / 标注</th></tr></thead>
<tbody>ROWS_PLACEHOLDER</tbody></table>
<div class="foot">归属数据来自 ipinfo.io；私网 / DoD 名义段 / ULA / IPv4 映射由本地规则识别。
纸面注册地（RDAP/IANA）不等于实际使用地，报告已对常见误判做标注。底图：腾讯地图。</div>
</div>
<script type="text/javascript">
(function () {
  var PATH = MAP_DATA_PLACEHOLDER;
  var el = document.getElementById('map');
  if (!PATH.length) {
    el.innerHTML = '<div class="map-empty">路径上无可定位的公网节点（可能全为私网 / DoD 名义段 / 无地理数据），地图未绘制。</div>';
    return;
  }
  var map = new TMap.Map('map', {
    zoom: MAP_ZOOM_PLACEHOLDER,
    center: new TMap.LatLng(MAP_LAT_PLACEHOLDER, MAP_LNG_PLACEHOLDER),
  });
  var coords = PATH.map(function (p) { return new TMap.LatLng(p.lat, p.lng); });
  if (coords.length >= 2) {
    new TMap.MultiPolyline({
      map: map,
      styles: { line: new TMap.PolylineStyle({ color: '#9b3b2e', width: 3, borderWidth: 1, borderColor: '#ffffff', lineCap: 'round' }) },
      geometries: [{ id: 'route', styleId: 'line', paths: coords }],
    });
  }
  var svg = '<svg xmlns="http://www.w3.org/2000/svg" width="28" height="28"><circle cx="14" cy="14" r="13" fill="#ffffff" stroke="#9b3b2e" stroke-width="2"/><circle cx="14" cy="14" r="9" fill="#9b3b2e"/></svg>';
  var markerStyle = new TMap.MarkerStyle({
    width: 28, height: 28, anchor: { x: 14, y: 14 },
    src: 'data:image/svg+xml;charset=utf-8,' + encodeURIComponent(svg),
  });
  var geoms = PATH.map(function (p) {
    return {
      id: 'n_' + p.hop + '_' + p.ip,
      styleId: 'dot',
      position: new TMap.LatLng(p.lat, p.lng),
      properties: { content: buildInfo(p) },
    };
  });
  var markers = new TMap.MultiMarker({
    map: map,
    styles: { dot: markerStyle },
    geometries: geoms,
  });
  var labels = new TMap.MultiLabel({
    map: map,
    styles: { num: new TMap.LabelStyle({ color: '#1c1b19', size: 12, angle: 0, alignment: 'center', verticalAlignment: 'middle', offset: { x: 0, y: 0 } }) },
    geometries: PATH.map(function (p) {
      return { id: 'l_' + p.hop + '_' + p.ip, styleId: 'num', position: new TMap.LatLng(p.lat, p.lng), content: String(p.hop) };
    }),
  });
  var info = new TMap.InfoWindow({ map: map, position: coords[0], content: '', enableCustom: false, offset: { x: 0, y: -18 } });
  info.close();
  markers.on('click', function (e) {
    info.setContent(e.geometry.properties.content);
    info.setPosition(e.geometry.position);
    info.open();
  });
  function buildInfo(p) {
    var h = '<div style="font-family:sans-serif;font-size:13px;line-height:1.7;min-width:180px">';
    h += '<b>第 ' + p.hop + ' 跳</b><br>';
    h += '<span style="font-family:monospace">' + p.ip + '</span><br>';
    h += (p.city ? p.city + '<br>' : '');
    h += (p.org ? p.org + '<br>' : '');
    h += (p.ms != null ? '延迟 ' + p.ms + ' ms' : '');
    h += '</div>';
    return h;
  }
})();
</script>
</body></html>"""

    from datetime import datetime
    uniq_ips = set()
    for h in hops:
        uniq_ips.update(h["ips"])
    doc = (doc.replace("TARGET_PLACEHOLDER", esc(target or "解析模式"))
              .replace("TIME_PLACEHOLDER", datetime.now().strftime("%Y-%m-%d %H:%M"))
              .replace("HOP_PLACEHOLDER", str(len(hops)))
              .replace("IP_PLACEHOLDER", str(len(uniq_ips)))
              .replace("MAP_PLACEHOLDER", str(len(path)))
              .replace("MAP_DATA_PLACEHOLDER", map_json)
              .replace("MAP_ZOOM_PLACEHOLDER", str(zoom))
              .replace("MAP_LAT_PLACEHOLDER", str(center_lat))
              .replace("MAP_LNG_PLACEHOLDER", str(center_lng))
              .replace("STATUS_CLS_PLACEHOLDER", status_cls)
              .replace("STATUS_PLACEHOLDER", status)
              .replace("NOTE_PLACEHOLDER", note_html)
              .replace("ROWS_PLACEHOLDER", "".join(rows)))
    with open(outfile, "w", encoding="utf-8") as f:
        f.write(doc)
    return outfile


def main():
    ap = argparse.ArgumentParser(description="traceroute 解析与节点归属诊断工具")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p1 = sub.add_parser("parse", help="解析已有的 traceroute 输出")
    p1.add_argument("source", help="文件路径，或 - 表示 stdin")
    p1.add_argument("-o", "--output", help="HTML 报告输出路径")

    p2 = sub.add_parser("trace", help="主动执行 traceroute 并解析")
    p2.add_argument("target")
    p2.add_argument("-p", "--port", type=int, default=443, help="TCP 端口（默认 443）")
    p2.add_argument("-T", "--tcp", action="store_true", help="使用 TCP 模式（Mac/Linux，需 root）")
    p2.add_argument("-I", "--icmp", action="store_true", help="使用 ICMP 模式")
    p2.add_argument("-U", "--udp", action="store_true", help="使用 UDP 模式")
    p2.add_argument("--hops", dest="max_hops", type=int, default=30, help="最大跳数")
    p2.add_argument("-o", "--output", help="HTML 报告输出路径")

    args = ap.parse_args()

    if args.cmd == "parse":
        if args.source == "-":
            text = sys.stdin.read()
        else:
            with open(args.source, encoding="utf-8", errors="replace") as f:
                text = f.read()
        target = ""
    else:
        proto = "T" if args.tcp else ("I" if args.icmp else ("U" if args.udp else "T"))
        text = run_trace(args.target, proto, args.port, args.max_hops)
        target = args.target
        if not text.strip():
            print("未获得 traceroute 输出", file=sys.stderr)
            return 1

    hops = parse_hops(text)
    if not hops:
        print("未从输入中解析出任何跳", file=sys.stderr)
        return 1

    ips = []
    for h in hops:
        for ip in h["ips"]:
            if ip not in ips:
                ips.append(ip)
    print("解析到 %d 跳、%d 个节点，正在查询归属..." % (len(hops), len(ips)), file=sys.stderr)
    cache = load_cache()
    info = enrich(ips, cache)
    save_cache(cache)

    notes = diagnose(hops, info, target)
    print_report(hops, info, notes, target)

    path = build_path(hops, info)
    print("地图路径点: %d 个（有公网坐标的节点）" % len(path), file=sys.stderr)

    os.makedirs(OUT_DIR, exist_ok=True)
    out = args.output or os.path.join(OUT_DIR, "nettrace_%s.html" % target.replace("/", "_")[:60])
    write_html(hops, info, notes, target, out, path)
    print("HTML 报告:", out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
