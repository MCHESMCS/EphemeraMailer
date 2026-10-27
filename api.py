#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import http.server
import urllib.parse
import urllib.request
import smtplib
import ssl
import json
import time
import secrets
import threading
import os
import sys
import socket
import socketserver
import re
import signal
import html
import email.header
import copy
import mimetypes
from email.utils import formatdate, make_msgid
from collections import defaultdict, deque
from concurrent.futures import ThreadPoolExecutor

# ==================== 相对路径核心 ====================
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_PATH = os.path.join(BASE_DIR, "config.json")
KEYS_PATH = os.path.join(BASE_DIR, "keys.json")
HTML_DIR = os.path.join(BASE_DIR, "html")
WEB_DIR = os.path.join(BASE_DIR, "web")
ASSETS_DIR = os.path.join(BASE_DIR, "assets")
STATIC_DIR = os.path.join(BASE_DIR, "static")
LOG_DIR = os.path.join(BASE_DIR, "logs")
LATEST_LOG = os.path.join(LOG_DIR, "latest.log")
DANGER_LOG = os.path.join(LOG_DIR, "danger.log")

# [ACCESS-CTRL] 接口级访问控制目录与配置
ACCESS_DIR = os.path.join(BASE_DIR, "access-control")
ACCESS_CONFIG_PATH = os.path.join(ACCESS_DIR, "config.json")
ACCESS_DANGER_PATH = os.path.join(ACCESS_DIR, "danger.json")
GLOBAL_STATE_PATH = os.path.join(ACCESS_DIR, "global_threat.json")

_keys_cache = {"keys": []}
_keys_dict = {}        
_keys_mtime = 0
_keys_lock = threading.RLock()
_temp_key_lock = threading.Lock()

# ==================== 危险感知全局状态 (重构版) ====================
# 滑动窗口计数，元组 key ("PATH", path, ip) 或 ("ZONE", zone_key, ip)
_danger_hits = {}
# 倒排索引：ip -> set of keys（加速 total_hits 计算）
_hits_by_ip = defaultdict(set)
_danger_lock = threading.RLock()
_zone_attackers = defaultdict(set)

# IP 最近访问路径
_ip_recent_paths = defaultdict(lambda: deque(maxlen=20))
_ip_paths_lock = threading.Lock()

# 活跃威胁 (ip -> {"event_id", "last_seen", "level", "last_path"})
_active_threats = {}
_active_threats_lock = threading.Lock()

# 告警去重集合：key = (ip, count_key) -> 首次触发时间
_alerted_set = {}
_alerted_lock = threading.Lock()

# 集群事件 (zone_key -> {"id", "time"})
_cluster_events = {}
_cluster_lock = threading.Lock()

# 全局熔断状态
_global_threat_state = {"high_count": 0, "critical_count": 0, "last_reset": time.time()}
_global_threat_lock = threading.Lock()
_global_save_lock = threading.Lock()
_last_global_save_time = 0
_persist_thread = None # 用于优雅关闭的引用

# 访问控制缓存与危险感知配置
_access_rules = {"default": "post", "routes": {}}
_access_mtime = 0
_access_lock = threading.RLock()

_danger_cfg = {
    "enabled": True, 
    "split_log": True,
    "ip_whitelist": ["127.0.0.1", "::1"],
    "default_policy": {"threshold": 10, "window_sec": 60, "apt_detection": False, "allow_shutdown": False},
    "zones": {},
    "active_threats_max": 50000
}
_danger_mtime = 0
_danger_cfg_lock = threading.RLock()

# 日志写盘锁
_rotate_lock = threading.Lock()
_danger_log_lock = threading.Lock()

# 线程池：危险日志独立异步池（max_workers=2）
_danger_log_pool = ThreadPoolExecutor(max_workers=2, thread_name_prefix="DangerLog")

# ==================== 核心启动时间 ====================
START_TIME = time.time() 
# 全局预计算 Node ID，防止高频调用 get_local_ip 产生 socket 开销
NODE_ID = "127.0.0.1" # 占位，稍后重新赋值

# 增加一个节拍器
_config_tick = threading.Event()
_config_reloading = threading.Lock()

# ==================== 监控统计 ====================
STATS_SUCCESS = 0
STATS_FAILED = 0
STATS_REJECTED = 0
_rejected_timestamps = deque()
_stats_lock = threading.Lock()

def record_success():
    global STATS_SUCCESS
    with _stats_lock: STATS_SUCCESS += 1

def record_fail():
    global STATS_FAILED
    with _stats_lock: STATS_FAILED += 1

def record_reject():
    global STATS_REJECTED
    with _stats_lock: 
        STATS_REJECTED += 1
        _rejected_timestamps.append(time.time())

# ==================== 默认模板 ====================
DEFAULT_HTML_CONFIG = {
    "account": "default",
    "subject": "【系统通知】您的验证码",
    "incoming": [
        {"incomingname": "code", "replace_string": "{code}"}
    ]
}

DEFAULT_HTML_CONTENT = """<!DOCTYPE html>
<html><head><meta charset="UTF-8"></head>
<body>
    <h2>系统验证</h2>
    <p>您的验证码是：<strong>{code}</strong></p>
</body></html>
"""

# ==================== 默认访问控制配置 ====================
DEFAULT_ACCESS_CONFIG = {
    "default": "post",
    "routes": {
        "/api/templates": "post",
        "/api/web_send": "all",
        "/api/*/send": "post",
        "/api/keys": "post",
        "/api/keys/create": "post",
        "/api/keys/revoke": "post",
        "/api/keys/perm": "post",
        "/api/admin/create_template": "post",
        "/api/admin/update_template": "post",
        "/api/admin/toggle_template_web": "post",
        "/api/admin/system_info": "post",
        "/api/admin/logs": "post",
        "/api/admin/list_templates": "post"
    }
}

DEFAULT_DANGER_CFG = {
    "enabled": True,
    "split_log": True,
    "ip_whitelist": ["127.0.0.1", "::1"],  # 打到内网了 那还说啥了给你了
    "default_policy": {
        "threshold": 10,
        "window_sec": 60,
        "apt_detection": False,
        "allow_shutdown": False
    },
    "zones": {}
}

# ==================== 工具类 ====================
def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"

def get_public_ip():
    try:
        req = urllib.request.Request("https://api.ipify.org", headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=2) as response:
            return response.read().decode('utf-8').strip()
    except Exception:
        return "未检测到公网IP(或超时)"

# ==================== 交互式 CLI ====================
def init_wizard():
    global _keys_cache 

    print("\n" + "="*60)
    print("欢迎使用 EphemeraMailer API 初始化向导")
    print("="*60)
    
    try:
        listen_port = int(input("1. HTTP 监听端口 [默认 8088]: ").strip() or 8088)
        https_port = int(input("2. HTTPS 监听端口 [默认 8443]: ").strip() or 8443)
        
        enable_api_http = input("3. 是否开启 HTTP API? (y/n) [默认 y]: ").strip().lower() != "n"
        enable_api_https = input("4. 是否开启 HTTPS API (需证书/私钥)? (y/n) [默认 y]: ").strip().lower() != "n"
        
        certfile = "certs/server.crt"
        keyfile = "certs/server.key"
        if enable_api_https:
            certfile = input("   - HTTPS 证书路径 [默认 certs/server.crt]: ").strip() or "certs/server.crt"
            keyfile = input("   - HTTPS 私钥路径 [默认 certs/server.key]: ").strip() or "certs/server.key"
        
        enable_web_page_http = False
        if enable_api_http:
            enable_web_page_http = input("   - HTTP API 已开启，是否同时允许通过 HTTP 访问 Web 页面 (发信页 + 管理页)? (y/n) [默认 n]: ").strip().lower() == "y"

        enable_web_page_https = False
        if enable_api_https:
            enable_web_page_https = input("   - HTTPS API 已开启，是否同时允许通过 HTTPS 访问 Web 页面 (发信页 + 管理页)? (y/n) [默认 y]: ").strip().lower() != "n"

        admin_path = input("5. 管理后台隐藏路径 [默认 /my_secret_admin]: ").strip() or "/my_secret_admin"
        
        print("\n--- 发信账户配置 ---")
        
        mode_in = input("   - 连接模式 (ssl/starttls/plain/localmta) [默认 ssl]: ").strip().lower()
        smtp_mode = mode_in if mode_in in ("starttls", "plain", "localmta") else "ssl"
        
        if smtp_mode == "localmta":
            smtp_host = input("   - 本地 MTA 地址 [默认 127.0.0.1]: ").strip() or "127.0.0.1"
            smtp_port = int(input("   - 本地 MTA 端口 [默认 25]: ").strip() or 25)
            smtp_user = ""
            smtp_pass = ""
            from_name = input("   - 发件人显示名称 [默认 System Admin]: ").strip() or "System Admin"
            from_addr = input("   - 发件人邮箱 (必须与本地 MTA 域名一致): ").strip()
            helo_host = input("   - HELO 域名 [默认 localhost]: ").strip() or "localhost"
            if "@" in helo_host or "." not in helo_host:
                helo_host = "localhost"
            ignore_ssl = False
            print("   ⚠️  注意: SPF/DKIM/DMARC 及投递策略需在本地 MTA 中配置")
        else:
            smtp_host = input("6. SMTP 服务器地址 [默认 127.0.0.1]: ").strip() or "127.0.0.1"
            smtp_port = int(input("   - SMTP 端口 [默认 465]: ").strip() or 465)
            smtp_user = input("   - SMTP 账号: ").strip()
            smtp_pass = input("   - SMTP 密码: ").strip()
            from_name = input("   - 发件人显示名称 [默认 System Admin]: ").strip() or "System Admin"
            from_addr = input("   - 发件人邮箱: ").strip() or smtp_user
            helo_host = input("   - HELO 域名 [默认 localhost]: ").strip() or "localhost"
            if "@" in helo_host or "." not in helo_host:
                helo_host = "localhost"
            ignore_ssl = input("   - 是否忽略 SMTP SSL 证书校验? (y/n) [默认 n]: ").strip().lower() == "y"
            >
        config = {
            "listen_port": listen_port,
            "https_port": https_port,
            "enable_web_http": enable_web_page_http,
            "enable_api_http": enable_api_http,
            "enable_web_https": enable_web_page_https,
            "enable_api_https": enable_api_https,
            "certfile": certfile,
            "keyfile": keyfile,
            "admin_path": admin_path,
            "rate_limit_ip_per_min": 10,
            "rate_limit_key_per_min": 30,
            "max_concurrent_sends": 5,
            "enable_custom_background": True,
            "accounts": {
                "default": {
                    "smtp_host": smtp_host,
                    "smtp_port": smtp_port,
                    "smtp_mode": smtp_mode,
                    "smtp_user": smtp_user,
                    "smtp_pass": smtp_pass,
                    "from_name": from_name,
                    "from_addr": from_addr,
                    "helo_host": helo_host,
                    "ignore_ssl": ignore_ssl
                }
            }
        }

        with open(CONFIG_PATH, "w", encoding="utf-8") as f:
            json.dump(config, f, ensure_ascii=False, indent=4)
        os.chmod(CONFIG_PATH, 0o600)
        
        print("\n✅ 配置已成功保存到 config.json！")

        admin_key = secrets.token_urlsafe(32)
        temp_test_key = "TEMP_TEST_" + secrets.token_urlsafe(16)
        
        test_data = {
            "keys": [
                {
                    "id": 1,
                    "key": admin_key,
                    "status": "active",
                    "perm": "admin",
                    "created": time.strftime("%Y-%m-%d %H:%M:%S"),
                    "note": "初始化超级管理员",
                    "is_temp": False
                },
                {
                    "id": 2,
                    "key": temp_test_key,
                    "status": "active",
                    "perm": "send",
                    "created": time.strftime("%Y-%m-%d %H:%M:%S"),
                    "note": "临时测试专用",
                    "is_temp": True
                }
            ]
        }
        
        with open(KEYS_PATH, "w", encoding="utf-8") as f:
            json.dump(test_data, f, ensure_ascii=False, indent=4)
        os.chmod(KEYS_PATH, 0o600)
        _keys_cache = test_data

        do_test = input("👉 是否现在生成测试命令以验证配置是否正确？ (y/n) [默认 y]: ").strip().lower() != "n"
        if do_test:
            print("\n" + "-"*60)
            test_to = input(f"📧 请输入用于接收测试邮件的收件邮箱 [默认发送到发件人自己 {from_addr}]: ").strip()
            if not test_to:
                test_to = from_addr
                
            local_ip = get_local_ip()
            public_ip = get_public_ip()
            
            test_code = str(secrets.randbelow(9000) + 1000)
            proto = "https" if enable_api_https else "http"
            port = https_port if enable_api_https else listen_port
            
            print(f"\n✅ 若配置正确，收件箱 {test_to} 应当收到一封验证码为 {test_code} 的邮件。")
            print(f"\n⚠️  默认策略下 /api/*/send 仅允许 POST，请使用以下命令测试：")
            print(f"\n🌐 公网测试:")
            print(f"   curl -X POST '{proto}://{public_ip}:{port}/api/v1/send' \\")
            print(f"     -H 'Content-Type: application/json' \\")
            print(f"     -d '{{\"KEY\":\"{temp_test_key}\",\"TO\":\"{test_to}\",\"code\":\"{test_code}\"}}'")
            print(f"\n🏠 内网测试:")
            print(f"   curl -X POST '{proto}://{local_ip}:{port}/api/v1/send' \\")
            print(f"     -H 'Content-Type: application/json' \\")
            print(f"     -d '{{\"KEY\":\"{temp_test_key}\",\"TO\":\"{test_to}\",\"code\":\"{test_code}\"}}'")
            print(f"\n💡 如需 GET 链接发信，请启动后修改 access-control/config.json 中 \"/api/*/send\" 为 \"all\" 或 \"get\"。")
            
            print("\n" + "="*60)
            print("🔑 您的初始 Admin Key (请务必妥善保存):")
            print(f"   {admin_key}")
            print(f"\n👉 管理后台访问地址:")
            print(f"   {proto}://{public_ip}:{port}{admin_path}")
            print("="*60 + "\n")

    except KeyboardInterrupt:
        print("\n[!] 用户取消初始化，退出。")
        sys.exit(1)
    except Exception as e:
        print(f"\n[!] 初始化失败: {repr(e)}")
        sys.exit(1)

def ensure_configs():
    global NODE_ID
    if not os.path.exists(CONFIG_PATH):
        init_wizard()
        
    if not os.path.exists(KEYS_PATH):
        with open(KEYS_PATH, "w", encoding="utf-8") as f:
            json.dump({"keys": []}, f, ensure_ascii=False, indent=4)
        os.chmod(KEYS_PATH, 0o600)

    if not os.path.exists(ACCESS_DIR):
        os.makedirs(ACCESS_DIR)
    if not os.path.exists(ACCESS_CONFIG_PATH):
        with open(ACCESS_CONFIG_PATH, "w", encoding="utf-8") as f:
            json.dump(DEFAULT_ACCESS_CONFIG, f, ensure_ascii=False, indent=4)
        os.chmod(ACCESS_CONFIG_PATH, 0o600)
        print("[*] 已自动生成接口访问控制配置 access-control/config.json")
    if not os.path.exists(ACCESS_DANGER_PATH):
        with open(ACCESS_DANGER_PATH, "w", encoding="utf-8") as f:
            json.dump(DEFAULT_DANGER_CFG, f, ensure_ascii=False, indent=4)
        os.chmod(ACCESS_DANGER_PATH, 0o600)
        print("[*] 已自动生成危险感知配置 access-control/danger.json")
    if not os.path.exists(WEB_DIR): os.makedirs(WEB_DIR)
    if not os.path.exists(ASSETS_DIR): os.makedirs(ASSETS_DIR)
    if not os.path.exists(STATIC_DIR): os.makedirs(STATIC_DIR)
    
    v1_dir = os.path.join(HTML_DIR, "v1")
    if not os.path.exists(v1_dir) or not os.listdir(HTML_DIR):
        if not os.path.exists(v1_dir): os.makedirs(v1_dir)
        with open(os.path.join(v1_dir, "config.json"), "w", encoding="utf-8") as f:
            json.dump(DEFAULT_HTML_CONFIG, f, ensure_ascii=False, indent=4)
        with open(os.path.join(v1_dir, "content.html"), "w", encoding="utf-8") as f:
            f.write(DEFAULT_HTML_CONTENT)
        print("[*] 已自动生成基础邮件模板 html/v1/")
    
    NODE_ID = get_local_ip()

ensure_configs()

with open(CONFIG_PATH, "r", encoding="utf-8") as f:
    CFG = json.load(f)

# ======== 防白痴路径校验 =============
admin_path = CFG.get("admin_path", "/my_secret_admin")
if not admin_path.startswith("/"):
    admin_path = "/" + admin_path
    
if admin_path == "/api" or admin_path.startswith("/api/"):
    print("\n" + "!"*60)
    print("[!] 致命错误: admin_path 不能以 /api 开头 这会与系统 API 路由发生严重冲突")
    print("[!] 请修改 config.json 中的 admin_path 配置")
    print("!"*60 + "\n")
    sys.exit(1)
    
if admin_path == "/web" or admin_path == "/":
    print("\n" + "!"*60)
    print(f"[!] 致命错误: admin_path 不能设置为 '{admin_path}'，这会与系统默认 Web 路由冲突")
    print("[!] 请修改 config.json 中的 admin_path 配置")
    print("!"*60 + "\n")
    sys.exit(1)

if admin_path == "/assets" or admin_path.startswith("/assets/"):
    print("\n" + "!"*60)
    print("[!] 致命错误: admin_path 不能以 /assets 开头，这会与静态资源路由冲突")
    print("!"*60 + "\n")
    sys.exit(1)

# ==================== 线程池与并发控制 ====================
max_workers = min(CFG.get("max_concurrent_sends", 5), 32)
executor = ThreadPoolExecutor(max_workers=max_workers)
semaphore = threading.Semaphore(max_workers * 2)
_log_lock = threading.Lock()
_config_executor = ThreadPoolExecutor(max_workers=3, thread_name_prefix="ConfigReloader")

# ==================== 轻量限流器 ====================
_rate_hits_ip = defaultdict(list)
_rate_hits_key = defaultdict(list)
_rate_lock = threading.Lock()

def clean_rate_dicts():
    while True:
        try:
            time.sleep(60)
            now = time.time()

            # 1. 限流清理
            with _rate_lock:
                for d in [_rate_hits_ip, _rate_hits_key]:
                    for k in list(d.keys()):
                        d[k] = [t for t in d[k] if t > now - 60]
                        if not d[k]: del d[k]
            with _stats_lock:
                while _rejected_timestamps and _rejected_timestamps[0] < now - 60:
                    _rejected_timestamps.popleft()

            with _danger_cfg_lock:
                danger_cfg_snapshot = dict(_danger_cfg)

            max_window = int(danger_cfg_snapshot.get("default_policy", {}).get("window_sec", 60))
            apt_window = 600
            for z in danger_cfg_snapshot.get("zones", {}).values():
                max_window = max(max_window, int(z.get("window_sec", 60)))
                apt_window = max(apt_window, int(z.get("apt_threshold_minutes", 10)) * 60)

            # === 锁内原地清理（杜绝 R71 快照丢数据） ===
            with _danger_lock:
                for k in list(_danger_hits.keys()):
                    k_window = max_window
                    if k[0] == "ZONE":
                        zone_cfg = danger_cfg_snapshot.get("zones", {}).get(k[1], {})
                        k_window = max(1, int(zone_cfg.get("window_sec", 60)))
                    elif k[0] == "PATH":
                        k_window = max(1, int(danger_cfg_snapshot.get("default_policy", {}).get("window_sec", 60)))
                    
                    valid = [t for t in _danger_hits[k] if t > now - k_window]
                    if valid:
                        _danger_hits[k] = valid
                    else:
                        del _danger_hits[k]

                new_hits_by_ip = defaultdict(set)
                new_zone_attackers = defaultdict(set)
                for k in _danger_hits.keys():
                    new_hits_by_ip[k[2]].add(k)
                    if k[0] == "ZONE":
                        new_zone_attackers[k[1]].add(k[2])

                _hits_by_ip.clear()
                _hits_by_ip.update(new_hits_by_ip)
                _zone_attackers.clear()
                _zone_attackers.update(new_zone_attackers)

            # === 清理 _active_threats（锁内扫，锁外不用算） ===
            with _active_threats_lock:
                victims = []
                for t_ip, info in _active_threats.items():
                    if info["level"] != "critical" and now - info["last_seen"] > apt_window:
                        victims.append(t_ip)
                    elif now - info["last_seen"] > 1800:
                        victims.append(t_ip)
                for v_ip in victims:
                    del _active_threats[v_ip]

            # === 清理 _alerted_set ===
            with _alerted_lock:
                for ak in list(_alerted_set.keys()):
                    if ak[1][0] == "ZONE":
                        w_sec = danger_cfg_snapshot.get("zones", {}).get(ak[1][1], {}).get("window_sec", 60)
                    else:
                        w_sec = danger_cfg_snapshot.get("default_policy", {}).get("window_sec", 60)
                    
                    if now - _alerted_set[ak] > w_sec:
                        del _alerted_set[ak]
                
                if len(_alerted_set) > 100000:
                    sorted_keys = sorted(_alerted_set.keys(), key=lambda k: _alerted_set[k])
                    for k in sorted_keys[:50000]:
                        del _alerted_set[k]
                    audit("ALERTED_SET_FORCED_EVICTION executed")

            # === 清理 _ip_recent_paths ===
            with _ip_paths_lock:
                for ip in list(_ip_recent_paths.keys()):
                    if not _ip_recent_paths[ip]:
                        del _ip_recent_paths[ip]
                    elif now - _ip_recent_paths[ip][-1][0] > max_window + 300:
                        del _ip_recent_paths[ip]

            # === 清理 _cluster_events ===
            with _cluster_lock:
                for zone in list(_cluster_events.keys()):
                    if now - _cluster_events[zone]["time"] > apt_window:
                        del _cluster_events[zone]

        except Exception as e:
            audit(f"CLEAN_ERR {repr(e)}")
            
threading.Thread(target=clean_rate_dicts, daemon=True).start()

def check_rate_limit(ip, key):
    now = time.time()
    lim_ip = CFG.get("rate_limit_ip_per_min", 10)
    lim_key = CFG.get("rate_limit_key_per_min", 30)
    with _rate_lock:
        _rate_hits_ip[ip] = [t for t in _rate_hits_ip[ip] if t > now - 60]
        _rate_hits_key[key] = [t for t in _rate_hits_key[key] if t > now - 60]
        if len(_rate_hits_ip[ip]) >= lim_ip:
            return False, f"IP rate limited ({lim_ip}/min)"
        if len(_rate_hits_key[key]) >= lim_key:
            return False, f"KEY rate limited ({lim_key}/min)"
        _rate_hits_ip[ip].append(now)
        _rate_hits_key[key].append(now)
        return True, ""

# ==================== 配置热重载 ====================

def _reload_keys():
    global _keys_mtime, _keys_cache, _keys_dict
    try:
        if os.path.exists(KEYS_PATH):
            mtime = os.stat(KEYS_PATH).st_mtime
            if mtime != _keys_mtime:
                with open(KEYS_PATH, "r", encoding="utf-8") as f:
                    data = json.load(f)
                if "keys" not in data:
                    data["keys"] = []
                
                new_dict = {}
                for item in data["keys"]:
                    if item.get("status") == "active":
                        new_dict[item["key"]] = item
                
                with _keys_lock:
                    _keys_cache = data
                    _keys_dict = new_dict
                    _keys_mtime = mtime
    except Exception as e:
        audit(f"KEYS_RELOAD_ERR {repr(e)}")

def _reload_access():
    global _access_rules, _access_mtime
    try:
        if os.path.exists(ACCESS_CONFIG_PATH):
            mtime = os.stat(ACCESS_CONFIG_PATH).st_mtime
            if mtime != _access_mtime:
                with open(ACCESS_CONFIG_PATH, "r", encoding="utf-8") as f:
                    data = json.load(f)
                if not isinstance(data, dict):
                    data = dict(DEFAULT_ACCESS_CONFIG)
                if "routes" not in data or not isinstance(data["routes"], dict):
                    data["routes"] = {}
                if data.get("default") not in ("all", "get", "post", "none"):
                    data["default"] = "post"
                with _access_lock:
                    _access_rules = data
                    _access_mtime = mtime
    except Exception as e:
        audit(f"ACCESS_RELOAD_ERR {repr(e)}")

def _reload_danger():
    global _danger_cfg, _danger_mtime
    try:
        if os.path.exists(ACCESS_DANGER_PATH):
            mtime = os.stat(ACCESS_DANGER_PATH).st_mtime
            if mtime != _danger_mtime:
                with open(ACCESS_DANGER_PATH, "r", encoding="utf-8") as f:
                    data = json.load(f)
                if not isinstance(data, dict):
                    data = dict(DEFAULT_DANGER_CFG)
                
                def_safe = DEFAULT_DANGER_CFG["default_policy"]
                dp_raw = data.get("default_policy", def_safe)
                default_policy = {
                    "threshold": max(1, int(dp_raw.get("threshold", 10))) if str(dp_raw.get("threshold", "")).isdigit() else 10,
                    "window_sec": max(1, int(dp_raw.get("window_sec", 60))) if str(dp_raw.get("window_sec", "")).isdigit() else 60,
                    "apt_detection": bool(dp_raw.get("apt_detection", False)),
                    "allow_shutdown": bool(dp_raw.get("allow_shutdown", False))
                }

                prio_map = {"low": 0, "medium": 1, "high": 2, "critical": 3}
                zones = {}
                for zone, p_raw in data.get("zones", {}).items():
                    if not isinstance(p_raw, dict):
                        continue
                    try:
                        prio_str = str(p_raw.get("priority", "low")).lower()
                        zones[zone] = {
                            "threshold": max(1, int(p_raw.get("threshold", 10))),
                            "window_sec": max(1, int(p_raw.get("window_sec", 60))),
                            "share_hits": bool(p_raw.get("share_hits", False)),
                            "apt_detection": bool(p_raw.get("apt_detection", False)),
                            "allow_shutdown": bool(p_raw.get("allow_shutdown", False)),
                            "apt_threshold_minutes": int(p_raw.get("apt_threshold_minutes", 10)),
                            "priority_num": prio_map.get(prio_str, 0)
                        }
                    except (ValueError, TypeError):
                        audit(f"DANGER_CONFIG_ERR zone={zone} skipped")

                merged = {
                    "enabled": bool(data.get("enabled", True)),
                    "split_log": bool(data.get("split_log", True)),
                    "ip_whitelist": list(data.get("ip_whitelist", ["127.0.0.1", "::1"])),
                    "default_policy": default_policy,
                    "zones": zones,
                    "active_threats_max": max(1000, int(data.get("active_threats_max", 50000)))
                }
                with _danger_cfg_lock:
                    _danger_cfg = merged
                    _danger_mtime = mtime
    except Exception as e:
        audit(f"DANGER_RELOAD_ERR {repr(e)}")

def _heartbeat():
    while True:
        time.sleep(1)
        _config_tick.set()

def _wait_for_tick():
    while True:
        _config_tick.wait()
        _config_tick.clear()
        
        if not _config_reloading.acquire(blocking=False):
            continue
            
        def _task_wrapper():
            try:
                _reload_keys()
                _reload_access()
                _reload_danger()
            finally:
                _config_reloading.release()
        
        _config_executor.submit(_task_wrapper)

# ==================== 危险感知辅助函数 ====================

def _rotate_latest_log_safe():
    """统一的 LATEST_LOG 轮转逻辑，防止并发 rename 丢文件"""
    with _rotate_lock:
        if not os.path.exists(LATEST_LOG):
            return
        if os.path.getsize(LATEST_LOG) <= 10 * 1024 * 1024:
            return
        try:
            archive_name = f"history_{time.strftime('%Y%m%d_%H%M%S')}_{secrets.token_hex(2)}.log"
            archive_path = os.path.join(LOG_DIR, archive_name)
            os.rename(LATEST_LOG, archive_path)
        except FileNotFoundError:
            pass
        except Exception as e:
            print(f"[_rotate_latest_log_safe] {repr(e)}")

def _write_danger_log_safe(line_obj):
    """异步、线程安全、原子、带时间戳的危险日志写入"""
    def _write():
        try:
            if not os.path.exists(LOG_DIR):
                os.makedirs(LOG_DIR, exist_ok=True)
            record = {"ts": time.strftime("%Y-%m-%d %H:%M:%S"), **line_obj}
            data = json.dumps(record, ensure_ascii=False)
            with _danger_log_lock:
                with open(DANGER_LOG, "a", encoding="utf-8") as f:
                    f.write(data + "\n")
        except Exception as e:
            audit(f"DANGER_LOG_WRITE_ERR {repr(e)}")

    try:
        _danger_log_pool.submit(_write)
    except RuntimeError:
        _write()

def _write_danger_to_latest_safe(line_obj):
    """A3 修复：split_log=False 时写入 LATEST_LOG，但不抢 audit() 的 _log_lock"""
    def _write():
        try:
            if not os.path.exists(LOG_DIR):
                os.makedirs(LOG_DIR, exist_ok=True)
            record = {"ts": time.strftime("%Y-%m-%d %H:%M:%S"), **line_obj}
            data = json.dumps(record, ensure_ascii=False)
            with _danger_log_lock:
                _rotate_latest_log_safe()
                with open(LATEST_LOG, "a", encoding="utf-8") as f:
                    f.write(f"[{record['ts']}] DANGER_PROBE {data}\n")
        except Exception as e:
            audit(f"DANGER_LATEST_WRITE_ERR {repr(e)}")

    try:
        _danger_log_pool.submit(_write)
    except RuntimeError:
        _write()

def _match_zone(path, zones_dict):
    matched = None
    matched_key = ""
    best_score = (-1, -1, -1, -1)

    for zone, policy in zones_dict.items():
        pattern = "^" + re.escape(zone).replace(r"\*", "[^/]+") + "$"
        if not re.match(pattern, path):
            continue

        prio = policy.get("priority_num", 0)
        if not isinstance(prio, int):
            prio = 0
        literal_len = len(zone.replace("*", ""))
        wildcard_count = zone.count("*")
        score = (prio, literal_len, -wildcard_count, len(zone))
        if score > best_score:
            best_score = score
            matched = policy
            matched_key = zone

    return matched_key, matched

def _save_global_state():
    with _global_threat_lock:
        snapshot = dict(_global_threat_state)

    tmp_path = GLOBAL_STATE_PATH + ".tmp"
    try:
        snapshot["v"] = 1
        with open(tmp_path, "w", encoding="utf-8") as f:
            json.dump(snapshot, f, ensure_ascii=False)
        os.chmod(tmp_path, 0o600)
        os.replace(tmp_path, GLOBAL_STATE_PATH)
    except Exception as e:
        audit(f"GLOBAL_STATE_SAVE_ERR {repr(e)}")
        if os.path.exists(tmp_path):
            try: os.remove(tmp_path)
            except: pass

def _load_global_state():
    if not os.path.exists(GLOBAL_STATE_PATH):
        return
    try:
        with open(GLOBAL_STATE_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
        if not isinstance(data, dict):
            raise ValueError("not a dict")

        now = time.time()
        last_reset = data.get("last_reset", 0)
        try:
            last_reset = float(last_reset)
        except (ValueError, TypeError):
            last_reset = 0

        if now - last_reset > 600:
            data = {"high_count": 0, "critical_count": 0, "last_reset": now}
        else:
            data = {
                "high_count": max(0, int(data.get("high_count", 0))),
                "critical_count": max(0, int(data.get("critical_count", 0))),
                "last_reset": last_reset
            }

        with _global_threat_lock:
            _global_threat_state.clear()
            _global_threat_state.update(data)

        audit(f"GLOBAL_STATE_LOADED high={data['high_count']} critical={data['critical_count']}")
    except Exception as e:
        audit(f"GLOBAL_STATE_LOAD_ERR {repr(e)}")

# ==================== 危险感知判定与记录 ====================

def _calculate_threat_level(ip, path, zone_key, window_sec, current_count, cfg):
    now = time.time()
    total_hits = 0
    with _danger_lock:
        for k in _hits_by_ip.get(ip, ()):
            k_window = window_sec
            if k[0] == "ZONE":
                zone_cfg = cfg.get("zones", {}).get(k[1], {})
                k_window = max(1, int(zone_cfg.get("window_sec", window_sec)))
            elif k[0] == "PATH":
                k_window = max(1, int(cfg.get("default_policy", {}).get("window_sec", window_sec)))
            
            valid_hits = [t for t in _danger_hits.get(k, ()) if t > now - k_window]
            total_hits += len(valid_hits)

    effective_hits = max(current_count, total_hits)

    path_count = 0
    with _ip_paths_lock:
        if ip in _ip_recent_paths:
            recent = set(p for t, p in _ip_recent_paths[ip] if t > now - window_sec)
            path_count = len(recent)

    if effective_hits > 30 or path_count > 5:
        level = "high"
    elif effective_hits > 10 or path_count > 2:
        level = "medium"
    else:
        level = "low"

    attacker_count = 1
    if zone_key:
        with _danger_lock:
            attackers = set()
            for a_ip in _zone_attackers.get(zone_key, ()):
                zk = ("ZONE", zone_key, a_ip)
                if any(t > now - window_sec for t in _danger_hits.get(zk, ())):
                    attackers.add(a_ip)
            attacker_count = len(attackers)
        if attacker_count >= 5:
            level = "high"

    return level, attacker_count

def _update_hits(ip, path, matched_zone_key, policy, is_zone_hit, now):
    if is_zone_hit and policy.get("share_hits", False):
        count_key = ("ZONE", matched_zone_key, ip)
    else:
        count_key = ("PATH", path, ip)
    
    threshold = max(1, int(policy.get("threshold", 10)))
    window = max(1, int(policy.get("window_sec", 60)))
    
    with _danger_lock:
        hits = [t for t in _danger_hits.get(count_key, ()) if t > now - window]
        hits.append(now)
        _danger_hits[count_key] = hits
        _hits_by_ip[ip].add(count_key)
        if count_key[0] == "ZONE":
            _zone_attackers[count_key[1]].add(ip)
        count = len(hits)
    
    return count_key, count, threshold, window

def _should_alert(ip, count_key, count, threshold, now):
    alert_key = (ip, count_key)
    with _alerted_lock:
        if count >= threshold and alert_key not in _alerted_set:
            _alerted_set[alert_key] = now
            if len(_alerted_set) > 50000 and len(_alerted_set) % 1000 == 0:
                audit(f"ALERTED_SET_WARNING size={len(_alerted_set)}")
            return True
    return False

def _compute_prio(ip, path, matched_zone_key, window, apt_enabled, policy, now, current_count, cfg):
    current_prio, attacker_count = _calculate_threat_level(ip, path, matched_zone_key, window, current_count, cfg)
    is_cluster = attacker_count > 1
    is_sustained = False
    event_id = ""
    cluster_event_id = ""

    if apt_enabled:
        apt_window = max(60, int(policy.get("apt_threshold_minutes", 10)) * 60)

        if is_cluster:
            current_prio = "critical"
            with _cluster_lock:
                if matched_zone_key not in _cluster_events or now - _cluster_events[matched_zone_key]["time"] > 300:
                    _cluster_events[matched_zone_key] = {
                        "id": f"EVT-CLUSTER-{secrets.token_hex(4)}",
                        "time": now
                    }
                cluster_event_id = _cluster_events[matched_zone_key]["id"]

        levels = ["low", "medium", "high", "critical"]
        with _active_threats_lock:
            threat_info = _active_threats.get(ip)
            old_level = threat_info["level"] if threat_info and threat_info["level"] in levels else "low"

            if threat_info and (now - threat_info["last_seen"] < apt_window):
                is_sustained = True
                event_id = threat_info["event_id"]
                old_idx = levels.index(old_level)
                new_idx = min(3, old_idx + 1)
                current_prio = levels[new_idx]
            else:
                if levels.index(current_prio) < levels.index(old_level):
                    current_prio = old_level

        if is_cluster:
            current_prio = "critical"
            if not is_sustained:
                event_id = cluster_event_id
    else:
        event_id = f"EVT-{secrets.token_hex(4)}"

    return current_prio, attacker_count, is_sustained, is_cluster, event_id

def _update_active_threat(ip, path, current_prio, event_id, now):
    # 锁序修复：先在 _danger_cfg_lock 内拿快照，出锁
    with _danger_cfg_lock:
        max_limit = _danger_cfg.get("active_threats_max", 50000)
    
    with _active_threats_lock:
        _active_threats[ip] = {
            "event_id": event_id,
            "last_seen": now,
            "level": current_prio,
            "last_path": path
        }
        if len(_active_threats) > max_limit * 1.2:
            victims = [k for k, v in _active_threats.items() if v["level"] != "critical"][:int(max_limit * 0.2)]
            for v_ip in victims:
                del _active_threats[v_ip]
            audit(f"ACTIVE_THREAT_EMERGENCY_EVICTED count={len(victims)}")

def _evaluate_global_shutdown(current_prio, allow_shutdown, now):
    global _last_global_save_time
    force_shutdown = False
    if allow_shutdown:
        with _global_threat_lock:
            if now - _global_threat_state["last_reset"] > 600:
                _global_threat_state["high_count"] = 0
                _global_threat_state["critical_count"] = 0
                _global_threat_state["last_reset"] = now

            if current_prio in ("high", "critical"):
                _global_threat_state[f"{current_prio}_count"] += 1

            if _global_threat_state["high_count"] > 20 or _global_threat_state["critical_count"] > 5:
                force_shutdown = True

        if force_shutdown:
            with _global_save_lock:
                if now - _last_global_save_time > 5:
                    _last_global_save_time = now
                    _save_global_state()

    return force_shutdown

def _emit_danger_log(ip, path, count_key, count, current_prio, is_sustained, is_cluster, 
                     attacker_count, event_id, allow_shutdown, force_shutdown, window, now, cfg):
    with _ip_paths_lock:
        targets = list(set(p for t, p in _ip_recent_paths[ip] if t > now - window))

    line_obj = {
        "node_id": NODE_ID,
        "evt": event_id,
        "prio": current_prio,
        "sustained": is_sustained,
        "cluster": attacker_count,
        "ip": ip,
        "scope_type": count_key[0],
        "scope_key": count_key[1],
        "count": count,
        "targets": targets,
        "allow_shutdown": allow_shutdown,
        "escalated": force_shutdown
    }

    if cfg.get("split_log", True):
        _write_danger_log_safe(line_obj)
    else:
        _write_danger_to_latest_safe(line_obj)

def record_danger(path, ip):
    with _danger_cfg_lock:
        cfg = dict(_danger_cfg)
    if not cfg.get("enabled", True):
        return
    if ip in cfg.get("ip_whitelist", []):
        return

    now = time.time()
    with _ip_paths_lock:
        _ip_recent_paths[ip].append((now, path))

    matched_zone_key, matched_zone = _match_zone(path, cfg.get("zones", {}))
    policy = matched_zone if matched_zone else cfg.get("default_policy", {})
    is_zone_hit = True if matched_zone else False

    count_key, count, threshold, window = _update_hits(ip, path, matched_zone_key, policy, is_zone_hit, now)

    if not _should_alert(ip, count_key, count, threshold, now):
        return

    current_prio, attacker_count, is_sustained, is_cluster, event_id = _compute_prio(
        ip, path, matched_zone_key, window, policy.get("apt_detection", False), policy, now, count, cfg
    )

    _update_active_threat(ip, path, current_prio, event_id, now)
    force_shutdown = _evaluate_global_shutdown(current_prio, policy.get("allow_shutdown", False), now)

    _emit_danger_log(
        ip, path, count_key, count, current_prio, is_sustained, is_cluster,
        attacker_count, event_id, policy.get("allow_shutdown", False), force_shutdown, window, now, cfg
    )

# ==================== 路径匹配与全局状态持久化 ====================
def _check_access(path):
    with _access_lock:
        routes = dict(_access_rules.get("routes", {}))
        default = _access_rules.get("default", "post")
    if path in routes:
        return routes[path]
    for rule, val in routes.items():
        if "*" in rule:
            pattern = "^" + re.escape(rule).replace(r"\*", "[^/]+") + "$"
            if re.match(pattern, path):
                return val
    return default

def load_keys():
    with _keys_lock: 
        return copy.deepcopy(_keys_cache)

def save_keys(new_data, deleted_ids=None):
    global _keys_cache
    if deleted_ids is None:
        deleted_ids = []

    with _keys_lock:
        tmp_path = KEYS_PATH + ".tmp" 
        try:
            try:
                with open(KEYS_PATH, "r", encoding="utf-8") as f:
                    disk_data = json.load(f)
            except Exception:
                disk_data = {"keys": []}
            
            disk_keys_map = {k["id"]: k for k in disk_data.get("keys", [])}
            
            for del_id in deleted_ids:
                disk_keys_map.pop(del_id, None)
                
            for new_k in new_data.get("keys", []):
                if new_k["id"] not in deleted_ids:
                    disk_keys_map[new_k["id"]] = new_k

            merged_data = {"keys": list(disk_keys_map.values())}
            _keys_cache = copy.deepcopy(merged_data)

            with open(tmp_path, "w", encoding="utf-8") as f:
                json.dump(merged_data, f, ensure_ascii=False, indent=2)
            os.chmod(tmp_path, 0o600)
            os.replace(tmp_path, KEYS_PATH)
            
        except Exception as e:
            audit(f"SAVE_KEYS_ERR {repr(e)}")
            if os.path.exists(tmp_path):
                os.remove(tmp_path)

def find_key(k):
    if not k:
        return None
    with _keys_lock:
        key_obj = _keys_dict.get(k)
        return copy.deepcopy(key_obj) if key_obj else None

def is_admin(k):
    key_obj = find_key(k)
    return key_obj is not None and key_obj.get("perm", "send") == "admin"

def audit(msg):
    safe_msg = str(msg).replace('\n', ' ').replace('\r', '')
    with _log_lock:
        try:
            print(f"\033[90m[{time.strftime('%Y-%m-%d %H:%M:%S')}]\033[0m {safe_msg}")
            
            if not os.path.exists(LOG_DIR):
                os.makedirs(LOG_DIR)
                
            _rotate_latest_log_safe()
                
            with open(LATEST_LOG, "a", encoding="utf-8") as f:
                f.write(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] {safe_msg}\n")
        except Exception:
            pass

def _enc_name(n):
    return email.header.Header(n, "utf-8").encode()

# ==================== 启动自动注册 Admin ====================
def init_admin_key():
    data = load_keys()
    has_admin = any(key_obj.get("perm") == "admin" and key_obj.get("status") == "active" for key_obj in data["keys"])
    
    if not has_admin:
        new_id = max([key_obj["id"] for key_obj in data["keys"]], default=0) + 1
        new_key = secrets.token_urlsafe(32)
        data["keys"].append({
            "id": new_id,
            "key": new_key,
            "status": "active",
            "perm": "admin",
            "created": time.strftime("%Y-%m-%d %H:%M:%S"),
            "note": "初始化超级管理员",
            "is_temp": False
        })
        save_keys(data)
        
        port = CFG.get("https_port") if CFG.get("enable_web_https", False) else CFG.get("listen_port")
        protocol = "https" if CFG.get("enable_web_https", False) else "http"

        print("\n" + "="*60)
        print("⚠️  未检测到可用的 Admin 权限 Key，系统已自动注册！")
        print(f"🔑 初始 Admin Key: {new_key}")
        print(f"👉 请复制此 Key 并前往: {protocol}://<你的IP>:{port}{admin_path} 进行登录")
        print("="*60 + "\n")

# ==================== 异步发信引擎 ====================
def async_send_task(template_name, to_addr, params, account_cfg, ip, key_id, is_temp_test, tmpl_cfg):
    try:
        dir_path = os.path.join(HTML_DIR, template_name)
        with open(os.path.join(dir_path, "content.html"), "r", encoding="utf-8") as f:
            html_content = f.read()

        incoming_rules = tmpl_cfg.get("incoming", [])
        if isinstance(incoming_rules, list):
            for rule in incoming_rules:
                incoming_name = rule.get("incomingname")
                replace_str = rule.get("replace_string")
                if incoming_name in params and replace_str:
                    safe_val = html.escape(str(params[incoming_name]))
                    html_content = html_content.replace(replace_str, safe_val)

        raw_subject = tmpl_cfg.get("subject", "Notification")
        subject = email.header.Header(raw_subject, "utf-8").encode()
        
        from_domain = account_cfg.get("from_addr", "localhost").split("@")[-1]
        msg_id = make_msgid(domain=from_domain)
        date_str = formatdate(localtime=False)
        
        mail_raw = f"""From: {_enc_name(account_cfg['from_name'])} <{account_cfg['from_addr']}>
To: {to_addr}
Subject: {subject}
Date: {date_str}
Message-ID: {msg_id}
MIME-Version: 1.0
Content-Type: text/html; charset="utf-8"

{html_content}
""".replace("\n", "\r\n")

                ignore_ssl = account_cfg.get("ignore_ssl", False)
        ctx = ssl._create_unverified_context() if ignore_ssl else ssl.create_default_context()
        
        smtp_mode = account_cfg.get("smtp_mode", "ssl")
        host = account_cfg["smtp_host"]
        port = account_cfg["smtp_port"]
        
        if smtp_mode == "localmta":
            # 这时候就有人要问了，为什么不把local和plain合并来简化代码量呢，因为我们是支持混发的，合并逻辑会大幅降低可维护性并引发各种各样的bug
            with smtplib.SMTP(host, port, timeout=3) as server:
                server.ehlo(account_cfg.get("helo_host", "localhost"))
                server.sendmail(account_cfg["from_addr"], [to_addr], mail_raw.encode("utf-8"))
                
        elif smtp_mode == "plain":
            with smtplib.SMTP(host, port, timeout=10) as server:
                server.ehlo(account_cfg.get("helo_host", "localhost"))
                if account_cfg.get("smtp_user") and account_cfg.get("smtp_pass"):
                    server.login(account_cfg["smtp_user"], account_cfg["smtp_pass"])
                server.sendmail(account_cfg["from_addr"], [to_addr], mail_raw.encode("utf-8"))
                
        elif smtp_mode == "starttls":
            with smtplib.SMTP(host, port, timeout=10) as server:
                server.ehlo(account_cfg.get("helo_host", "localhost"))
                server.starttls(context=ctx)
                if account_cfg.get("smtp_user") and account_cfg.get("smtp_pass"):
                    server.login(account_cfg["smtp_user"], account_cfg["smtp_pass"])
                server.sendmail(account_cfg["from_addr"], [to_addr], mail_raw.encode("utf-8"))
                
        else: # smtp_mode == "ssl"
            with smtplib.SMTP_SSL(host, port, timeout=10, context=ctx) as server:
                server.ehlo(account_cfg.get("helo_host", "localhost"))
                if account_cfg.get("smtp_user") and account_cfg.get("smtp_pass"):
                    server.login(account_cfg["smtp_user"], account_cfg["smtp_pass"])
                server.sendmail(account_cfg["from_addr"], [to_addr], mail_raw.encode("utf-8"))
        
        audit(f"SEND_OK tmpl={template_name} to={to_addr} key_id={key_id} ip={ip}")
        record_success()

    except Exception as e:
        audit(f"SEND_ERR tmpl={template_name} to={to_addr} key_id={key_id} ip={ip} err={repr(e)}")
        record_fail()
    finally:
        if is_temp_test:
            with _temp_key_lock:
                save_keys({"keys": []}, deleted_ids=[key_id])
                audit(f"TEMP_KEY_REVOKED id={key_id} reason=test_completed")
        
        try:
            semaphore.release()
        except Exception:
            pass

# ==================== 主处理类 ====================
class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, fmt, *args): pass

    def handle_one_request(self):
        try:
            super().handle_one_request()
        except (ConnectionResetError, BrokenPipeError, TimeoutError):
            pass 
        except Exception as e:
            audit(f"HANDLE_ERR {repr(e)}")

    def _resp(self, code, obj):
        body = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _html(self, content):
        body = content.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _params(self, parsed):
        d = {}
        for k, v in urllib.parse.parse_qs(parsed.query, keep_blank_values=True).items():
            d[k] = v[0]
            
        if self.headers.get("Transfer-Encoding") and self.headers.get("Content-Length"):
            self.close_connection = True
            return None

        if self.headers.get("Transfer-Encoding"):
            self.close_connection = True
            return None
            
        cl_values = self.headers.get_all("Content-Length")
        if cl_values and len(cl_values) > 1:
            self.close_connection = True
            return None
            
        try:
            raw_length = self.headers.get("Content-Length", "0")
            length = int(raw_length)
            
            if length < 0 or length > 1024 * 1024:
                self.close_connection = True
                return None
            
            if length > 0:
                raw = self.rfile.read(length)
                if not raw: 
                    return d
                
                content_type = self.headers.get("Content-Type", "")
                
                if "application/json" in content_type:
                    try:
                        body = json.loads(raw.decode("utf-8"))
                        if isinstance(body, dict):
                            d.update(body)
                    except Exception:
                        pass
                elif "application/x-www-form-urlencoded" in content_type:
                    try:
                        body = urllib.parse.parse_qs(raw.decode("utf-8"), keep_blank_values=True)
                        for k, v in body.items():
                            d[k] = v[0]
                    except Exception:
                        pass

        except ValueError:
            self.close_connection = True
            return None
        except Exception as e:
            audit(f"PARAMS_LEN_ERR {repr(e)}")
            self.close_connection = True
            return None
            
        return d

    def do_GET(self): self._route("GET")
    def do_POST(self): self._route("POST")

    def _route(self, method):
        try:
            if "FAKE" in self.path or "HACKED" in self.path:
                self.send_response(401)
                self.end_headers()
                return

            parsed = urllib.parse.urlparse(self.path)
            path = parsed.path
            client_ip = self.client_address[0]

            # ==================== 极致路由级拦截 ====================
            is_https = isinstance(self.request, ssl.SSLSocket)
            if is_https:
                enable_api = CFG.get("enable_api_https", True)
                enable_web = CFG.get("enable_web_https", True)
            else:
                enable_api = CFG.get("enable_api_http", True)
                enable_web = CFG.get("enable_web_http", False)

            is_web_req = (path == "/web" or path == admin_path)
            is_api_req = path.startswith("/api/")

            if is_web_req and not enable_web:
                self.close_connection = True 
                return
            if is_api_req and not enable_api:
                self.close_connection = True
                return

            # ==================== Access-Control 接口授权 ====================
            if is_api_req:
                allowed = _check_access(path)
                if allowed == "none":
                    record_danger(path, client_ip)
                    self._resp(404, {"ok": False, "error": "not found"})
                    return
                if allowed == "get" and method == "POST":
                    record_reject()
                    self._resp(405, {"ok": False, "error": "POST method not allowed"})
                    return
                if allowed == "post" and method == "GET":
                    record_reject()
                    self._resp(405, {"ok": False, "error": "GET method not allowed"})
                    return
                    
            # ==================== 参数提取 ====================
            p = self._params(parsed)
            if p is None:
                record_reject()
                self.close_connection = True
                self._resp(413, {"ok": False, "error": "Payload Too Large"})
                return

            # ==================== 路由分发 ====================

            if path == "/web" and method == "GET":
                return self._handle_web_page()
            if path == admin_path and method == "GET":
                return self._handle_admin_page()
            if path.startswith("/assets/"):
                return self._handle_static_assets(path, "assets")
            if path.startswith("/static/"):
                return self._handle_static_assets(path, "static")
            if path == "/api/templates" and method in ("GET", "POST"):
                return self._handle_templates_list()

            if path.startswith("/api/") and (path.endswith("/send") or path == "/api/web_send"):
                return self._handle_send(path, method, p, client_ip)

            # Admin 路由统一入口与归一化
            is_admin_path = False
            if path == "/admin/api/keys":
                path = "/api/keys"
                is_admin_path = True
            elif path == "/api/keys" or path.startswith("/api/keys/") or path.startswith("/api/admin/"):
                is_admin_path = True

            if is_admin_path:
                return self._handle_admin_api(path, method, p, client_ip)

            # API 未命中扫描
            if is_api_req:
                record_danger(path, client_ip)

            self._resp(404, {"ok": False, "error": "not found"})

        except Exception as e:
            audit(f"ROUTE_ERR {type(e).__name__}: {repr(e)} path={self.path}")
            try:
                self._resp(500, {"ok": False, "error": "internal server error"})
            except Exception:
                pass

    def _handle_web_page(self):
        web_index = os.path.join(WEB_DIR, "index.html")
        if not os.path.exists(web_index):
            return self._html("<h1>Web page not found</h1>")

        with open(web_index, "r", encoding="utf-8") as f: 
            content = f.read()
            
        bg_flag = "true" if CFG.get("enable_custom_background", False) else "false"
        content = content.replace("{{ENABLE_BG}}", bg_flag)
        
        with _access_lock:
            access_snapshot = dict(_access_rules.get("routes", {}))
        access_json = json.dumps(access_snapshot, ensure_ascii=False).replace("<", "\\u003c")
        content = content.replace("{{ACCESS_MAP}}", access_json)
        
        return self._html(content)
        
    def _handle_admin_page(self):
        admin_file = os.path.join(WEB_DIR, "admin.html")
        if not os.path.exists(admin_file):
            return self._html("<h1>Admin page not found</h1>")

        with open(admin_file, "r", encoding="utf-8") as f: 
            content = f.read()
            
        bg_flag = "true" if CFG.get("enable_custom_background", False) else "false"
        content = content.replace("{{ENABLE_BG}}", bg_flag)
        
        with _access_lock:
            access_snapshot = dict(_access_rules.get("routes", {}))
        access_json = json.dumps(access_snapshot, ensure_ascii=False).replace("<", "\\u003c")
        content = content.replace("{{ACCESS_MAP}}", access_json)
        
        return self._html(content)

    def _handle_static_assets(self, path, prefix):
        file_name = path.split(f"/{prefix}/")[-1]
        # 允许子目录但禁止路径穿越
        if not re.match(r"^[a-zA-Z0-9_\-\./]+$", file_name) or ".." in file_name:
            return self._resp(400, {"ok": False, "error": "invalid filename"})
        
        base_dir = ASSETS_DIR if prefix == "assets" else STATIC_DIR
        file_path = os.path.join(base_dir, file_name)
        
        # 二次防穿越：realpath 校验(谁给点三次防穿越的东西 我不想系统密码漏给人家)
        real_path = os.path.realpath(file_path)
        if not real_path.startswith(os.path.realpath(base_dir) + os.sep):
            return self._resp(403, {"ok": False, "error": "forbidden"})
        
        if not os.path.exists(file_path) or not os.path.isfile(file_path):
            return self._resp(404, {"ok": False, "error": "not found"})
        
        mime_type, _ = mimetypes.guess_type(file_path)
        with open(file_path, "rb") as f:
            data = f.read()
        
        self.send_response(200)
        self.send_header("Content-Type", mime_type or "application/octet-stream")
        self.send_header("Content-Length", str(len(data)))
        
        # 开发阶段用缓存怎么死的都不知道
        self.send_header("Cache-Control", "no-cache, no-store, must-revalidate")
        self.send_header("Pragma", "no-cache")
        self.send_header("Expires", "0")
        
        self.end_headers()
        self.wfile.write(data)

    def _handle_templates_list(self):
        templates = []
        if os.path.exists(HTML_DIR):
            for d in os.listdir(HTML_DIR):
                t_dir = os.path.join(HTML_DIR, d)
                if os.path.isdir(t_dir):
                    reg_path = os.path.join(t_dir, "register.json")
                    if os.path.exists(reg_path):
                        try:
                            with open(reg_path, "r", encoding="utf-8") as f:
                                reg_data = json.load(f)
                            if reg_data.get("is_api_only", False):
                                continue
                            templates.append({
                                "id": d, "name": reg_data.get("name", d),
                                "fields": reg_data.get("fields", [])
                            })
                        except Exception as e:
                            audit(f"REGISTER_PARSE_ERR template={d} err={repr(e)}")
        return self._resp(200, {"ok": True, "templates": templates})

    def _handle_send(self, path, method, p, client_ip):
        is_web = (path == "/api/web_send")
        if is_web: 
            template_name = p.get("template", "v1")
        else:
            parts = path.strip("/").split("/")
            if len(parts) != 3: 
                record_reject()
                return self._resp(404, {"ok": False, "error": "bad path"})
            template_name = parts[1]

        if not re.match(r"^[a-zA-Z0-9_\-]+$", template_name):
            record_reject()
            return self._resp(400, {"ok": False, "error": "invalid template name"})

        k = p.get("KEY", "")
        key_obj = find_key(k)
        if not key_obj:
            audit(f"REJECT auth ip={client_ip}")
            record_reject()
            return self._resp(401, {"ok": False, "error": "unauthorized"})

        to_addr = p.get("TO", "").strip().replace('\r', '').replace('\n', '')
        if not re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", to_addr):
            record_reject()
            return self._resp(400, {"ok": False, "error": "invalid recipient email format"})

        RESERVED_KEYS = {"KEY", "TO", "template"}
        template_vars = {key: val for key, val in p.items() if key not in RESERVED_KEYS}

        dir_path = os.path.join(HTML_DIR, template_name)
        tmpl_cfg_path = os.path.join(dir_path, "config.json")
        if not os.path.exists(tmpl_cfg_path):
            record_reject()
            return self._resp(404, {"ok": False, "error": f"version '{template_name}' not found"})

        with open(tmpl_cfg_path, "r", encoding="utf-8") as f:
            tmpl_cfg = json.load(f)

        incoming_rules = tmpl_cfg.get("incoming", [])
        if isinstance(incoming_rules, list):
            for rule in incoming_rules:
                in_name = rule.get("incomingname")
                replace_str = rule.get("replace_string")
                
                if in_name in RESERVED_KEYS:
                    record_reject()
                    return self._resp(500, {"ok": False, "error": f"template config error: '{in_name}' is a reserved keyword"})
                if not in_name or not replace_str:
                    record_reject()
                    return self._resp(500, {"ok": False, "error": f"template config error: invalid incoming rule"})
                if in_name not in template_vars:
                    record_reject()
                    return self._resp(400, {"ok": False, "error": f"missing param: {in_name}"})

        acc_name = tmpl_cfg.get("account", "default")
        accounts_pool = CFG.get("accounts", {})
        if acc_name not in accounts_pool:
            record_reject()
            return self._resp(400, {"ok": False, "error": f"account '{acc_name}' not configured"})
        acc_cfg = accounts_pool[acc_name]

        passed, err_msg = check_rate_limit(client_ip, k)
        if not passed:
            record_reject()
            return self._resp(429, {"ok": False, "error": err_msg})

        if not semaphore.acquire(blocking=False):
            record_reject()
            return self._resp(503, {"ok": False, "error": "Server busy, please retry later"})

        is_temp = key_obj.get("is_temp", False)

        try: 
            executor.submit(
                async_send_task, 
                template_name, to_addr, template_vars, acc_cfg, client_ip, key_obj.get("id"), is_temp, tmpl_cfg
            )
        except Exception as e:
            semaphore.release()
            audit(f"EXECUTOR_SUBMIT_ERR {repr(e)} ip={client_ip}")
            record_reject()
            return self._resp(500, {"ok": False, "error": "server threadpool exception"})

        audit(f"ACCEPT tmpl={template_name} to={to_addr} key_id={key_obj.get('id')} ip={client_ip}")
        return self._resp(200, {"ok": True, "msg": "accepted"})

    def _handle_admin_api(self, path, method, p, client_ip):
        # 1. 统一鉴权前置
        admin_key = self.headers.get("X-Admin-Key", "")
        if not is_admin(admin_key):
            return self._resp(401, {"ok": False, "error": "admin unauthorized"})
        
        admin_obj = find_key(admin_key)
        ctx = {
            "p": p, 
            "client_ip": client_ip,
            "admin_id": admin_obj.get("id") if admin_obj else "INVALID"
        }
        
        # 2. 查表分发并校验 Method
        route_entry = _ADMIN_ROUTES.get(path)
        if not route_entry:
            return self._resp(404, {"ok": False, "error": "admin route not found"})
            
        handler_func, allowed_methods = route_entry
        if method not in allowed_methods:
            return self._resp(405, {"ok": False, "error": f"Method {method} not allowed"})
            
        return handler_func(self, ctx)


# ==================== Admin API 路由表 ====================
# 表项格式: path -> (handler_func, allowed_methods)
# 方法校验在分发入口统一完成，防止 GET 越权调用 POST 接口

def _admin_keys_list(h, ctx):
    data = load_keys()
    safe_keys = []
    for k in data["keys"]:
        k_copy = copy.deepcopy(k)
        raw_key = k_copy.get("key", "")
        if len(raw_key) > 10:
            k_copy["key"] = f"{raw_key[:6]}····{raw_key[-4:]}"
        elif raw_key:
            k_copy["key"] = "···"
        else:
            k_copy["key"] = "—"
        safe_keys.append(k_copy)
    return h._resp(200, {"ok": True, "keys": safe_keys})

def _admin_keys_create(h, ctx):
    p = ctx["p"]
    with _keys_lock:
        data = load_keys()
        new_id = max([key_obj["id"] for key_obj in data["keys"]], default=0) + 1
        new_key = secrets.token_urlsafe(32)
        perm = p.get("perm", "send")
        if perm not in ("send", "admin"): perm = "send"
        data["keys"].append({
            "id": new_id, "key": new_key, "status": "active", "perm": perm,
            "created": time.strftime("%Y-%m-%d %H:%M:%S"),
            "note": (p.get("note") or "").strip(),
        })
        save_keys(data)
        # save_keys 内部会刷新 _keys_cache，此处 data 仅作本次变更载体
    audit(f"KEY_CREATE id={new_id} perm={perm} note='{p.get('note', '')}' by_admin={ctx['admin_id']} ip={ctx['client_ip']}")
    return h._resp(200, {"ok": True, "id": new_id, "key": new_key, "perm": perm})

def _admin_keys_revoke(h, ctx):
    p = ctx["p"]
    target_id = p.get("id", "")
    found = False
    with _keys_lock:
        data = load_keys()
        for key_obj in data["keys"]:
            if str(key_obj["id"]) == str(target_id):
                key_obj["status"] = "revoked"
                found = True
                break
        if found: save_keys(data)
    if not found:
        return h._resp(404, {"ok": False, "error": "key not found"})
    audit(f"KEY_REVOKE id={target_id} by_admin={ctx['admin_id']} ip={ctx['client_ip']}")
    return h._resp(200, {"ok": True, "revoked_id": target_id})

def _admin_keys_perm(h, ctx):
    p = ctx["p"]
    target_id = p.get("id", "")
    new_perm = p.get("perm", "")
    if new_perm not in ("send", "admin"):
        return h._resp(400, {"ok": False, "error": "perm must be send or admin"})
    found = False
    with _keys_lock:
        data = load_keys()
        for key_obj in data["keys"]:
            if str(key_obj["id"]) == str(target_id):
                key_obj["perm"] = new_perm
                found = True
                break
        if found: save_keys(data)
    if not found:
        return h._resp(404, {"ok": False, "error": "key not found"})
    audit(f"KEY_PERM_CHANGE id={target_id} new_perm={new_perm} by_admin={ctx['admin_id']} ip={ctx['client_ip']}")
    return h._resp(200, {"ok": True, "id": target_id, "perm": new_perm})

def _parse_api_fields(raw_str):
    """统一解析 a:b,c:d 格式为 [{incomingname, replace_string}]"""
    incoming = []
    if raw_str:
        for item in raw_str.split(","):
            if ":" in item:
                p_name, rep_str = item.split(":", 1)
                incoming.append({"incomingname": p_name.strip(), "replace_string": rep_str.strip()})
    return incoming

def _admin_create_template(h, ctx):
    p = ctx["p"]
    t_id = p.get("id", "").strip()
    if not re.match(r"^[a-zA-Z0-9_\-]+$", t_id):
        return h._resp(400, {"ok": False, "error": "invalid template id"})
    
    t_name = p.get("name", "").strip()
    t_account = p.get("account", "default").strip()
    t_subject = p.get("subject", "").strip()
    t_html = p.get("html", "")
    is_web = str(p.get("is_web", "false")).lower() == "true"
    web_fields = p.get("web_fields", "").strip()

    t_dir = os.path.join(HTML_DIR, t_id)
    incoming = _parse_api_fields(p.get("api_fields", "").strip())

    if not os.path.exists(t_dir):
        os.makedirs(t_dir)
    elif not os.path.exists(os.path.join(t_dir, "config.json")) and not t_html:
        return h._resp(400, {"ok": False, "error": "template folder exists but missing config/html"})

    cfg_data = {"account": t_account, "subject": t_subject, "incoming": incoming}
    with open(os.path.join(t_dir, "config.json"), "w", encoding="utf-8") as f:
        json.dump(cfg_data, f, ensure_ascii=False, indent=4)

    if t_html:
        with open(os.path.join(t_dir, "content.html"), "w", encoding="utf-8") as f:
            f.write(t_html)

    reg_data = {"name": t_name or t_id, "is_api_only": not is_web, "fields": []}
    if is_web and web_fields:
        for item in web_fields.split(","):
            if ";" in item:
                disp, in_name = item.split(";", 1)
                reg_data["fields"].append({
                    "key": in_name.strip(), "label": disp.strip(),
                    "placeholder": f"请输入 {disp.strip()}", "type": "text"
                })
    with open(os.path.join(t_dir, "register.json"), "w", encoding="utf-8") as f:
        json.dump(reg_data, f, ensure_ascii=False, indent=4)

    audit(f"TEMPLATE_CREATE id={t_id} is_web={is_web} by_admin={ctx['admin_id']} ip={ctx['client_ip']}")
    return h._resp(200, {"ok": True, "msg": "template created/updated successfully"})

def _admin_update_template(h, ctx):
    p = ctx["p"]
    t_id = p.get("id", "").strip()
    if not re.match(r"^[a-zA-Z0-9_\-]+$", t_id):
        return h._resp(400, {"ok": False, "error": "invalid template id"})
    
    t_dir = os.path.join(HTML_DIR, t_id)
    cfg_path = os.path.join(t_dir, "config.json")
    reg_path = os.path.join(t_dir, "register.json")
    if not os.path.exists(t_dir) or not os.path.exists(cfg_path):
        return h._resp(404, {"ok": False, "error": f"template '{t_id}' does not exist"})

    reg_data = {}
    if os.path.exists(reg_path):
        try:
            with open(reg_path, "r", encoding="utf-8") as f:
                reg_data = json.load(f)
        except Exception: pass

    if "name" not in reg_data: reg_data["name"] = t_id
    if "is_api_only" not in reg_data: reg_data["is_api_only"] = True
    if "fields" not in reg_data: reg_data["fields"] = []

    if "name" in p and p["name"]: reg_data["name"] = p["name"]
    if "web_fields" in p and p["web_fields"]:
        fields_ui = []
        for item in p["web_fields"].split(","):
            if ";" in item:
                disp, in_name = item.split(";", 1)
                fields_ui.append({
                    "key": in_name.strip(), "label": disp.strip(),
                    "placeholder": f"请输入 {disp.strip()}", "type": "text"
                })
        reg_data["fields"] = fields_ui
        reg_data["is_api_only"] = False 

    with open(reg_path, "w", encoding="utf-8") as f:
        json.dump(reg_data, f, ensure_ascii=False, indent=4)

    audit(f"TEMPLATE_UPDATE id={t_id} by_admin={ctx['admin_id']} ip={ctx['client_ip']}")
    return h._resp(200, {"ok": True, "msg": "template info updated successfully"})

def _admin_toggle_template_web(h, ctx):
    p = ctx["p"]
    t_id = p.get("id", "").strip()
    action = p.get("action", "").strip().lower()
    if not re.match(r"^[a-zA-Z0-9_\-]+$", t_id) or action not in ("enable", "disable"):
        return h._resp(400, {"ok": False, "error": "invalid template id or action"})

    t_dir = os.path.join(HTML_DIR, t_id)
    cfg_path = os.path.join(t_dir, "config.json")
    reg_path = os.path.join(t_dir, "register.json")
    if not os.path.exists(t_dir) or not os.path.exists(cfg_path):
        return h._resp(404, {"ok": False, "error": f"template '{t_id}' not found"})

    reg_data = {}
    if os.path.exists(reg_path):
        try:
            with open(reg_path, "r", encoding="utf-8") as f:
                reg_data = json.load(f)
        except Exception: pass

    if "name" not in reg_data: reg_data["name"] = t_id
    if "fields" not in reg_data: reg_data["fields"] = []
    reg_data["is_api_only"] = (action == "disable")

    with open(reg_path, "w", encoding="utf-8") as f:
        json.dump(reg_data, f, ensure_ascii=False, indent=4)

    audit(f"TEMPLATE_TOGGLE id={t_id} action={action} by_admin={ctx['admin_id']} ip={ctx['client_ip']}")
    return h._resp(200, {"ok": True, "msg": f"template web {action}d"})

def _admin_system_info(h, ctx):
    uptime_sec = time.time() - START_TIME
    hours, remainder = divmod(int(uptime_sec), 3600)
    minutes, seconds = divmod(remainder, 60)
    
    mem_used_mb, mem_total_mb = 0, 0
    try:
        with open("/proc/meminfo", "r") as f:
            meminfo = f.read()
            m_total = re.search(r"MemTotal:\s+(\d+)", meminfo)
            m_avail = re.search(r"MemAvailable:\s+(\d+)", meminfo)
            if m_total and m_avail:
                mem_total_mb = round(int(m_total.group(1)) / 1024)
                mem_used_mb = round((int(m_total.group(1)) - int(m_avail.group(1))) / 1024)
    except Exception: pass

    with _stats_lock:
        total_success, total_fail = STATS_SUCCESS, STATS_FAILED
        total_reject = STATS_REJECTED
        now = time.time()
        recent_rejects = len([t for t in _rejected_timestamps if t > now - 60])

    running_tasks = (max_workers * 2) - semaphore._value
    tmpl_count = len([d for d in os.listdir(HTML_DIR) if os.path.isdir(os.path.join(HTML_DIR, d))]) if os.path.exists(HTML_DIR) else 0
    acc_count = len(CFG.get("accounts", {}))

    # 运维指标外露
    danger_metrics = {
        "hits_keys": len(_danger_hits),
        "active_threats": len(_active_threats),
        "alerted_set_size": len(_alerted_set),
        "global_high": _global_threat_state.get("high_count", 0),
        "global_critical": _global_threat_state.get("critical_count", 0)
    }

    smtp_modes = {}
    for name, acc in CFG.get("accounts", {}).items():
        smtp_modes[name] = acc.get("smtp_mode", "ssl")

    return h._resp(200, {
        "ok": True, "uptime": f"{hours}h {minutes}m {seconds}s", "running_tasks": running_tasks,
        "total_success": total_success, "total_fail": total_fail, "total_reject": total_reject,
        "reject_1m": recent_rejects, "template_count": tmpl_count, "account_count": acc_count,
        "mem_used_mb": mem_used_mb, "mem_total_mb": mem_total_mb,
        "danger_metrics": danger_metrics,
        "smtp_modes": smtp_modes  # 新增字段
    })

def _admin_logs(h, ctx):
    p = ctx["p"]
    lines_str = str(p.get("lines", "50")).strip()
    if not lines_str.isdigit(): return h._resp(400, {"ok": False, "error": "lines must be a positive integer"})
    limit = int(lines_str)
    if limit < 1 or limit > 500: return h._resp(400, {"ok": False, "error": "lines limit must be between 1 and 500"})
    
    log_path = LATEST_LOG
    if not os.path.exists(log_path): return h._resp(200, {"ok": True, "logs": "Log file empty or not found."})
    
    try:
        with open(log_path, "rb") as f:
            f.seek(0, 2)
            end = f.tell()
            if end == 0: return h._resp(200, {"ok": True, "logs": "Log file is empty."})
            
            size, block_size, lines_found, buffer = end, 4096, 0, b""
            while size > 0 and lines_found <= limit:
                size = max(0, size - block_size)
                f.seek(size)
                chunk = f.read(min(block_size, end - size))
                buffer = chunk + buffer
                lines_found = buffer.count(b"\n")

            decoded = buffer.decode("utf-8", errors="ignore")
            last_lines = decoded.splitlines()[-limit:]
            logs_str = "\n".join(last_lines)

        return h._resp(200, {"ok": True, "logs": logs_str})
    except Exception as e:
        return h._resp(500, {"ok": False, "error": f"read log error: {e}"})

def _admin_list_templates(h, ctx):
    all_tmpls = []
    if os.path.exists(HTML_DIR):
        for d in os.listdir(HTML_DIR):
            t_dir = os.path.join(HTML_DIR, d)
            if os.path.isdir(t_dir):
                reg_path = os.path.join(t_dir, "register.json")
                is_web = False
                name = d
                if os.path.exists(reg_path):
                    try:
                        with open(reg_path, "r", encoding="utf-8") as f:
                            reg_data = json.load(f)
                            name = reg_data.get("name", d)
                            is_web = not reg_data.get("is_api_only", False)
                    except Exception: pass
                all_tmpls.append({"id": d, "name": name, "is_web": is_web})
    return h._resp(200, {"ok": True, "templates": all_tmpls})

# 路由表：注册允许的方法，删除冗余的 /admin/api/keys
_ADMIN_ROUTES = {
    "/api/keys": (_admin_keys_list, ["GET", "POST"]),
    "/api/keys/create": (_admin_keys_create, ["POST"]),
    "/api/keys/revoke": (_admin_keys_revoke, ["POST"]),
    "/api/keys/perm": (_admin_keys_perm, ["POST"]),
    "/api/admin/create_template": (_admin_create_template, ["POST"]),
    "/api/admin/update_template": (_admin_update_template, ["POST"]),
    "/api/admin/toggle_template_web": (_admin_toggle_template_web, ["POST"]),
    "/api/admin/system_info": (_admin_system_info, ["GET", "POST"]),
    "/api/admin/logs": (_admin_logs, ["GET", "POST"]),
    "/api/admin/list_templates": (_admin_list_templates, ["GET", "POST"]),
}

# ==================== 多线程服务与启动 ====================
class ThreadingHTTPServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True

http_server_instance = None
https_server_instance = None

def run_http_server():
    global http_server_instance
    port = CFG.get("listen_port", 8088)
    audit(f"START HTTP Server on :{port}")
    http_server_instance = ThreadingHTTPServer(("0.0.0.0", port), Handler)
    http_server_instance.serve_forever()

def run_https_server():
    global https_server_instance
    try:
        port = CFG.get("https_port", 8443)
        cert_file = CFG["certfile"]
        key_file = CFG["keyfile"]
        if not os.path.isabs(cert_file): cert_file = os.path.join(BASE_DIR, cert_file)
        if not os.path.isabs(key_file): key_file = os.path.join(BASE_DIR, key_file)

        https_server_instance = ThreadingHTTPServer(("0.0.0.0", port), Handler)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(certfile=cert_file, keyfile=key_file)
        https_server_instance.socket = ctx.wrap_socket(https_server_instance.socket, server_side=True)
        
        audit(f"START HTTPS Server on :{port}")
        https_server_instance.serve_forever()
    except Exception as e:
        audit(f"HTTPS_START_ERR {repr(e)}")

def _do_shutdown():
    print("[*] 正在关闭底层网络监听端口...")
    for srv in [http_server_instance, https_server_instance]:
        if srv:
            try:
                srv.shutdown()
                srv.server_close()
            except Exception:
                pass

def graceful_shutdown(signum, frame):
    print("\n[*] 收到终止信号，正在关闭...")
    
    # 启动子线程去关网络端口，因为 srv.shutdown() 是阻塞的
    threading.Thread(target=_do_shutdown, daemon=True).start()
    
    # 如果全局状态持久化线程还在，给它 2 秒收尾
    global _persist_thread
    if "_persist_thread" in globals() and _persist_thread and _persist_thread.is_alive():
        _persist_thread.join(timeout=2.0)
        print("[*] 已等待全局状态落盘")
        
    running_tasks = 0
    for i in range(3, 0, -1):
        time.sleep(1)
        running_tasks = (max_workers * 2) - semaphore._value
        if running_tasks > 0:
            print(f"[~] 正在等待 {running_tasks} 个发信任务完成... ({i}s)")
        else:
            print("[+] 邮件队列已清空")
            break
            
    if running_tasks > 0:
        print(f"[?] 即将有 {running_tasks} 个发信任务被丢弃")
                     
    print("[+] 服务器已安全关闭，进程退出")
    sys.exit(0)

signal.signal(signal.SIGINT, graceful_shutdown)
signal.signal(signal.SIGTERM, graceful_shutdown)

if __name__ == "__main__":
    # 加载全局威胁状态
    _load_global_state()
    
    # 启动持久化线程
    def _persist_global_state():
        while True:
            time.sleep(10)
            _save_global_state()
            
    _persist_thread = threading.Thread(target=_persist_global_state, daemon=True)
    _persist_thread.start()

    threading.Thread(target=_heartbeat, daemon=True).start()
    threading.Thread(target=_wait_for_tick, daemon=True).start()

    time.sleep(1.1) #多睡0.1秒
    
    init_admin_key()
    
    # ==================== 宏观依赖强管控 ====================
    http_api_on = CFG.get("enable_api_http", True)
    http_web_on = CFG.get("enable_web_http", False)
    
    if not http_api_on:
        if http_web_on:
            print("\n[!] 警告: HTTP API 未开启，HTTP Web 无法独立运行，已强制关闭 HTTP Web")
        http_web_on = False
        
    need_http = http_api_on or http_web_on

    https_api_on = CFG.get("enable_api_https", True)
    https_web_on = CFG.get("enable_web_https", True)
    
    if not https_api_on:
        if https_web_on:
            print("\n[!] 警告: HTTPS API 未开启，HTTPS Web 无法独立运行，已强制关闭 HTTPS Web")
        https_web_on = False
        
    need_https = https_api_on or https_web_on
    # ======================================================

    if not need_http and not need_https:
        print("\n" + "="*45)
        print("服务启动中止：正在进行光合作用")
        print("="*45)
        print("[Server]：开摆咯～")
        print("(检测到 HTTP 和 HTTPS 的 API 与 Web 全部未启动)")
        print("请检查config.json中的enable_api/enable_web配置")
        print("="*45 + "\n")
    else:
        print("\n" + "="*45)
        print("EphemeraMailer 启动前依赖检查")
        print("="*45)
        
        if need_http:
            print(f"  [HTTP]  启动 (API: {'✅ 开' if http_api_on else '❌ 关'} | Web: {'✅ 开' if http_web_on else '❌ 关'})")
        else:
            print("  [HTTP]  ❌ 完全关闭 (API和Web都未开启)")

        if need_https:
            print(f"  [HTTPS] 启动 (API: {'✅ 开' if https_api_on else '❌ 关'} | Web: {'✅ 开' if https_web_on else '❌ 关'})")
        else:
            print("  [HTTPS] ❌ 完全关闭 (API和Web都未开启)")
        
        print("="*45 + "\n")

        # 物理绑定，强制按顺序输出
        if need_https:
            threading.Thread(target=run_https_server, daemon=True).start()
            time.sleep(0.05) 
        if need_http:
            threading.Thread(target=run_http_server, daemon=True).start()
            time.sleep(0.05) 

        print("\n" + "="*45)
        print("服务已就绪 等待请求... (按 Ctrl+C 退出)")
        print("="*45 + "\n")

    main_event = threading.Event()
    try:
        main_event.wait()
    except KeyboardInterrupt:
        graceful_shutdown(None, None)
