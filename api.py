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
LOG_DIR = os.path.join(BASE_DIR, "logs")
LATEST_LOG = os.path.join(LOG_DIR, "latest.log")

_keys_cache = None
_keys_lock = threading.RLock()
_temp_key_lock = threading.Lock()

# ==================== 核心启动时间 ====================
START_TIME = time.time() 

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
        listen_port = int(input("1. HTTP API/Web 监听端口 [默认 8088]: ").strip() or 8088)
        https_port = int(input("2. HTTPS API/Web 监听端口 [默认 8443]: ").strip() or 8443)
        
        enable_get = input("3. 是否允许 GET 请求发信? (y/n) [默认 n]: ").strip().lower() == "y"
        enable_web = input("4. 是否开启 HTTPS Web 发信页? (y/n) [默认 y]: ").strip().lower() != "n"
        
        certfile = "certs/server.crt"
        keyfile = "certs/server.key"
        if enable_web:
            certfile = input("   - 证书路径 [默认 certs/server.crt]: ").strip() or "certs/server.crt"
            keyfile = input("   - 私钥路径 [默认 certs/server.key]: ").strip() or "certs/server.key"

        admin_path = input("5. 管理后台隐藏路径 [默认 /my_secret_admin]: ").strip() or "/my_secret_admin"
        
        print("\n--- 发信账户配置 ---")
        smtp_host = input("6. SMTP 服务器地址 [默认 127.0.0.1]: ").strip() or "127.0.0.1"
        smtp_port = int(input("   - SMTP 端口 [默认 465]: ").strip() or 465)
        
        mode_in = input("   - 连接模式 (ssl/starttls/plain) [默认 ssl]: ").strip().lower()
        smtp_mode = mode_in if mode_in in ("starttls", "plain") else "ssl"
        
        smtp_user = input("   - SMTP 账号: ").strip()
        smtp_pass = input("   - SMTP 密码: ").strip()
        from_name = input("   - 发件人显示名称 [默认 System Admin]: ").strip() or "System Admin"
        from_addr = input("   - 发件人邮箱: ").strip() or smtp_user
        helo_host = input("   - HELO 域名 [默认 localhost]: ").strip() or "localhost"
        if "@" in helo_host or "." not in helo_host:
            helo_host = "localhost"
            
        ignore_ssl = input("   - 是否忽略 SMTP SSL 证书校验? (y/n) [默认 n]: ").strip().lower() == "y"

        config = {
            "listen_port": listen_port,
            "https_port": https_port,
            "enable_get": enable_get,
            "enable_web_http": False,
            "enable_api_http": True,
            "enable_web_https": enable_web,
            "enable_api_https": True,
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

        do_test = input("👉 是否现在生成测试链接以验证配置是否正确？ (y/n) [默认 y]: ").strip().lower() != "n"
        if do_test:
            print("\n" + "-"*60)
            test_to = input(f"📧 请输入用于接收测试邮件的收件邮箱 [默认发送到发件人自己 {from_addr}]: ").strip()
            if not test_to:
                test_to = from_addr
                
            local_ip = get_local_ip()
            public_ip = get_public_ip()
            
            test_code = str(secrets.randbelow(9000) + 1000)
            proto = "https" if enable_web else "http"
            port = https_port if enable_web else listen_port
            
            if not enable_get:
                print(f"\n⚠️  您禁用了 GET 请求，无法直接通过浏览器链接测试。")
                print(f"✅ 若需验证，请稍后启动服务后使用 POST 测试")
            else:
                print(f"\n✅ 若配置正确，收件箱 {test_to} 应当收到一封验证码为 {test_code} 的邮件。")
                print("\n🌐 公网访问测试 (复制到浏览器):")
                print(f"   {proto}://{public_ip}:{port}/api/v1/send?TO={test_to}&KEY={temp_test_key}&code={test_code}")
                print("\n🏠 内网访问测试 (复制到浏览器):")
                print(f"   {proto}://{local_ip}:{port}/api/v1/send?TO={test_to}&KEY={temp_test_key}&code={test_code}")
            
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
    if not os.path.exists(CONFIG_PATH):
        init_wizard()
        
    if not os.path.exists(KEYS_PATH):
        with open(KEYS_PATH, "w", encoding="utf-8") as f:
            json.dump({"keys": []}, f, ensure_ascii=False, indent=4)
        os.chmod(KEYS_PATH, 0o600)

    if not os.path.exists(WEB_DIR): os.makedirs(WEB_DIR)
    if not os.path.exists(ASSETS_DIR): os.makedirs(ASSETS_DIR)
    
    v1_dir = os.path.join(HTML_DIR, "v1")
    if not os.path.exists(v1_dir) or not os.listdir(HTML_DIR):
        if not os.path.exists(v1_dir): os.makedirs(v1_dir)
        with open(os.path.join(v1_dir, "config.json"), "w", encoding="utf-8") as f:
            json.dump(DEFAULT_HTML_CONFIG, f, ensure_ascii=False, indent=4)
        with open(os.path.join(v1_dir, "content.html"), "w", encoding="utf-8") as f:
            f.write(DEFAULT_HTML_CONTENT)
        print("[*] 已自动生成基础邮件模板 html/v1/")

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

# ==================== 轻量限流器 ====================
_rate_hits_ip = defaultdict(list)
_rate_hits_key = defaultdict(list)
_rate_lock = threading.Lock()

def clean_rate_dicts():
    while True:
        time.sleep(60)
        now = time.time()
        with _rate_lock:
            for d in [_rate_hits_ip, _rate_hits_key]:
                for k in list(d.keys()):
                    d[k] = [t for t in d[k] if t > now - 60]
                    if not d[k]:
                        del d[k]
        with _stats_lock:
            while _rejected_timestamps and _rejected_timestamps[0] < now - 60:
                _rejected_timestamps.popleft()

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

# ==================== 内存缓存 Keys ====================
def load_keys():
    global _keys_cache
    with _keys_lock: 
        if _keys_cache is not None:
            return copy.deepcopy(_keys_cache)
        try:
            with open(KEYS_PATH, "r", encoding="utf-8") as f:
                data = json.load(f)
                if "keys" not in data:
                    data["keys"] = []
                _keys_cache = data
                return copy.deepcopy(data)
        except Exception as e:
            audit(f"LOAD_KEYS_ERR {repr(e)}")
            return {"keys": []}

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
    for key_obj in load_keys()["keys"]:
        if key_obj["status"] == "active" and secrets.compare_digest(key_obj["key"], k):
            return key_obj
    return None

def is_admin(k):
    key_obj = find_key(k)
    return key_obj is not None and key_obj.get("perm", "send") == "admin"

def audit(msg):
    safe_msg = str(msg).replace('\n', ' ').replace('\r', '')
    with _log_lock:
        try:
            # 加上颜色前缀，终端里看起来会非常清爽
            print(f"\033[90m[{time.strftime('%Y-%m-%d %H:%M:%S')}]\033[0m {safe_msg}")
            
            if not os.path.exists(LOG_DIR):
                os.makedirs(LOG_DIR)
                
            if os.path.exists(LATEST_LOG) and os.path.getsize(LATEST_LOG) > 10 * 1024 * 1024:
                archive_name = f"history_{time.strftime('%Y%m%d_%H%M%S')}.log"
                archive_path = os.path.join(LOG_DIR, archive_name)
                os.rename(LATEST_LOG, archive_path)
                
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
        
        if smtp_mode == "plain":
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
        else:
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
        
        semaphore.release()

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
        # 1. 从 URL 提取参数
        for k, v in urllib.parse.parse_qs(parsed.query, keep_blank_values=True).items():
            d[k] = v[0]
            
        # ==================== 防请求走私 (HTTP Smuggling) ====================
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
                
                # 优先 JSON 解析
                if "application/json" in content_type:
                    try:
                        body = json.loads(raw.decode("utf-8"))
                        if isinstance(body, dict):
                            d.update(body)
                    except Exception:
                        pass
                # 兼容表单
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
            # ========================================================

            p = self._params(parsed)
            if p is None:
                record_reject()
                self.close_connection = True
                self._resp(413, {"ok": False, "error": "Payload Too Large"})
                return

            # ================= 页面路由 (仅限 GET) =================
            if path == "/web" and method == "GET":
                web_index = os.path.join(WEB_DIR, "index.html")
                if os.path.exists(web_index):
                    with open(web_index, "r", encoding="utf-8") as f: 
                        html = f.read()
                    bg_flag = "true" if CFG.get("enable_custom_background", False) else "false"
                    html = html.replace("{{ENABLE_BG}}", bg_flag)
                    self._html(html)
                else: self._html("<h1>Web page not found</h1>")
                return

            if path == admin_path and method == "GET":
                admin_file = os.path.join(WEB_DIR, "admin.html")
                if os.path.exists(admin_file):
                    with open(admin_file, "r", encoding="utf-8") as f: 
                        html = f.read()
                    bg_flag = "true" if CFG.get("enable_custom_background", False) else "false"
                    html = html.replace("{{ENABLE_BG}}", bg_flag)
                    self._html(html)
                else: self._html("<h1>Admin page not found</h1>")
                return

            # ================= 静态资源目录 =================
            if path.startswith("/assets/"):
                file_name = path.split("/assets/")[-1]
                if not re.match(r"^[a-zA-Z0-9_\-\.]+$", file_name):
                    self._resp(400, {"ok": False, "error": "invalid filename"})
                    return
                
                file_path = os.path.join(ASSETS_DIR, file_name)
                if not os.path.exists(file_path):
                    self._resp(404, {"ok": False, "error": "asset not found"})
                    return
                
                mime_type, _ = mimetypes.guess_type(file_path)
                
                with open(file_path, "rb") as f:
                    img_data = f.read()
                    
                self.send_response(200)
                self.send_header("Content-Type", mime_type or "application/octet-stream")
                self.send_header("Content-Length", str(len(img_data)))
                self.send_header("Cache-Control", "public, max-age=86400")
                self.end_headers()
                self.wfile.write(img_data)
                return

            # ================= 供前端拉取模板注册表 =================
            if path == "/api/templates" and method == "GET":
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
                                        "id": d,
                                        "name": reg_data.get("name", d),
                                        "fields": reg_data.get("fields", [])
                                    })
                                except Exception as e:
                                    audit(f"REGISTER_PARSE_ERR template={d} err={repr(e)}")
                self._resp(200, {"ok": True, "templates": templates})
                return

            # ================= 动态模板发信 =================
            if path.startswith("/api/") and (path.endswith("/send") or path == "/api/web_send"):
                is_web = (path == "/api/web_send")
                if method == "GET" and not is_web and not CFG.get("enable_get", False):
                    record_reject()
                    self._resp(403, {"ok": False, "error": "GET send is disabled"})
                    return

                if is_web: template_name = p.get("template", "v1")
                else:
                    parts = path.strip("/").split("/")
                    if len(parts) != 3: 
                        record_reject()
                        return self._resp(404, {"ok": False, "error": "bad path"})
                    template_name = parts[1]

                if not re.match(r"^[a-zA-Z0-9_\-]+$", template_name):
                    record_reject()
                    self._resp(400, {"ok": False, "error": "invalid template name"})
                    return

                k = p.get("KEY", "") # 移除遗留 k
                key_obj = find_key(k)
                if not key_obj:
                    audit(f"REJECT auth ip={client_ip}")
                    record_reject()
                    self._resp(401, {"ok": False, "error": "unauthorized"})
                    return

                to_addr = p.get("TO", "").strip() # 移除遗留 s
                to_addr = to_addr.replace('\r', '').replace('\n', '')
                if not re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", to_addr):
                    record_reject()
                    self._resp(400, {"ok": False, "error": "invalid recipient email format"})
                    return

                dir_path = os.path.join(HTML_DIR, template_name)
                tmpl_cfg_path = os.path.join(dir_path, "config.json")
                if not os.path.exists(tmpl_cfg_path):
                    record_reject()
                    self._resp(404, {"ok": False, "error": f"version '{template_name}' not found"})
                    return

                with open(tmpl_cfg_path, "r", encoding="utf-8") as f:
                    tmpl_cfg = json.load(f)

                incoming_rules = tmpl_cfg.get("incoming", [])
                if isinstance(incoming_rules, list):
                    RESERVED_KEYS = {"KEY", "TO", "template"}
                    
                    for rule in incoming_rules:
                        in_name = rule.get("incomingname")
                        replace_str = rule.get("replace_string")
                        
                        if in_name in RESERVED_KEYS:
                            record_reject()
                            self._resp(500, {"ok": False, "error": f"template config error: '{in_name}' is a reserved keyword"})
                            return
                        
                        if not in_name or not replace_str:
                            record_reject()
                            self._resp(500, {"ok": False, "error": f"template config error: invalid incoming rule"})
                            return
                        if in_name and in_name not in p:
                            record_reject()
                            self._resp(400, {"ok": False, "error": f"missing param: {in_name}"})
                            return

                acc_name = tmpl_cfg.get("account", "default")
                accounts_pool = CFG.get("accounts", {})
                if acc_name not in accounts_pool:
                    record_reject()
                    self._resp(400, {"ok": False, "error": f"account '{acc_name}' not configured"})
                    return
                acc_cfg = accounts_pool[acc_name]

                passed, err_msg = check_rate_limit(client_ip, k)
                if not passed:
                    record_reject()
                    self._resp(429, {"ok": False, "error": err_msg})
                    return

                if not semaphore.acquire(blocking=False):
                    record_reject()
                    self._resp(503, {"ok": False, "error": "Server busy, please retry later"})
                    return

                is_temp = key_obj.get("is_temp", False)

                try: 
                    executor.submit(
                        async_send_task, 
                        template_name, to_addr, p, acc_cfg, client_ip, key_obj.get("id"), is_temp, tmpl_cfg
                    )
                except Exception as e:
                    semaphore.release()
                    audit(f"EXECUTOR_SUBMIT_ERR {repr(e)} ip={client_ip}")
                    record_reject()
                    self._resp(500, {"ok": False, "error": "server threadpool exception"})
                    return

                audit(f"ACCEPT tmpl={template_name} to={to_addr} key_id={key_obj.get('id')} ip={client_ip}")
                self._resp(200, {"ok": True, "msg": "accepted"})
                return

            # ================= Admin API =================
            admin_key = self.headers.get("X-Admin-Key", "")
            
            admin_obj = find_key(admin_key)
            admin_id = admin_obj.get("id") if admin_obj else "INVALID"

            if path in ("/api/keys", "/admin/api/keys"):
                if not is_admin(admin_key):
                    self._resp(401, {"ok": False, "error": "admin unauthorized"})
                    return
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

                self._resp(200, {"ok": True, "keys": safe_keys})
                return
                
            if path == "/api/keys/create":
                if not is_admin(admin_key):
                    self._resp(401, {"ok": False, "error": "admin unauthorized"})
                    return
                
                with _keys_lock:
                    data = load_keys()
                    new_id = max([key_obj["id"] for key_obj in data["keys"]], default=0) + 1
                    new_key = secrets.token_urlsafe(32)
                    perm = p.get("perm", "send")
                    if perm not in ("send", "admin"): perm = "send"
                    data["keys"].append({
                        "id": new_id,
                        "key": new_key,
                        "status": "active",
                        "perm": perm,
                        "created": time.strftime("%Y-%m-%d %H:%M:%S"),
                        "note": (p.get("note") or "").strip(),
                    })
                    save_keys(data)
                
                audit(f"KEY_CREATE id={new_id} perm={perm} note='{p.get('note', '')}' by_admin={admin_id} ip={client_ip}")
                self._resp(200, {"ok": True, "id": new_id, "key": new_key, "perm": perm})
                return
                
            if path == "/api/keys/revoke":
                if not is_admin(admin_key):
                    self._resp(401, {"ok": False, "error": "admin unauthorized"})
                    return
                
                target_id = p.get("id", "")
                found = False
                
                with _keys_lock:
                    data = load_keys()
                    for key_obj in data["keys"]:
                        if str(key_obj["id"]) == str(target_id):
                            key_obj["status"] = "revoked"
                            found = True
                            break
                    if found:
                        save_keys(data)
                
                if not found:
                    self._resp(404, {"ok": False, "error": "key not found"})
                    return
                audit(f"KEY_REVOKE id={target_id} by_admin={admin_id} ip={client_ip}")
                self._resp(200, {"ok": True, "revoked_id": target_id})
                return
                
            if path == "/api/keys/perm":
                if not is_admin(admin_key):
                    self._resp(401, {"ok": False, "error": "admin unauthorized"})
                    return
                
                target_id = p.get("id", "")
                new_perm = p.get("perm", "")
                if new_perm not in ("send", "admin"):
                    self._resp(400, {"ok": False, "error": "perm must be send or admin"})
                    return
                
                found = False
                with _keys_lock:
                    data = load_keys()
                    for key_obj in data["keys"]:
                        if str(key_obj["id"]) == str(target_id):
                            key_obj["perm"] = new_perm
                            found = True
                            break
                    if found:
                        save_keys(data)
                        
                if not found:
                    self._resp(404, {"ok": False, "error": "key not found"})
                    return
                audit(f"KEY_PERM_CHANGE id={target_id} new_perm={new_perm} by_admin={admin_id} ip={client_ip}")
                self._resp(200, {"ok": True, "id": target_id, "perm": new_perm})
                return

            # ================= Admin：创建新模板 =================
            if path == "/api/admin/create_template" and method == "POST":
                if not is_admin(admin_key):
                    self._resp(401, {"ok": False, "error": "admin unauthorized"})
                    return
                
                t_id = p.get("id", "").strip()
                t_name = p.get("name", "").strip()
                t_account = p.get("account", "default").strip()
                t_subject = p.get("subject", "").strip()
                t_html = p.get("html", "")
                
                is_web = str(p.get("is_web", "false")).lower() == "true"
                web_fields = p.get("web_fields", "").strip()
                
                if not re.match(r"^[a-zA-Z0-9_\-]+$", t_id):
                    self._resp(400, {"ok": False, "error": "invalid template id"})
                    return

                t_dir = os.path.join(HTML_DIR, t_id)

                incoming = []
                api_fields_raw = p.get("api_fields", "").strip()
                if api_fields_raw:
                    for item in api_fields_raw.split(","):
                        if ":" in item:
                            p_name, rep_str = item.split(":", 1)
                            incoming.append({"incomingname": p_name.strip(), "replace_string": rep_str.strip()})

                if not os.path.exists(t_dir):
                    os.makedirs(t_dir)
                elif not os.path.exists(os.path.join(t_dir, "config.json")) and not t_html:
                    self._resp(400, {"ok": False, "error": "template folder exists but missing config/html"})
                    return

                cfg_data = {
                    "account": t_account,
                    "subject": t_subject,
                    "incoming": incoming
                }
                with open(os.path.join(t_dir, "config.json"), "w", encoding="utf-8") as f:
                    json.dump(cfg_data, f, ensure_ascii=False, indent=4)

                if t_html:
                    with open(os.path.join(t_dir, "content.html"), "w", encoding="utf-8") as f:
                        f.write(t_html)

                reg_data = {
                    "name": t_name or t_id,
                    "is_api_only": not is_web,
                    "fields": []
                }
                
                if is_web and web_fields:
                    for item in web_fields.split(","):
                        if ";" in item:
                            disp, in_name = item.split(";", 1)
                            reg_data["fields"].append({
                                "key": in_name.strip(),
                                "label": disp.strip(),
                                "placeholder": f"请输入 {disp.strip()}",
                                "type": "text"
                            })
                
                with open(os.path.join(t_dir, "register.json"), "w", encoding="utf-8") as f:
                    json.dump(reg_data, f, ensure_ascii=False, indent=4)

                audit(f"TEMPLATE_CREATE id={t_id} is_web={is_web} by_admin={admin_id} ip={client_ip}")
                self._resp(200, {"ok": True, "msg": "template created/updated successfully"})
                return

            # ================= Admin：增量更新模板 =================
            if path == "/api/admin/update_template" and method == "POST":
                if not is_admin(admin_key):
                    self._resp(401, {"ok": False, "error": "admin unauthorized"})
                    return
                
                t_id = p.get("id", "").strip()
                if not re.match(r"^[a-zA-Z0-9_\-]+$", t_id):
                    self._resp(400, {"ok": False, "error": "invalid template id"})
                    return

                t_dir = os.path.join(HTML_DIR, t_id)
                cfg_path = os.path.join(t_dir, "config.json")
                reg_path = os.path.join(t_dir, "register.json")

                if not os.path.exists(t_dir) or not os.path.exists(cfg_path):
                    self._resp(404, {"ok": False, "error": f"template '{t_id}' does not exist"})
                    return

                reg_data = {}
                if os.path.exists(reg_path):
                    try:
                        with open(reg_path, "r", encoding="utf-8") as f:
                            reg_data = json.load(f)
                    except Exception:
                        pass

                if "name" not in reg_data: reg_data["name"] = t_id
                if "is_api_only" not in reg_data: reg_data["is_api_only"] = True
                if "fields" not in reg_data: reg_data["fields"] = []

                if "name" in p and p["name"]:
                    reg_data["name"] = p["name"]
                
                if "web_fields" in p and p["web_fields"]:
                    fields_ui = []
                    for item in p["web_fields"].split(","):
                        if ";" in item:
                            disp, in_name = item.split(";", 1)
                            fields_ui.append({
                                "key": in_name.strip(),
                                "label": disp.strip(),
                                "placeholder": f"请输入 {disp.strip()}",
                                "type": "text"
                            })
                    reg_data["fields"] = fields_ui
                    reg_data["is_api_only"] = False 

                with open(reg_path, "w", encoding="utf-8") as f:
                    json.dump(reg_data, f, ensure_ascii=False, indent=4)

                audit(f"TEMPLATE_UPDATE id={t_id} by_admin={admin_id} ip={client_ip}")
                self._resp(200, {"ok": True, "msg": "template info updated successfully"})
                return

            # ================= Admin：切换 Web 启用/禁用 =================
            if path == "/api/admin/toggle_template_web" and method == "POST":
                if not is_admin(admin_key):
                    self._resp(401, {"ok": False, "error": "admin unauthorized"})
                    return
                
                t_id = p.get("id", "").strip()
                action = p.get("action", "").strip().lower()
                
                if not re.match(r"^[a-zA-Z0-9_\-]+$", t_id):
                    self._resp(400, {"ok": False, "error": "invalid template id"})
                    return
                
                if action not in ("enable", "disable"):
                    self._resp(400, {"ok": False, "error": "invalid action"})
                    return

                t_dir = os.path.join(HTML_DIR, t_id)
                cfg_path = os.path.join(t_dir, "config.json")
                reg_path = os.path.join(t_dir, "register.json")

                if not os.path.exists(t_dir) or not os.path.exists(cfg_path):
                    self._resp(404, {"ok": False, "error": f"template '{t_id}' not found"})
                    return

                reg_data = {}
                if os.path.exists(reg_path):
                    try:
                        with open(reg_path, "r", encoding="utf-8") as f:
                            reg_data = json.load(f)
                    except Exception:
                        pass

                if "name" not in reg_data: reg_data["name"] = t_id
                if "fields" not in reg_data: reg_data["fields"] = []

                reg_data["is_api_only"] = (action == "disable")

                with open(reg_path, "w", encoding="utf-8") as f:
                    json.dump(reg_data, f, ensure_ascii=False, indent=4)

                audit(f"TEMPLATE_TOGGLE id={t_id} action={action} by_admin={admin_id} ip={client_ip}")
                self._resp(200, {"ok": True, "msg": f"template web {action}d"})
                return

            # ================= Admin：系统状态 =================
            if path == "/api/admin/system_info" and method in ("GET", "POST"):
                if not is_admin(admin_key):
                    self._resp(401, {"ok": False, "error": "admin unauthorized"})
                    return
                
                uptime_sec = time.time() - START_TIME
                hours, remainder = divmod(int(uptime_sec), 3600)
                minutes, seconds = divmod(remainder, 60)
                uptime_str = f"{hours}h {minutes}m {seconds}s"

                mem_used_mb = 0
                mem_total_mb = 0
                try:
                    with open("/proc/meminfo", "r") as f:
                        meminfo = f.read()
                        mem_total = int(re.search(r"MemTotal:\s+(\d+)", meminfo).group(1))
                        mem_avail = int(re.search(r"MemAvailable:\s+(\d+)", meminfo).group(1))
                        mem_total_mb = round(mem_total / 1024)
                        mem_used_mb = round((mem_total - mem_avail) / 1024)
                except Exception:
                    pass

                with _stats_lock:
                    total_success = STATS_SUCCESS
                    total_fail = STATS_FAILED
                    total_reject = STATS_REJECTED
                    now = time.time()
                    recent_rejects = len([t for t in _rejected_timestamps if t > now - 60])

                running_tasks = (max_workers * 2) - semaphore._value
                
                tmpl_count = 0
                if os.path.exists(HTML_DIR):
                    tmpl_count = len([d for d in os.listdir(HTML_DIR) if os.path.isdir(os.path.join(HTML_DIR, d))])

                acc_count = len(CFG.get("accounts", {}))

                self._resp(200, {
                    "ok": True,
                    "uptime": uptime_str,
                    "running_tasks": running_tasks,
                    "total_success": total_success,
                    "total_fail": total_fail,
                    "total_reject": total_reject,
                    "reject_1m": recent_rejects,
                    "template_count": tmpl_count,
                    "account_count": acc_count,
                    "mem_used_mb": mem_used_mb,
                    "mem_total_mb": mem_total_mb
                })
                return

            # ================= Admin：读取日志 =================
            if path == "/api/admin/logs" and method in ("GET", "POST"):
                if not is_admin(admin_key):
                    self._resp(401, {"ok": False, "error": "admin unauthorized"})
                    return
                
                lines_str = str(p.get("lines", "50"))
                if not lines_str.isdigit():
                    self._resp(400, {"ok": False, "error": "lines must be a positive integer"})
                    return

                limit = int(lines_str)
                if limit < 1 or limit > 500:
                    self._resp(400, {"ok": False, "error": "lines limit must be between 1 and 500"})
                    return
                
                log_path = LATEST_LOG
                if not os.path.exists(log_path):
                    self._resp(200, {"ok": True, "logs": "Log file empty or not found."})
                    return
                
                try:
                    with open(log_path, "rb") as f:
                        f.seek(0, 2)
                        end = f.tell()
                        if end == 0:
                            self._resp(200, {"ok": True, "logs": "Log file is empty."})
                            return
                        
                        size = end
                        block_size = 4096
                        lines_found = 0
                        buffer = b""

                        while size > 0 and lines_found <= limit:
                            size = max(0, size - block_size)
                            f.seek(size)
                            chunk = f.read(min(block_size, end - size))
                            buffer = chunk + buffer
                            lines_found = buffer.count(b"\n")

                        decoded = buffer.decode("utf-8", errors="ignore")
                        last_lines = decoded.splitlines()[-limit:]
                        logs_str = "\n".join(last_lines)

                    self._resp(200, {"ok": True, "logs": logs_str})
                except Exception as e:
                    self._resp(500, {"ok": False, "error": f"read log error: {e}"})
                return

            # ================= Admin：全量模板列表 =================
            if path == "/api/admin/list_templates" and method in ("GET", "POST"):
                if not is_admin(admin_key):
                    self._resp(401, {"ok": False, "error": "admin unauthorized"})
                    return
                
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
                                except Exception:
                                    pass
                            
                            all_tmpls.append({
                                "id": d,
                                "name": name,
                                "is_web": is_web
                            })
                self._resp(200, {"ok": True, "templates": all_tmpls})
                return

            self._resp(404, {"ok": False, "error": "not found"})
        except Exception as e:
            audit(f"ROUTE_ERR {type(e).__name__}: {repr(e)} path={self.path}")
            try:
                self._resp(500, {"ok": False, "error": "internal server error"})
            except Exception:
                pass

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
