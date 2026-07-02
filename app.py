import sys
import traceback
import sqlite3

# ---  ضد کرش کیری ---
def global_exception_handler(exctype, value, tb):
    print("\n" + "="*50)
    print("❌ FATAL ERROR:")
    traceback.print_exception(exctype, value, tb)
    print("="*50)
    input("\nPress Enter to exit...")

sys.excepthook = global_exception_handler
# -------------------------------------------------------------------

import asyncio
import time
import requests
import json
import os
import socket
from datetime import datetime
import urllib3
import subprocess
import tempfile
from urllib.parse import urlparse, parse_qs, unquote

from fastapi import FastAPI, Request, BackgroundTasks
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
import uvicorn

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_FILE = os.path.join(BASE_DIR, "scanner.db")
XRAY_EXE_NAME = "xray.exe" if os.name == "nt" else "xray"
XRAY_PATH = os.path.join(BASE_DIR, XRAY_EXE_NAME)

# --- سیستم مدیریت لایو لاگ ---
live_logs = []

def log_to_panel(message: str):
    timestamp = datetime.now().strftime("%H:%M:%S")
    formatted_msg = f"[{timestamp}] {message}"
    print(formatted_msg)
    live_logs.append(formatted_msg)
    if len(live_logs) > 100:
        live_logs.pop(0)

# --- مدیریت دیتابیس SQLite ---
def get_db_connection():
    conn = sqlite3.connect(DB_FILE, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db_connection()
    conn.execute('''CREATE TABLE IF NOT EXISTS config (key TEXT PRIMARY KEY, value TEXT)''')
    conn.execute('''CREATE TABLE IF NOT EXISTS ip_ranges (prefix TEXT UNIQUE)''')
    conn.execute('''CREATE TABLE IF NOT EXISTS xray_links (link TEXT UNIQUE)''')
    
    cursor = conn.execute("SELECT count(*) FROM config")
    if cursor.fetchone()[0] == 0:
        defaults = [
            ('cf_domain', ''), ('cf_zone_id', ''), ('cf_api_token', ''), ('cf_record_id', ''),
            ('scanner_port', '443'), ('scanner_timeout', '3.0'), ('scanner_test_count', '5'), ('scanner_max_workers', '40')
        ]
        conn.executemany("INSERT INTO config (key, value) VALUES (?, ?)", defaults)
        conn.execute("INSERT OR IGNORE INTO ip_ranges (prefix) VALUES ('104.16.1.')")
    conn.commit()
    conn.close()

def load_config_from_db():
    conn = get_db_connection()
    config = {"cloudflare": {}, "scanner": {}, "xray_links": [], "ip_prefixes": []}
    
    for row in conn.execute("SELECT key, value FROM config"):
        k, v = row['key'], row['value']
        if k.startswith('cf_'): config['cloudflare'][k.replace('cf_', '')] = v
        elif k.startswith('scanner_'):
            config['scanner'][k.replace('scanner_', '')] = int(v) if v.isdigit() else (float(v) if '.' in v else v)
            
    config['ip_prefixes'] = [row['prefix'] for row in conn.execute("SELECT prefix FROM ip_ranges")]
    config['xray_links'] = [row['link'] for row in conn.execute("SELECT link FROM xray_links")]
    conn.close()
    return config

init_db()

# --- ساخت فایل فرانت‌اند ---
TEMPLATES_DIR = os.path.join(BASE_DIR, "templates")
os.makedirs(TEMPLATES_DIR, exist_ok=True)

INDEX_HTML_PATH = os.path.join(TEMPLATES_DIR, "index.html")
html_content = """<!DOCTYPE html>
<html lang="fa" dir="rtl">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Cloudflare Auto DNS Set</title>
    <link href="https://cdn.jsdelivr.net/gh/rastikerdar/vazirmatn@v33.0.0/Vazirmatn-font-face.css" rel="stylesheet" type="text/css" />
    <style>
        :root {
            --bg-body: #252836;
            --bg-card: #1F1D2B;
            --bg-inner: #2D3042;
            --bg-tabs: #13121A;
            
            --text-main: #FFFFFF;
            --text-muted: #808191;
            
            --accent-purple: #6C5DD3;
            --accent-purple-hover: #5b4eb3;
            --accent-green: #22B07D;
            --accent-red: #FF754C;
            --border-color: #353340;
        }

        body {
            background-color: var(--bg-body);
            color: var(--text-main);
            font-family: 'Vazirmatn', Tahoma, sans-serif;
            margin: 0;
            padding: 0;
            min-height: 100vh;
            display: flex;
            flex-direction: column;
            justify-content: center;
            align-items: center;
            position: relative;
        }

        .main-wrapper {
            display: flex; justify-content: center; align-items: flex-start;
            width: 100%; max-width: 1100px; padding: 40px 20px 80px 20px; box-sizing: border-box; gap: 30px;
            z-index: 2;
        }

        .solid-panel {
            background: var(--bg-card);
            border-radius: 28px;
            box-shadow: 0 20px 50px rgba(0, 0, 0, 0.25);
            transition: all 0.4s ease;
            border: 1px solid rgba(255, 255, 255, 0.03);
        }

        .panel-container { padding: 40px; width: 480px; max-width: 100%; position: relative; z-index: 2; }
        
        h1 {
            color: var(--text-main); text-align: center; font-size: 19px; 
            margin-top: 0; margin-bottom: 30px; font-weight: 800; letter-spacing: 1px;
            display: flex; align-items: center; justify-content: center; gap: 8px;
        }

        /* استایل تب‌های جدید و جذاب‌تر */
        .tabs {
            display: flex; background: var(--bg-tabs); border-radius: 16px;
            padding: 6px; margin-bottom: 30px; border: 1px solid var(--border-color);
            box-shadow: inset 0 2px 5px rgba(0,0,0,0.2);
        }
        .tab-btn {
            flex: 1; background: transparent; color: var(--text-muted); border: none; cursor: pointer;
            padding: 10px; font-size: 13px; font-weight: 600; border-radius: 12px; transition: all 0.3s; 
            font-family: inherit; display: flex; align-items: center; justify-content: center; gap: 6px;
        }
        .tab-btn:hover { color: var(--text-main); }
        .tab-btn.active { 
            background: var(--bg-card); color: var(--text-main); 
            box-shadow: 0 4px 10px rgba(0,0,0,0.2); 
        }
        
        .tab-content { display: none; animation: fadeIn 0.4s cubic-bezier(0.16, 1, 0.3, 1); }
        .tab-content.active { display: block; }
        @keyframes fadeIn { from { opacity: 0; transform: translateY(15px); } to { opacity: 1; transform: translateY(0); } }

        .status-box {
            background: var(--bg-inner); border-radius: 20px; padding: 25px; margin-bottom: 30px;
            border: 1px solid rgba(255,255,255,0.02); box-shadow: 0 8px 20px rgba(0,0,0,0.1);
        }
        .status-item { margin: 12px 0; font-size: 13px; color: var(--text-muted); display: flex; justify-content: space-between; align-items: center;}
        .status-item span { color: var(--text-main); font-weight: 700; font-size: 14px; }
        
        .input-group { margin-bottom: 22px; text-align: right; }
        .input-group label { display: block; margin-bottom: 6px; color: var(--text-muted); font-size: 12px; font-weight: 600;}
        .neon-input {
            width: 100%; padding: 12px 10px; background: transparent; border: none; 
            border-bottom: 2px solid var(--border-color); border-radius: 0;
            color: var(--text-main); font-size: 13.5px; outline: none; transition: 0.3s; font-family: inherit; box-sizing: border-box;
        }
        .neon-input::placeholder { color: #515466; font-size: 12.5px; }
        .neon-input:focus { border-bottom-color: var(--accent-purple); }
        
        .row-inputs { display: grid; grid-template-columns: 1fr 1fr; gap: 20px; }

        .primary-btn {
            background: var(--accent-purple); color: #fff; display: flex; justify-content: center; align-items: center; gap: 8px;
            font-weight: 700; font-size: 14px; border: none; border-radius: 16px; padding: 16px; cursor: pointer;
            width: 100%; transition: 0.3s; margin-bottom: 15px; font-family: inherit;
        }
        .primary-btn:hover { background: var(--accent-purple-hover); transform: translateY(-2px); box-shadow: 0 8px 20px rgba(108, 93, 211, 0.3); }

        .secondary-btn {
            background: var(--bg-inner); color: var(--text-main); font-size: 12.5px; padding: 14px; cursor: pointer; 
            border-radius: 14px; transition: 0.3s; font-weight: 600; font-family: inherit; display: flex; align-items: center; justify-content: center; gap: 6px; border: none;
        }
        .secondary-btn:hover { background: var(--border-color); transform: translateY(-1px); }

        .fast-test-btn { color: var(--accent-red); background: rgba(255, 117, 76, 0.1); }
        .fast-test-btn:hover { background: rgba(255, 117, 76, 0.2); }

        .confirm-btn { background: var(--accent-green); display: none; }
        .confirm-btn:hover { background: #1fa072; box-shadow: 0 8px 20px rgba(34, 176, 125, 0.3); }

        .console-box {
            background: var(--bg-tabs); border-radius: 16px; padding: 18px; height: 160px; overflow-y: auto; 
            text-align: left; direction: ltr; font-size: 11.5px; color: var(--accent-green);
            font-family: 'Courier New', monospace; margin-top: 25px; border: 1px solid var(--border-color);
            box-shadow: inset 0 2px 10px rgba(0,0,0,0.3);
        }

        .data-list { max-height: 160px; overflow-y: auto; margin-bottom: 25px; padding-right: 5px; }
        .data-item {
            display: flex; justify-content: space-between; align-items: center; padding: 12px 16px;
            background: var(--bg-inner); border-radius: 12px; margin-bottom: 10px; font-size: 12px; transition: 0.2s;
        }
        .data-item:hover { background: var(--border-color); transform: translateX(-3px); }
        .data-item-text { direction: ltr; text-align: left; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; max-width: 75%; color: var(--text-main); font-family: monospace;}
        .delete-btn { background: transparent; border: none; color: var(--accent-red); cursor: pointer; border-radius: 8px; transition: 0.2s; font-size: 11.5px; font-weight: 700; padding: 5px;}
        .delete-btn:hover { text-decoration: underline; }

        ::-webkit-scrollbar { width: 4px; }
        ::-webkit-scrollbar-track { background: transparent; }
        ::-webkit-scrollbar-thumb { background: var(--border-color); border-radius: 10px; }
        ::-webkit-scrollbar-thumb:hover { background: var(--text-muted); }

        /* استایل فوتر اختصاصی */
        .footer {
            position: fixed;
            bottom: 25px;
            width: 100%;
            text-align: center;
            font-size: 12px;
            color: var(--text-muted);
            letter-spacing: 0.5px;
            z-index: 10;
            pointer-events: none;
        }
        .footer .highlight-green {
            color: var(--accent-green);
            font-weight: 700;
            text-shadow: 0 0 8px rgba(34, 176, 125, 0.4);
        }
        .footer .highlight-purple {
            color: #9d8df1;
            font-weight: 800;
            text-shadow: 0 0 8px rgba(108, 93, 211, 0.5);
            letter-spacing: 1px;
            font-family: Tahoma, sans-serif;
        }
    </style>
</head>
<body>
    <div class="main-wrapper" id="mainWrapper">
        
        <!-- پنل اصلی -->
        <div class="panel-container solid-panel">
            <h1><span style="font-size: 22px; filter: drop-shadow(0 0 8px var(--accent-purple));">⚡</span> CLOUDFLARE AUTO DNS SET</h1>

            <div class="tabs">
                <button class="tab-btn active" onclick="switchTab('tab-scan', this)">🎛️ داشبورد</button>
                <button class="tab-btn" onclick="switchTab('tab-cf', this)">⚙️ تنظیمات</button>
                <button class="tab-btn" onclick="switchTab('tab-data', this)">🗄️ دیتا سنتر</button>
            </div>

            <!-- تب داشبورد اسکن -->
            <div id="tab-scan" class="tab-content active">
                <div class="status-box">
                    <div class="status-item">وضعیت سیستم: <span id="panelStatus" style="color: var(--text-main);">آماده به کار</span></div>
                    <div class="status-item">آی‌پی فعلی روی دامنه: <span id="currentIP">درحال دریافت...</span></div>
                    <div class="status-item">بهترین کاندید اسکن: <span id="foundIP" style="color: var(--accent-green);">منتظر فرمان</span></div>
                </div>

                <button id="confirmBtn" class="primary-btn confirm-btn" onclick="confirmIP()">
                    🚀 تأیید نهایی و ثبت در کلودفلر
                </button>
                <button id="scanBtn" class="primary-btn" onclick="startScan()">
                    🔥 شروع اسکن هوشمند
                </button>
                
                <div id="consoleBox" class="console-box">root@core:~# System initialized...</div>
            </div>

            <!-- تب تنظیمات -->
            <div id="tab-cf" class="tab-content">
                <div class="row-inputs">
                    <div class="input-group">
                        <label>Sub/Domain (دامنه هدف)</label>
                        <input type="text" id="domainInput" class="neon-input" placeholder="sub.domain.com" onchange="saveSettings()">
                    </div>
                    <div class="input-group">
                        <label>API Token (توکن کلودفلر)</label>
                        <input type="password" id="tokenInput" class="neon-input" placeholder="••••••••••••••" onchange="saveSettings()">
                    </div>
                </div>

                <!-- دکمه‌های دریافت توکن و استخراج -->
                <div style="display:flex; gap:15px; margin-bottom:25px; margin-top: 5px;">
                    <a href="https://dash.cloudflare.com/profile/api-tokens?permissionGroupKeys=%5B%7B%22key%22%3A%22zone%22%2C%22type%22%3A%22read%22%7D%2C%7B%22key%22%3A%22dns%22%2C%22type%22%3A%22edit%22%7D%5D&name=MHJ_AutoSet_DNS_Token&accountId=*&zoneId=all" target="_blank" class="secondary-btn" style="flex:1; margin:0; text-decoration:none; color: var(--accent-green); border: 1px solid rgba(34, 176, 125, 0.3); background: rgba(34, 176, 125, 0.05);">
                        🔑 گرفتن توکن کلودفلر
                    </a>
                    <button class="secondary-btn" style="flex:1; margin:0; color: #a192fc; border: 1px solid rgba(108, 93, 211, 0.3); background: rgba(108, 93, 211, 0.08);" onclick="autoFetchCF(this)">
                        🪄 استخراج خودکار شناسه‌ها
                    </button>
                </div>

                <div class="row-inputs">
                    <div class="input-group">
                        <label>Zone ID (شناسه زون)</label>
                        <input type="text" id="zoneInput" class="neon-input" placeholder="Auto fetched or Manual" onchange="saveSettings()">
                    </div>
                    <div class="input-group">
                        <label>DNS Record ID (شناسه رکورد)</label>
                        <input type="text" id="recordInput" class="neon-input" placeholder="Auto fetched or Manual" onchange="saveSettings()">
                    </div>
                </div>
                <button class="primary-btn" style="margin-top: 5px;" onclick="saveSettings(); alert('تنظیمات شبکه ذخیره شد.');">💾 ذخیره تنظیمات شبکه</button>
            </div>

            <!-- تب دیتا سنتر -->
            <div id="tab-data" class="tab-content">
                <div class="input-group">
                    <label>مخزن IP / رنج‌ها</label>
                    <input type="text" id="ipInput" class="neon-input" placeholder="مثال: 104.16.5. یا آی‌پی کامل">
                    <div style="display:flex; gap:12px; margin-top:15px;">
                        <button class="secondary-btn" style="flex:1;" onclick="addIP()">➕ افزودن رنج</button>
                        <button class="secondary-btn fast-test-btn" style="flex:1;" onclick="testSingleIP()">⚡ تست فوری IP</button>
                    </div>
                </div>
                <div class="data-list" id="ipList"></div>

                <div class="input-group" style="margin-top: 35px;">
                    <label>مخزن کانفیگ‌های Xray</label>
                    <input type="text" id="xrayInput" class="neon-input" placeholder="لینک Vless یا Trojan">
                    <button class="secondary-btn" style="margin-top:15px; width:100%;" onclick="addLink()">💉 تزریق کانفیگ به موتور</button>
                </div>
                <div class="data-list" id="linkList"></div>
            </div>
        </div>
    </div>

    <!-- فوتر اختصاصی پایین صفحه -->
    <div class="footer">
        ساخته شده با <span class="highlight-green">Xray</span> . توسط <span class="highlight-purple">MHJ Studio</span>
    </div>

    <script>
        let isFirstLoad = true;

        function switchTab(tabId, element) {
            document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
            document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
            document.getElementById(tabId).classList.add('active');
            element.classList.add('active');
            if(tabId === 'tab-data') loadDataManager();
        }

        async function updateStatus() {
            try {
                const res = await fetch('/api/status');
                const data = await res.json();
                
                document.getElementById('panelStatus').innerText = data.status;
                document.getElementById('currentIP').innerText = data.current_dns_ip || "نامشخص";
                document.getElementById('foundIP').innerText = data.candidate_ip || "منتظر عملیات...";
                
                if (isFirstLoad) {
                    document.getElementById('domainInput').value = data.config.cloudflare.domain || '';
                    document.getElementById('tokenInput').value = data.config.cloudflare.api_token || '';
                    document.getElementById('zoneInput').value = data.config.cloudflare.zone_id || '';
                    document.getElementById('recordInput').value = data.config.cloudflare.record_id || '';
                    isFirstLoad = false;
                }

                const confirmBtn = document.getElementById('confirmBtn');
                const scanBtn = document.getElementById('scanBtn');

                if (data.status === "Awaiting Confirmation") {
                    confirmBtn.style.display = "flex";
                    scanBtn.style.display = "none";
                    document.getElementById('panelStatus').style.color = "var(--accent-red)";
                } else if (data.status === "Scanning") {
                    confirmBtn.style.display = "none";
                    scanBtn.innerHTML = "⏳ در حال پردازش...";
                    scanBtn.disabled = true;
                    scanBtn.style.opacity = "0.6";
                    document.getElementById('panelStatus').style.color = "var(--accent-purple)";
                } else {
                    confirmBtn.style.display = "none";
                    scanBtn.style.display = "flex";
                    scanBtn.innerHTML = "🔥 شروع اسکن هوشمند";
                    scanBtn.disabled = false;
                    scanBtn.style.opacity = "1";
                    document.getElementById('panelStatus').style.color = "var(--text-main)";
                }

                const logRes = await fetch('/api/logs');
                const logData = await logRes.json();
                const consoleBox = document.getElementById('consoleBox');
                const isScrolledToBottom = consoleBox.scrollHeight - consoleBox.clientHeight <= consoleBox.scrollTop + 10;
                
                const formattedLogs = logData.logs.map(log => `root@core:~# ${log}`).join('<br>');
                consoleBox.innerHTML = formattedLogs || 'root@core:~# Waiting for commands...';
                
                if(isScrolledToBottom) consoleBox.scrollTop = consoleBox.scrollHeight;

            } catch (e) {}
        }

        async function saveSettings() {
            const cfData = {
                domain: document.getElementById('domainInput').value,
                token: document.getElementById('tokenInput').value,
                zone: document.getElementById('zoneInput').value,
                record: document.getElementById('recordInput').value
            };
            await fetch('/api/save_config', { method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(cfData) });
        }

        // --- اسکریپت جادویی برای گرفتن اتوماتیک کلودفلر ---
        async function autoFetchCF(btnElement) {
            const domain = document.getElementById('domainInput').value;
            const token = document.getElementById('tokenInput').value;
            
            if(!domain || !token) {
                return alert("لطفاً ابتدا فیلد دامنه و توکن را پر کنید!");
            }
            
            const originalText = btnElement.innerHTML;
            btnElement.innerHTML = "⏳ در حال استخراج...";
            btnElement.disabled = true;
            
            try {
                const res = await fetch('/api/auto_cf', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({domain: domain, token: token})
                });
                const data = await res.json();
                
                if(data.status === 'success') {
                    document.getElementById('zoneInput').value = data.zone_id;
                    document.getElementById('recordInput').value = data.record_id;
                    alert(data.message);
                } else {
                    alert(data.message);
                }
            } catch (e) {
                alert("خطا در ارتباط با سرور داخلی");
            }
            
            btnElement.innerHTML = originalText;
            btnElement.disabled = false;
        }

        async function startScan() {
            await saveSettings();
            const res = await fetch('/api/start', {method: 'POST'});
            const data = await res.json();
            alert(data.message);
            updateStatus();
        }

        async function testSingleIP() {
            const ip = document.getElementById('ipInput').value;
            if(!ip) return alert("ابتدا یک آی‌پی در کادر وارد کنید!");
            await saveSettings();
            const res = await fetch('/api/test_single', { method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({ip: ip}) });
            const data = await res.json();
            alert(data.message);
            document.getElementById('ipInput').value = '';
            updateStatus();
            document.querySelector('.tab-btn').click(); 
        }

        async function confirmIP() {
            const res = await fetch('/api/confirm', {method: 'POST'});
            const data = await res.json();
            alert(data.message);
            updateStatus();
        }

        async function loadDataManager() {
            const res = await fetch('/api/status');
            const data = await res.json();
            
            const ipList = document.getElementById('ipList');
            ipList.innerHTML = data.config.ip_prefixes.map(ip => `
                <div class="data-item">
                    <span class="data-item-text">${ip}*</span>
                    <button class="delete-btn" onclick="deleteItem('ip', '${ip}')">حذف</button>
                </div>
            `).join('') || '<div style="color:var(--text-muted); text-align:center; font-size:12px; padding:15px;">لیست خالی است</div>';

            const linkList = document.getElementById('linkList');
            linkList.innerHTML = data.config.xray_links.map(link => `
                <div class="data-item">
                    <span class="data-item-text" title="${link}">${link.substring(0,35)}...</span>
                    <button class="delete-btn" onclick="deleteItem('link', '${link}')">حذف</button>
                </div>
            `).join('') || '<div style="color:var(--text-muted); text-align:center; font-size:12px; padding:15px;">لیست خالی است</div>';
        }

        async function addIP() {
            const ip = document.getElementById('ipInput').value;
            if(!ip) return alert("فیلد خالی است");
            await fetch('/api/add_ip', { method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({ip: ip}) });
            document.getElementById('ipInput').value = '';
            loadDataManager();
        }

        async function addLink() {
            const link = document.getElementById('xrayInput').value;
            if(!link) return alert("فیلد خالی است");
            await fetch('/api/add_link', { method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({link: link}) });
            document.getElementById('xrayInput').value = '';
            loadDataManager();
        }

        async function deleteItem(type, value) {
            if(!confirm('آیا از حذف این رکورد مطمئن هستید؟')) return;
            await fetch(`/api/delete_${type}`, { method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({value: value}) });
            loadDataManager();
        }

        setInterval(updateStatus, 2000);
        updateStatus();
    </script>
</body>
</html>
"""
with open(INDEX_HTML_PATH, "w", encoding="utf-8") as f:
    f.write(html_content)

app = FastAPI()
templates = Jinja2Templates(directory=TEMPLATES_DIR)

# --- وضعیت زنده برنامه ---
scanner_status = {
    "status": "Idle", 
    "current_dns_ip": None, 
    "candidate_ip": None
}

# --- متدهای شبکه ---
def get_current_dns_ip(domain):
    try: return socket.gethostbyname(domain)
    except: return None

async def test_single_packet(ip, port, timeout):
    try:
        start_time = time.time()
        _, writer = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout=timeout)
        writer.close()
        await writer.wait_closed()
        return (time.time() - start_time) * 1000
    except: return None

async def measure_stability(ip, semaphore, config):
    port = config["scanner"]["port"]
    timeout = config["scanner"]["timeout"]
    test_count = config["scanner"]["test_count"]
    async with semaphore:
        ip_last_octet = int(ip.split('.')[-1])
        await asyncio.sleep((ip_last_octet % 20) * 0.05)
        latencies = []
        for _ in range(test_count):
            latency = await test_single_packet(ip, port, timeout)
            if latency is not None: latencies.append(latency)
            await asyncio.sleep(0.2)
        success_rate = (len(latencies) / test_count) * 100
        if success_rate < 100: return (ip, float('inf'), success_rate, float('inf'), float('inf'))
        avg_latency = sum(latencies) / len(latencies)
        jitter = max(latencies) - min(latencies)
        if avg_latency > 250 or jitter > 30: return (ip, float('inf'), success_rate, avg_latency, jitter)
        score = avg_latency + (jitter * 5)
        return (ip, score, success_rate, avg_latency, jitter)

def verify_real_traffic(ip, domain):
    headers = {"Host": domain}
    for attempt in range(2):
        try:
            start_time = time.time()
            response = requests.get(f"https://{ip}/cdn-cgi/trace", headers=headers, timeout=5.0, verify=False)
            if "cloudflare" in response.text.lower() or response.headers.get("Server", "").lower() == "cloudflare":
                return time.time() - start_time
        except: continue
    return float('inf')

def link_to_xray_config(link, target_ip):
    try:
        parsed = urlparse(link)
        protocol = parsed.scheme
        if protocol not in ["vless", "trojan"]: return None
        user_info = parsed.username 
        original_host = parsed.hostname
        port = parsed.port if parsed.port else 443
        params = {k: v[0] for k, v in parse_qs(parsed.query).items()}
        config = {
            "log": {"loglevel": "warning"},
            "inbounds": [{"port": 40808, "listen": "127.0.0.1", "protocol": "socks", "settings": {"auth": "noauth", "udp": True}}],
            "outbounds": [{"protocol": protocol, "settings": {"servers": []}, "streamSettings": {}}]
        }
        server_settings = {"address": target_ip, "port": int(port)}
        if protocol == "vless":
            server_settings["users"] = [{"id": user_info, "encryption": params.get("encryption", "none")}]
        elif protocol == "trojan":
            server_settings["password"] = unquote(user_info)
        config["outbounds"][0]["settings"]["servers"].append(server_settings)
        stream_settings = config["outbounds"][0]["streamSettings"]
        network_type = params.get("type", "tcp")
        security_type = params.get("security", "none")
        stream_settings["network"] = network_type
        stream_settings["security"] = security_type
        sni = params.get("sni", original_host)
        if security_type == "tls":
            is_insecure = params.get("allowInsecure", "0") == "1" or params.get("insecure", "0") == "1"
            stream_settings["tlsSettings"] = {"serverName": sni, "allowInsecure": is_insecure}
        elif security_type == "reality":
            stream_settings["realitySettings"] = {"show": False, "serverName": sni, "publicKey": params.get("pbk", ""), "shortId": params.get("sid", ""), "spiderX": params.get("spx", ""), "fingerprint": params.get("fp", "chrome")}
        if network_type == "ws":
            stream_settings["wsSettings"] = {"path": unquote(params.get("path", "/")), "host": params.get("host", sni)}
        return config
    except: return None

def test_with_xray(ip, xray_path, config_link):
    if not os.path.exists(xray_path): return float('inf')
    config_dict = link_to_xray_config(config_link, ip)
    if not config_dict: return float('inf')
    fd, temp_config_path = tempfile.mkstemp(suffix=".json")
    with os.fdopen(fd, 'w', encoding='utf-8') as f: json.dump(config_dict, f, indent=2)
    xray_process = None
    try:
        xray_process = subprocess.Popen([xray_path, "-c", temp_config_path], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(2.5)
        if xray_process.poll() is not None: return float('inf')
        proxies = {"http": "socks5h://127.0.0.1:40808", "https": "socks5h://127.0.0.1:40808"}
        start_time = time.time()
        response = requests.get("https://cloudflare.com/cdn-cgi/trace", proxies=proxies, timeout=6.0, verify=False)
        if response.status_code == 200: return time.time() - start_time
    except: pass
    finally:
        if xray_process:
            xray_process.terminate()
            xray_process.wait()
        try: os.remove(temp_config_path)
        except: pass
    return float('inf')

def update_cloudflare(best_ip, config):
    cf = config["cloudflare"]
    url = f"https://api.cloudflare.com/client/v4/zones/{cf['zone_id']}/dns_records/{cf['record_id']}"
    headers = {"Authorization": f"Bearer {cf['api_token']}", "Content-Type": "application/json"}
    data = {"type": "A", "name": cf["domain"], "content": best_ip, "ttl": 60, "proxied": False}
    try: return requests.put(url, headers=headers, json=data).status_code == 200
    except: return False

# --- هسته شماره 1: اسکن کلی (Scanner) ---
async def run_scanner_core():
    global scanner_status
    scanner_status["status"] = "Scanning"
    live_logs.clear()
    
    log_to_panel("Loading configurations for Auto-Scan...")
    config = load_config_from_db()
    domain = config["cloudflare"].get("domain")
    ip_prefixes = config["ip_prefixes"]
    
    if not domain:
        log_to_panel("❌ Error: Cloudflare domain name is missing!")
        scanner_status["status"] = "Idle"
        return

    current_dns_ip = get_current_dns_ip(domain)
    scanner_status["current_dns_ip"] = current_dns_ip
    log_to_panel(f"Current Domain IP on Cloudflare is: {current_dns_ip}")

    ips_to_test = []
    for prefix in ip_prefixes:
        if prefix.count('.') == 3 and prefix.endswith('.'):
            ips_to_test.extend([f"{prefix}{i}" for i in range(1, 255)])
        else:
            ips_to_test.append(prefix)

    if current_dns_ip and current_dns_ip not in ips_to_test:
        ips_to_test.append(current_dns_ip)

    log_to_panel(f"Stage 1: Pinging {len(ips_to_test)} IPs concurrently...")
    max_workers = min(config["scanner"]["max_workers"], 50)
    semaphore = asyncio.Semaphore(max_workers)
    tasks = [measure_stability(ip, semaphore, config) for ip in ips_to_test]
    results = await asyncio.gather(*tasks)
    
    valid_results = [r for r in results if r[1] != float('inf')]
    
    if not valid_results:
        log_to_panel("❌ No stable IPs found in Stage 1 testing.")
        scanner_status["status"] = "Idle"
        scanner_status["candidate_ip"] = "No stable candidate"
        return
        
    valid_results.sort(key=lambda x: x[1])
    top_candidates = valid_results[:15]
    
    log_to_panel("Stage 2: Verifying TLS Handshake...")
    stage2_passed = []
    for candidate in top_candidates:
        cand_ip = candidate[0]
        real_latency = verify_real_traffic(cand_ip, domain)
        if real_latency != float('inf'):
            stage2_passed.append((candidate, real_latency))
            log_to_panel(f" -> {cand_ip} passed TLS check.")

    if stage2_passed:
        stage2_passed.sort(key=lambda x: x[1])
        stage2_best_ip = stage2_passed[0][0][0]
    else:
        stage2_best_ip = top_candidates[0][0]

    xray_links = config.get("xray_links", [])
    absolute_best_ip = stage2_best_ip

    if xray_links:
        log_to_panel(f"Stage 3: Testing live tunnel (Xray)...")
        candidates_to_test = [c[0] for c in stage2_passed] if stage2_passed else top_candidates
        best_xray_latency = float('inf')
        best_xray_ip = None
        
        for candidate in candidates_to_test:
            cand_ip = candidate[0]
            for link in xray_links:
                xray_latency = test_with_xray(cand_ip, XRAY_PATH, link)
                if xray_latency < best_xray_latency:
                    best_xray_latency = xray_latency
                    best_xray_ip = cand_ip
            if best_xray_ip == cand_ip:
                log_to_panel(f" -> [Tunnel Success] IP: {cand_ip}")
        
        if best_xray_ip:
            absolute_best_ip = best_xray_ip

    log_to_panel(f"🎉 Complete! Optimal IP target: {absolute_best_ip}")
    scanner_status["status"] = "Awaiting Confirmation"
    scanner_status["candidate_ip"] = absolute_best_ip

# --- هسته شماره 2: تست فوری یک آی‌پی خاص (Fast-Track) ---
async def run_single_ip_core(target_ip):
    global scanner_status
    scanner_status["status"] = "Scanning"
    live_logs.clear()
    
    log_to_panel(f"⚡ FAST-TRACK: Testing single IP -> {target_ip}")
    config = load_config_from_db()
    domain = config["cloudflare"].get("domain")
    
    if not domain:
        log_to_panel("❌ Error: Domain is missing! Save settings first.")
        scanner_status["status"] = "Idle"
        return
        
    current_dns_ip = get_current_dns_ip(domain)
    scanner_status["current_dns_ip"] = current_dns_ip
    
    log_to_panel("Stage 1: Socket Ping Test...")
    semaphore = asyncio.Semaphore(1)
    _, score, success, avg_lat, jitter = await measure_stability(target_ip, semaphore, config)
    
    if score == float('inf'):
        log_to_panel(f"❌ Failed: IP {target_ip} is dead or blocked.")
        scanner_status["status"] = "Idle"
        return
        
    log_to_panel(f"✅ Ping Passed! Latency: {avg_lat:.1f}ms")
    
    log_to_panel("Stage 2: Cloudflare Routing & TLS Check...")
    real_latency = verify_real_traffic(target_ip, domain)
    if real_latency == float('inf'):
        log_to_panel(f"❌ Failed: No route to Cloudflare TLS on {target_ip}.")
        scanner_status["status"] = "Idle"
        return
        
    log_to_panel(f"✅ TLS Passed! Delay: {real_latency*1000:.1f}ms")
    
    xray_links = config.get("xray_links", [])
    if xray_links:
        log_to_panel("Stage 3: Testing Vless/Trojan Tunnel...")
        best_xray = float('inf')
        for link in xray_links:
            lat = test_with_xray(target_ip, XRAY_PATH, link)
            if lat < best_xray: best_xray = lat
            
        if best_xray == float('inf'):
            log_to_panel("❌ Tunnel Connection Failed on this IP.")
            scanner_status["status"] = "Idle"
            return
        log_to_panel(f"✅ Tunnel Connected! Speed: {best_xray*1000:.1f}ms")
        
    log_to_panel(f"🎉 SUCCESS! IP {target_ip} is healthy and ready to deploy.")
    scanner_status["status"] = "Awaiting Confirmation"
    scanner_status["candidate_ip"] = target_ip

# --- مسیرهای مربوط به وب‌سرور FastAPI ---
@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    return templates.TemplateResponse(request=request, name="index.html")

@app.get("/api/status")
async def get_status():
    config = load_config_from_db()
    if not scanner_status["current_dns_ip"] and config["cloudflare"].get("domain"):
        scanner_status["current_dns_ip"] = get_current_dns_ip(config["cloudflare"]["domain"])
    return {
        "status": scanner_status["status"],
        "current_dns_ip": scanner_status["current_dns_ip"],
        "candidate_ip": scanner_status["candidate_ip"],
        "config": config
    }

@app.get("/api/logs")
async def get_logs():
    return {"logs": live_logs}

@app.post("/api/save_config")
async def save_config(data: dict):
    conn = get_db_connection()
    conn.execute("UPDATE config SET value = ? WHERE key = 'cf_domain'", (data.get("domain", ""),))
    conn.execute("UPDATE config SET value = ? WHERE key = 'cf_api_token'", (data.get("token", ""),))
    conn.execute("UPDATE config SET value = ? WHERE key = 'cf_zone_id'", (data.get("zone", ""),))
    conn.execute("UPDATE config SET value = ? WHERE key = 'cf_record_id'", (data.get("record", ""),))
    conn.commit()
    conn.close()
    return {"status": "success"}

# --- API استخراج خودکار Zone ID و Record ID ---
@app.post("/api/auto_cf")
async def auto_cf(data: dict):
    domain = data.get("domain", "").strip()
    token = data.get("token", "").strip()
    
    if not domain or not token:
        return {"status": "error", "message": "دامنه و توکن باید وارد شوند!"}
        
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    
    try:
        # مرحله اول: گرفتن لیست Zone ها و پیدا کردن زون مربوط به این دامنه
        z_resp = requests.get("https://api.cloudflare.com/client/v4/zones", headers=headers, timeout=15).json()
        if not z_resp.get("success"):
            return {"status": "error", "message": "خطا در توکن یا عدم دسترسی Zone. توکن را بررسی کنید."}
        
        target_zone = None
        for z in z_resp.get("result", []):
            # بررسی اینکه آیا ساب دامین بخشی از این زون هست یا خودشه
            if domain == z["name"] or domain.endswith("." + z["name"]):
                target_zone = z
                break
                
        if not target_zone:
            return {"status": "error", "message": "دامنه اصلی این ساب‌دامین در اکانت کلودفلر یافت نشد!"}
            
        zone_id = target_zone["id"]
        
        # مرحله دوم: گرفتن Record ID بر اساس زون پیدا شده
        r_url = f"https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records?name={domain}"
        r_resp = requests.get(r_url, headers=headers, timeout=15).json()
        if not r_resp.get("success"):
            return {"status": "error", "message": "خطا در دریافت لیست رکوردهای DNS کلودفلر."}
            
        records = r_resp.get("result", [])
        if not records:
            return {"status": "error", "message": f"رکوردی به نام {domain} وجود ندارد. لطفاً ابتدا در کلودفلر یک رکورد A با آی‌پی فیک بسازید."}
            
        record_id = records[0]["id"]
        
        # مرحله سوم: ذخیره مستقیم داخل دیتابیس
        conn = get_db_connection()
        conn.execute("UPDATE config SET value = ? WHERE key = 'cf_zone_id'", (zone_id,))
        conn.execute("UPDATE config SET value = ? WHERE key = 'cf_record_id'", (record_id,))
        conn.execute("UPDATE config SET value = ? WHERE key = 'cf_domain'", (domain,))
        conn.execute("UPDATE config SET value = ? WHERE key = 'cf_api_token'", (token,))
        conn.commit()
        conn.close()
        
        return {
            "status": "success", 
            "zone_id": zone_id, 
            "record_id": record_id, 
            "message": "اطلاعات با موفقیت از کلودفلر استخراج و ذخیره شد! 🎉"
        }
        
    except Exception as e:
        return {"status": "error", "message": f"خطای ارتباط با کلودفلر"}

@app.post("/api/start")
async def start_scan(background_tasks: BackgroundTasks):
    if scanner_status["status"] == "Scanning":
        return {"status": "error", "message": "یک عملیات دیگر در حال اجراست!"}
    
    background_tasks.add_task(run_scanner_core)
    return {"status": "success", "message": "موتور اسکنر استارت خورد. لاگ‌ها را بررسی کنید."}

@app.post("/api/test_single")
async def test_single(data: dict, background_tasks: BackgroundTasks):
    target_ip = data.get("ip")
    if scanner_status["status"] == "Scanning":
        return {"status": "error", "message": "سیستم درگیر کار دیگری است. صبر کنید."}
    if not target_ip:
        return {"status": "error", "message": "آی‌پی دریافت نشد!"}
        
    background_tasks.add_task(run_single_ip_core, target_ip)
    return {"status": "success", "message": f"تست روی {target_ip} شروع شد. نتیجه را در لاگ ببینید."}

@app.post("/api/confirm")
async def confirm_update():
    if scanner_status["status"] != "Awaiting Confirmation":
        return {"status": "error", "message": "رکورد جدیدی برای تایید نهایی آماده نیست."}
    
    config = load_config_from_db()
    best_ip = scanner_status["candidate_ip"]
    
    log_to_panel(f"Pushing updates to Cloudflare API for IP: {best_ip}")
    success = update_cloudflare(best_ip, config)
    if success:
        log_to_panel("🚀 Cloudflare Updated Successfully!")
        scanner_status["status"] = "Idle"
        scanner_status["current_dns_ip"] = best_ip
        return {"status": "success", "message": "آی‌پی با موفقیت روی کلودفلر ست شد!"}
    else:
        log_to_panel("❌ API Update Failed. Check token permissions.")
        return {"status": "error", "message": "خطا در ثبت اطلاعات در کلودفلر! لاگ سیستم را چک کنید."}

@app.post("/api/add_ip")
async def add_manual_ip(data: dict):
    new_ip = data.get("ip", "").strip()
    if not new_ip: return {"status": "error", "message": "ورودی معتبر نیست"}
    
    parts = new_ip.split('.')
    if len(parts) == 4 and parts[3] != "":
        prefix = new_ip
    elif len(parts) >= 3:
        prefix = f"{parts[0]}.{parts[1]}.{parts[2]}." 
    else:
        return {"status": "error", "message": "فرمت آی‌پی اشتباه است."}

    conn = get_db_connection()
    try:
        conn.execute("INSERT INTO ip_ranges (prefix) VALUES (?)", (prefix,))
        conn.commit()
        msg = "با موفقیت به لیست اضافه شد."
    except sqlite3.IntegrityError:
        msg = "این مورد قبلاً اضافه شده بود."
    finally: conn.close()
    return {"status": "success", "message": msg}

@app.post("/api/delete_ip")
async def delete_ip(data: dict):
    value = data.get("value")
    conn = get_db_connection()
    conn.execute("DELETE FROM ip_ranges WHERE prefix = ?", (value,))
    conn.commit()
    conn.close()
    return {"status": "success"}

@app.post("/api/add_link")
async def add_manual_link(data: dict):
    link = data.get("link", "").strip()
    if not link or not (link.startswith("vless://") or link.startswith("trojan://")):
        return {"status": "error", "message": "لینک کانفیگ باید vless یا trojan باشد"}
    
    conn = get_db_connection()
    try:
        conn.execute("INSERT INTO xray_links (link) VALUES (?)", (link,))
        conn.commit()
        msg = "کانفیگ ذخیره شد."
    except sqlite3.IntegrityError:
        msg = "این کانفیگ از قبل ذخیره شده بود."
    finally: conn.close()
    return {"status": "success", "message": msg}

@app.post("/api/delete_link")
async def delete_link(data: dict):
    value = data.get("value")
    conn = get_db_connection()
    conn.execute("DELETE FROM xray_links WHERE link = ?", (value,))
    conn.commit()
    conn.close()
    return {"status": "success"}

if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=8000)