import sys
import traceback

# --- سپر ضد کرش ---
def global_exception_handler(exctype, value, tb):
    print("\n" + "="*50)
    print("❌ FATAL ERROR (برنامه با خطای زیر متوقف شد):")
    print("="*50)
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

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_FILE = os.path.join(BASE_DIR, "config.json")
LOG_FILE = os.path.join(BASE_DIR, "ip_changes.log")
XRAY_EXE_NAME = "xray.exe" if os.name == "nt" else "xray"
XRAY_PATH = os.path.join(BASE_DIR, XRAY_EXE_NAME)

def load_config():
    if not os.path.exists(CONFIG_FILE):
        print(f"[-] Error: '{CONFIG_FILE}' not found! Please create it first.")
        input("\nPress Enter to exit...")
        sys.exit(1)
    with open(CONFIG_FILE, "r", encoding="utf-8") as f:
        return json.load(f)

def get_current_dns_ip(domain):
    try:
        return socket.gethostbyname(domain)
    except Exception:
        return None

async def test_single_packet(ip, port, timeout):
    try:
        start_time = time.time()
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port), timeout=timeout
        )
        writer.close()
        await writer.wait_closed()
        return (time.time() - start_time) * 1000
    except:
        return None

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
            if latency is not None:
                latencies.append(latency)
            await asyncio.sleep(0.2)
        
        success_rate = (len(latencies) / test_count) * 100
        if success_rate < 100:
            return (ip, float('inf'), success_rate, float('inf'), float('inf'))
            
        avg_latency = sum(latencies) / len(latencies)
        jitter = max(latencies) - min(latencies)
        
        if avg_latency > 250 or jitter > 30:
            return (ip, float('inf'), success_rate, avg_latency, jitter)
            
        score = avg_latency + (jitter * 5)
        return (ip, score, success_rate, avg_latency, jitter)

def verify_real_traffic(ip, domain):
    headers = {"Host": domain}
    max_retries = 2
    for attempt in range(max_retries):
        try:
            start_time = time.time()
            response = requests.get(
                f"https://{ip}/cdn-cgi/trace", 
                headers=headers, 
                timeout=5.0,
                verify=False
            )
            if "cloudflare" in response.text.lower() or response.headers.get("Server", "").lower() == "cloudflare":
                return time.time() - start_time
        except requests.exceptions.Timeout:
            time.sleep(0.5)
            continue
        except Exception:
            break
    return float('inf')

def link_to_xray_config(link, target_ip):
    try:
        parsed = urlparse(link)
        protocol = parsed.scheme
        
        if protocol not in ["vless", "trojan"]:
            return None

        user_info = parsed.username 
        original_host = parsed.hostname
        port = parsed.port if parsed.port else 443
        params = {k: v[0] for k, v in parse_qs(parsed.query).items()}
        
        config = {
            "log": {"loglevel": "warning"},
            "inbounds": [
                {
                    "port": 40808,
                    "listen": "127.0.0.1",
                    "protocol": "socks",
                    "settings": {"auth": "noauth", "udp": True}
                }
            ],
            "outbounds": [
                {
                    "protocol": protocol,
                    "settings": {"servers": []},
                    "streamSettings": {}
                }
            ]
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
            stream_settings["tlsSettings"] = {
                "serverName": sni,
                "allowInsecure": is_insecure
            }
            if "alpn" in params:
                stream_settings["tlsSettings"]["alpn"] = unquote(params["alpn"]).split(",")
            if "fp" in params:
                stream_settings["tlsSettings"]["fingerprint"] = params["fp"]
                
        elif security_type == "reality":
            stream_settings["realitySettings"] = {
                "show": False,
                "serverName": sni,
                "publicKey": params.get("pbk", ""),
                "shortId": params.get("sid", ""),
                "spiderX": params.get("spx", ""),
                "fingerprint": params.get("fp", "chrome")
            }
            
        if network_type == "ws":
            host_header = params.get("host", sni)
            path = unquote(params.get("path", "/"))
            stream_settings["wsSettings"] = {
                "path": path,
                "host": host_header
            }
        elif network_type == "grpc":
            stream_settings["grpcSettings"] = {
                "serviceName": params.get("serviceName", ""),
                "multiMode": True if params.get("mode", "multi") == "multi" else False
            }
            
        return config
    except Exception as e:
        print(f"[-] Config Link Parse Error: {e}")
        return None

def test_with_xray(ip, xray_path, config_link):
    if not os.path.exists(xray_path):
        print(f"\n[-] Xray core not found at: {xray_path}")
        return float('inf')
        
    config_dict = link_to_xray_config(config_link, ip)
    if not config_dict:
        return float('inf')

    fd, temp_config_path = tempfile.mkstemp(suffix=".json")
    with os.fdopen(fd, 'w', encoding='utf-8') as f:
        json.dump(config_dict, f, indent=2)

    debug_log_path = os.path.join(BASE_DIR, "xray_debug.log")
    xray_process = None
    
    try:
        with open(debug_log_path, "w", encoding="utf-8") as log_file:
            xray_process = subprocess.Popen(
                [xray_path, "-c", temp_config_path],
                stdout=log_file,
                stderr=log_file
            )
        
        time.sleep(3)
        
        if xray_process.poll() is not None:
            return float('inf')
            
        proxies = {
            "http": "socks5h://127.0.0.1:40808",
            "https": "socks5h://127.0.0.1:40808"
        }
        
        start_time = time.time()
        response = requests.get("https://cloudflare.com/cdn-cgi/trace", proxies=proxies, timeout=7.0, verify=False)
        
        if response.status_code == 200:
            return time.time() - start_time
            
    except Exception as py_err:
        with open(debug_log_path, "a", encoding="utf-8") as log_file:
            log_file.write(f"\n[Python Side Error] Connection failed via proxy: {py_err}\n")
    finally:
        if xray_process:
            xray_process.terminate()
            xray_process.wait()
        try:
            os.remove(temp_config_path)
        except:
            pass

    return float('inf')

def update_cloudflare(best_ip, config):
    cf = config["cloudflare"]
    url = f"https://api.cloudflare.com/client/v4/zones/{cf['zone_id']}/dns_records/{cf['record_id']}"
    headers = {
        "Authorization": f"Bearer {cf['api_token']}",
        "Content-Type": "application/json"
    }
    data = {"type": "A", "name": cf["domain_name"], "content": best_ip, "ttl": 60, "proxied": False}
    try:
        response = requests.put(url, headers=headers, json=data)
        return response.status_code == 200
    except:
        return False

def write_to_log(status_tag, old_ip, new_ip, success, avg, jitter):
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_entry = (
        f"==================================================\n"
        f"📅 Time:         {now}\n"
        f"🔄 Status:       {status_tag}\n"
        f"❌ Old IP:        {old_ip}\n"
        f"✨ New IP:        {new_ip}\n"
        f"📊 Success Rate:  {success}%\n"
        f"⚡ TCP Avg Ping:  {avg:.2f} ms\n"
        f"📉 TCP Jitter:    {jitter:.2f} ms\n"
        f"==================================================\n\n"
    )
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(log_entry)

async def main():
    print("=== Auto Cloudflare DNS Updater (Flexible DPI + Xray Stage 3 Version) ===")
    config = load_config()
    domain = config["cloudflare"]["domain_name"]
    ip_prefixes = config["scanner"].get("ip_prefixes", [])
    
    if not ip_prefixes:
        print("[-] Error: 'ip_prefixes' missing or empty in config.json!")
        return

    ips_to_test = []
    for prefix in ip_prefixes:
        ips_to_test.extend([f"{prefix}{i}" for i in range(1, 255)])

    max_workers = min(config["scanner"]["max_workers"], 50)
    current_dns_ip = get_current_dns_ip(domain)
    
    print(f"[*] Current Live IP on DNS: {current_dns_ip}")
    
    if current_dns_ip and current_dns_ip not in ips_to_test:
        ips_to_test.append(current_dns_ip)
        print(f"[*] Added current IP ({current_dns_ip}) to the scan pool to compete!")

    print(f"[*] Loaded {len(ip_prefixes)} ranges. Total IPs to scan: {len(ips_to_test)}")
    print("[*] Stage 1: Running fast stability scan (TCP Check)...")
    
    start_time = time.time()
    semaphore = asyncio.Semaphore(max_workers)
    
    tasks = [measure_stability(ip, semaphore, config) for ip in ips_to_test]
    results = await asyncio.gather(*tasks)
    
    valid_results = [r for r in results if r[1] != float('inf')]
    
    if not valid_results:
        print("[-] No stable IPs found in Stage 1.")
        return
        
    valid_results.sort(key=lambda x: x[1])
    top_candidates = valid_results[:15]
    
    print(f"[*] Stage 1 finished in {time.time() - start_time:.2f}s. Found {len(top_candidates)} top candidates.")
    print("[*] Stage 2: Verifying real-world traffic via HTTPS...")
    
    stage2_passed_candidates = []
    
    # متغیرهایی برای ذخیره عملکرد آی‌پی فعلی در استیج ۲
    current_ip_stage2_latency = float('inf')
    current_ip_stage2_stats = None
    
    for index, candidate in enumerate(top_candidates):
        cand_ip, cand_score, cand_success, cand_avg, cand_jitter = candidate
        is_current_tag = " (Current DNS)" if cand_ip == current_dns_ip else ""
        
        print(f"    [{index+1}/{len(top_candidates)}] Testing {cand_ip}{is_current_tag} (TCP Ping: {cand_avg:.1f}ms)...", end=" ", flush=True)
        real_latency = verify_real_traffic(cand_ip, domain)
        if real_latency != float('inf'):
            print(f"PASSED (Latency: {real_latency*1000:.1f}ms)")
            stage2_passed_candidates.append((candidate, real_latency))
            
            if cand_ip == current_dns_ip:
                current_ip_stage2_latency = real_latency
                current_ip_stage2_stats = candidate
        else:
            print("FAILED")
            
    if stage2_passed_candidates:
        stage2_passed_candidates.sort(key=lambda x: x[1])
        stage2_best_candidate = stage2_passed_candidates[0][0]
        stage2_best_ip = stage2_best_candidate[0]
        stage2_best_stats = stage2_best_candidate
        stage2_best_real_latency = stage2_passed_candidates[0][1]
        stage2_tag = "(VERIFIED-HTTPS)"
    else:
        stage2_best_candidate = top_candidates[0]
        stage2_best_ip = top_candidates[0][0]
        stage2_best_stats = top_candidates[0]
        stage2_best_real_latency = float('inf')
        stage2_tag = "(FALLBACK-TCP)"

    print("\n[*] Stage 3: Decoding links and testing stability with Xray-Core...")
    xray_links = config.get("xray_links", [])
    
    absolute_best_ip = None
    best_stats = None
    best_real_latency = float('inf')
    fallback_tag = None
    
    # متغیرهایی برای ذخیره بهترین عملکرد آی‌پی فعلی در استیج ۳
    current_ip_xray_latency = float('inf')
    current_ip_xray_stats = None
    best_proto_tag = ""
    
    if not xray_links:
        print("[*] No xray links found in config.json. Skipping Stage 3.")
        absolute_best_ip = stage2_best_ip
        best_stats = stage2_best_stats
        best_real_latency = stage2_best_real_latency
        fallback_tag = stage2_tag
    else:
        if stage2_passed_candidates:
            candidates_to_test_xray = [c[0] for c in stage2_passed_candidates]
        else:
            candidates_to_test_xray = top_candidates
            
        best_xray_latency = float('inf')
        best_xray_ip = None
        best_xray_stats = None
        
        print(f"[*] Testing {len(candidates_to_test_xray)} passed IPs against {len(xray_links)} Xray links...")
        for idx, candidate in enumerate(candidates_to_test_xray):
            cand_ip = candidate[0]
            is_current_tag = " (Current DNS)" if cand_ip == current_dns_ip else ""
            print(f"    [{idx+1}/{len(candidates_to_test_xray)}] Testing IP: {cand_ip}{is_current_tag}")
            
            for l_idx, link in enumerate(xray_links):
                proto = "VLESS" if link.startswith("vless://") else "TROJAN" if link.startswith("trojan://") else "XRAY"
                print(f"      -> {proto} Link #{l_idx+1}...", end=" ", flush=True)
                
                xray_latency = test_with_xray(cand_ip, XRAY_PATH, link)
                if xray_latency != float('inf'):
                    print(f"PASSED ({xray_latency*1000:.1f}ms)")
                    
                    # ذخیره مشخصات عملکردی آی‌پی فعلی در صورت موفقیت تونل
                    if cand_ip == current_dns_ip and xray_latency < current_ip_xray_latency:
                        current_ip_xray_latency = xray_latency
                        current_ip_xray_stats = candidate
                    
                    if xray_latency < best_xray_latency:
                        best_xray_latency = xray_latency
                        best_xray_ip = cand_ip
                        best_xray_stats = candidate
                        best_proto_tag = proto
                else:
                    print("FAILED")
        
        if best_xray_ip:
            absolute_best_ip = best_xray_ip
            best_stats = best_xray_stats
            best_real_latency = best_xray_latency
            fallback_tag = f"(VERIFIED-{best_proto_tag})"
            print(f"\n[+] 🎯 Xray-Core confirmed working IP: {absolute_best_ip}")
        else:
            print("\n[-] All candidates failed Xray Stage 3. Falling back to Stage 2 winner...")
            absolute_best_ip = stage2_best_ip
            best_stats = stage2_best_stats
            best_real_latency = stage2_best_real_latency
            fallback_tag = stage2_tag

    # ----------------------------------------------------------------------
    # 🔥 هوشمندسازی نهایی: سیستم اولویت‌دهی و وفاداری به آی‌پي فعلی کلودفلر
    # ----------------------------------------------------------------------
    # حاشیه امنیت پایداری بر حسب ثانیه (0.025 ثانیه = 25 میلی‌ثانیه)
    LATENCY_THRESHOLD = 25.0 / 1000.0 
    
    # مشخص کردن آخرین وضعیت پینگ آی‌پی فعلی (اگر در مرحله ۳ پاس شده بود لیتنسی ۳، وگرنه لیتنسی ۲)
    current_working_latency = current_ip_xray_latency if xray_links else current_ip_stage2_latency
    current_working_stats = current_ip_xray_stats if xray_links else current_ip_stage2_stats
    
    # اگر آی‌پی فعلی زنده بود و قهرمانِ رقابت‌ها یک آی‌پی جدید بود:
    if current_working_latency != float('inf') and absolute_best_ip != current_dns_ip:
        latency_diff = current_working_latency - best_real_latency
        
        # اگر اختلاف پینگ آی‌پی جدید با آی‌پی فعلی کمتر از ۲۵ میلی‌ثانیه بود، تغییرش نده!
        if latency_diff < LATENCY_THRESHOLD:
            print(f"\n[*] Anti-Hopping Protection: Current DNS IP ({current_dns_ip}) is still solid.")
            print(f"[*] New IP is faster by only {latency_diff * 1000:.1f}ms (Threshold is 25ms).")
            print("[*] Decided to KEEP the current IP to maintain connection stability.")
            
            absolute_best_ip = current_dns_ip
            best_stats = current_working_stats
            best_real_latency = current_working_latency
            fallback_tag = "(RETAINED-CURRENT)"
    # ----------------------------------------------------------------------

    _, _, best_success, best_avg, best_jitter = best_stats
    
    print("-" * 50)
    print(f"[+] 🏆 FINAL SELECTED IP: {absolute_best_ip}")
    print(f"    - TCP Ping Avg: {best_avg:.2f} ms | Jitter: {best_jitter:.2f} ms")
    if best_real_latency != float('inf'):
        print(f"    - Real Tunnel Latency: {best_real_latency*1000:.2f} ms")
    print("-" * 50)
    
    if current_dns_ip == absolute_best_ip:
        print(f"[*] DNS is already pointing to the best IP. Skipping update.")
        write_to_log(f"NO CHANGE {fallback_tag}", current_dns_ip, absolute_best_ip, best_success, best_avg, best_jitter)
    else:
        print(f"[!] Better IP found! Updating Cloudflare...")
        if update_cloudflare(absolute_best_ip, config):
            print(f"[+] SUCCESS: DNS updated to {absolute_best_ip}")
            write_to_log(f"IP CHANGED {fallback_tag}", current_dns_ip, absolute_best_ip, best_success, best_avg, best_jitter)
        else:
            print("[-] FAILED to update Cloudflare DNS.")

if __name__ == "__main__":
    try:
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    except AttributeError:
        pass
    try:
        asyncio.run(main())
    finally:
        input("\n[!] Scan completed. Press Enter to exit...")