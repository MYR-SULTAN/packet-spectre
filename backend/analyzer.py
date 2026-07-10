import os
import re
import sys
import math
import collections
from datetime import datetime

# Safe Scapy import
try:
    from scapy.utils import PcapReader
    from scapy.layers.l2 import Ether, ARP
    from scapy.layers.inet import IP, TCP, UDP, ICMP
    from scapy.layers.inet6 import IPv6
    from scapy.layers.dns import DNS, DNSQR, DNSRR
    from scapy.layers.dhcp import DHCP, BOOTP
    from scapy.config import conf
    try:
        from scapy.layers.tls.all import TLS, TLSApplicationData
    except ImportError:
        pass
except ImportError:
    # We will install it in the virtual environment later
    pass

class PacketSpectreAnalyzer:
    def __init__(self, pcap_path, keylog_path=None):
        self.pcap_path = pcap_path
        self.keylog_path = keylog_path
        self.total_bytes = os.path.getsize(pcap_path) if os.path.exists(pcap_path) else 0
        
        # Configure TLS decryption keys if keylog_path is provided
        if keylog_path and os.path.exists(keylog_path):
            try:
                conf.tls_keylog = keylog_path
                print(f"[+] Loaded TLS keylog: {keylog_path}")
            except Exception as e:
                print(f"[-] Failed to load keylog file in Scapy: {e}")
        
        # General statistics
        self.packet_count = 0
        self.duration = 0.0
        self.first_packet_time = None
        self.last_packet_time = None
        self.total_payload_bytes = 0
        
        # Protocols count
        self.protocols = collections.defaultdict(int)
        
        # Hosts inventory: IP -> {mac, os_guess, sent_packets, recv_packets, sent_bytes, recv_bytes, open_ports: set, mac_vendors: set}
        self.hosts = {}
        
        # Conversations: (src_ip, dst_ip, proto) -> {packets, bytes}
        self.conversations = collections.defaultdict(lambda: {"packets": 0, "bytes": 0})
        
        # DNS data: domain -> {ips: set, query_count: 0}
        self.dns_mappings = {}
        
        # TCP states tracking: connection_key -> state
        # connection_key = (src_ip, src_port, dst_ip, dst_port)
        self.tcp_connections = collections.defaultdict(list)
        self.tcp_retransmissions = 0
        self.tcp_resets = 0
        self.tcp_handshake_failures = 0
        self.tcp_successful_handshakes = 0
        
        # Active TCP seq numbers to detect retransmissions
        # (src_ip, dst_ip, src_port, dport) -> set(seq_numbers)
        self.tcp_seq_numbers = collections.defaultdict(set)
        
        # Port Scanning detection
        # src_ip -> set(dst_ports)
        self.port_scan_tracker = collections.defaultdict(set)
        self.port_scan_alerts = {}  # src_ip -> {ports_scanned, type}
        
        # ARP Spoofing detection
        # ip -> set(macs)
        self.arp_ip_mac_map = collections.defaultdict(set)
        
        # Plaintext credential leaks
        self.credential_leaks = [] # list of dicts: {timestamp, ip_src, ip_dst, protocol, type, leak_detail}
        
        # IT & Network Infrastructure Diagnostics
        self.icmp_errors = []
        self.dns_failures = []
        self.connection_timeouts = []
        self.tcp_handshake_rtts = []
        self.syn_times = {}
        
        self.tcp_zero_window_events = []
        self.dns_query_times = {}
        self.dns_latencies = []
        self.throughput_bins = collections.defaultdict(int)
        self.port_traffic = collections.defaultdict(int)
        
        # Common credentials keywords
        self.cred_pattern = re.compile(
            r'(password|passwd|pass|username|user|usr|login|signin|admin|email|token|bearer|apikey|authorization|auth|secret|key|cookie)\b', 
            re.IGNORECASE
        )
        
        # Custom DNS Anomalies
        self.dns_anomalies = [] # list of dicts: {timestamp, client_ip, query, type, reason}
        
        # Unencrypted Protocols Alerts
        self.unencrypted_protocols_used = set()
        
        # Malware detections
        self.malware_detections = [] # list of dicts: {timestamp, title, details, meta, severity}
        
        # Advanced Brute Force & Sweep trackers
        self.ftp_failed_logins = collections.defaultdict(int)
        self.web_brute_force_tracker = collections.defaultdict(int)
        self.arp_sweep_tracker = collections.defaultdict(set)
        self.icmp_sweep_tracker = collections.defaultdict(set)
        
        # Advanced DLP & Web Attack trackers
        self.web_404_tracker = collections.defaultdict(int)
        self.cc_pattern = re.compile(r'\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14})\b')
        self.api_key_pattern = re.compile(r'\b(AIza[0-9A-Za-z-_]{35}|AKIA[0-9A-Z]{16})\b')
        
        # DoS/DDoS Flooding & SMB trackers
        self.syn_flood_tracker = collections.defaultdict(int)
        self.udp_flood_tracker = collections.defaultdict(int)
        self.smb_write_tracker = collections.defaultdict(int)
        
        # Digital Forensics (DFIR) trackers
        self.forensic_files_carved = []
        self.connection_timestamps = collections.defaultdict(list)
        self.beaconing_alerts = []
        self.dns_spoof_tracker = collections.defaultdict(list)
        self.forensic_exfiltrations = []

    def get_progress(self, reader):
        """
        Calculates the progress percentage of parsing the PCAP.
        """
        if self.total_bytes == 0:
            return 100.0
        try:
            offset = reader.f.tell()
            return round((offset / self.total_bytes) * 100.0, 1)
        except Exception:
            return 0.0

    def calculate_entropy(self, text):
        if not text:
            return 0.0
        entropy = 0.0
        length = len(text)
        frequencies = collections.Counter(text)
        for count in frequencies.values():
            p = count / length
            entropy -= p * math.log2(p)
        return entropy

    def generate_hex_ascii_dump(self, payload):
        chunk = payload[:256]
        lines = []
        for i in range(0, len(chunk), 16):
            sub = chunk[i:i+16]
            hex_part = " ".join(f"{b:02X}" for b in sub)
            hex_part = hex_part.ljust(47)
            ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in sub)
            lines.append(f"{i:04X}  {hex_part}  |{ascii_part}|")
        return "\n".join(lines)

    def guess_os_from_ttl(self, ttl):
        """
        Heuristically guesses the Operating System based on the IP TTL value.
        """
        if ttl <= 64:
            return "Linux / Android / macOS / iOS"
        elif ttl <= 128:
            return "Windows"
        elif ttl <= 255:
            return "Unix / Cisco / Router"
        return "Unknown"

    def detect_malware_signatures(self, payload, src_ip, dst_ip, sport, dport, timestamp_str):
        try:
            # Check njRAT splitter
            if b"|'|'|" in payload or b"[|'|']" in payload:
                self.malware_detections.append({
                    "timestamp": timestamp_str,
                    "title": "كشف نشاط njRAT RAT",
                    "details": "تم رصد علامة الفصل الخاصة بـ njRAT (|'|'|) في مجرى بيانات TCP. هذا يشير إلى وجود برنامج تحكم عن بعد (njRAT) نشط.",
                    "meta": f"المصدر: {src_ip}:{sport} -> {dst_ip}:{dport}",
                    "severity": "critical"
                })
            # Check Xworm signature
            elif b"<XWORM>" in payload or b"XWORM" in payload:
                if b"<XWORM>" in payload or (b"Xworm" in payload and len(payload) < 500):
                    self.malware_detections.append({
                        "timestamp": timestamp_str,
                        "title": "كشف نشاط Xworm RAT",
                        "details": "تم رصد علامات بروتوكول Xworm في مجرى البيانات. هذا يشير إلى اتصال نشط لبرنامج خبيث من نوع Xworm RAT.",
                        "meta": f"المصدر: {src_ip}:{sport} -> {dst_ip}:{dport}",
                        "severity": "critical"
                    })
            # Check Lumma Stealer User-Agent
            elif b"TeslaBrowser/5.5" in payload:
                self.malware_detections.append({
                    "timestamp": timestamp_str,
                    "title": "كشف برمجية Lumma Stealer (سرقة بيانات)",
                    "details": "تم رصد اسم المتصفح الخاص بـ Lumma Stealer (TeslaBrowser/5.5) في ترويسات HTTP. هذه حركة مرور مؤكدة لسرقة البيانات exfiltration.",
                    "meta": f"المصدر: {src_ip}:{sport} -> {dst_ip}:{dport}",
                    "severity": "critical"
                })
            # Check Telegram Bot API exfiltration (used by AMOS / Atomic Stealer and macOS stealers)
            elif b"api.telegram.org/bot" in payload:
                self.malware_detections.append({
                    "timestamp": timestamp_str,
                    "title": "تسريب بيانات عبر Telegram Bot (AMOS/Stealer)",
                    "details": "تم رصد اتصال بـ Telegram Bot API لرفع ملفات أو إرسال وثائق. هذا السلوك شائع جداً في برمجيات سرقة البيانات على macOS (مثل AMOS و Shub Stealer) لتهريب البيانات المسروقة.",
                    "meta": f"المصدر: {src_ip}:{sport} -> {dst_ip}:{dport} (api.telegram.org)",
                    "severity": "critical"
                })
            # Check macOS specific paths in cleartext payloads (AMOS/Stealer file exfiltration indicators)
            elif any(x in payload for x in [b"Library/Application Support", b".keychain", b"Keychain.db", b"cookies.sqlite"]):
                self.malware_detections.append({
                    "timestamp": timestamp_str,
                    "title": "تسريب ملفات نظام macOS حساسة",
                    "details": "تم رصد مسارات ملفات Keychain أو Application Support الحساسة لنظام macOS في مجرى الاتصال غير المشفر. هذا يشير إلى سرقة ملفات النظام وهجوم Stealer نشط.",
                    "meta": f"المصدر: {src_ip}:{sport} -> {dst_ip}:{dport}",
                    "severity": "critical"
                })
            # Check NetSupport RAT configurations or requests
            elif any(x in payload for x in [b"/support/g2.php", b"/client/project.txt", b"remotesupport"]):
                self.malware_detections.append({
                    "timestamp": timestamp_str,
                    "title": "كشف نشاط NetSupport RAT",
                    "details": "تم رصد طلبات برمجية NetSupport Manager المعدلة للتحكم غير المصرح به (RAT) مثل طلبات g2.php أو ملفات المشروع.",
                    "meta": f"المصدر: {src_ip}:{sport} -> {dst_ip}:{dport}",
                    "severity": "critical"
                })
            # Check FTP exfiltration
            elif b"STOR " in payload and (sport == 21 or dport == 21):
                try:
                    filename = payload.split(b"STOR ")[1].split(b"\r\n")[0].decode('utf-8', errors='ignore')
                    self.malware_detections.append({
                        "timestamp": timestamp_str,
                        "title": "تهريب بيانات عبر بروتوكول FTP (AgentTesla/VIP Recovery)",
                        "details": f"تم رصد عملية رفع ملف حساسة باستخدام أمر (STOR) للملف: '{filename}'. هذا السلوك يطابق تكتيكات تهريب البيانات (Exfiltration) لبرمجيات AgentTesla و VIP Recovery.",
                        "meta": f"المصدر: {src_ip}:{sport} -> {dst_ip}:{dport}",
                        "severity": "critical"
                    })
                except Exception:
                    pass
            
            # --- Expanded Detections ---
            # Safe payload decoding for text checks
            decoded = payload.decode('utf-8', errors='ignore')
            decoded_lower = decoded.lower()
            
            # 1. Hacking & Scanner User-Agents
            if "sqlmap" in decoded_lower:
                self.malware_detections.append({
                    "timestamp": timestamp_str,
                    "title": "محاولة اختراق بقاعدة البيانات (Sqlmap)",
                    "details": "تم رصد بصمة أداة حقن وقراءة قواعد البيانات Sqlmap في طلبات HTTP. يشير هذا لاستهداف نشط ومحاولات استغلال ثغرات SQLi.",
                    "meta": f"المصدر: {src_ip}:{sport} -> {dst_ip}:{dport}",
                    "severity": "critical"
                })
            elif "nikto" in decoded_lower:
                self.malware_detections.append({
                    "timestamp": timestamp_str,
                    "title": "فحص ثغرات ويب (Nikto Scan)",
                    "details": "تم رصد أداة فحص خوادم الويب Nikto. هذا السلوك استطلاعي نشط للبحث عن إعدادات خادئة وملفات حساسة.",
                    "meta": f"المصدر: {src_ip}:{sport} -> {dst_ip}:{dport}",
                    "severity": "warning"
                })
            elif "nmap" in decoded_lower:
                self.malware_detections.append({
                    "timestamp": timestamp_str,
                    "title": "فحص شبكة نشط (Nmap NSE)",
                    "details": "تم رصد بصمة محرك سكربتات Nmap (Nmap Scripting Engine) في الطلبات. يشير هذا لفحص الخدمات والثغرات بنشاط.",
                    "meta": f"المصدر: {src_ip}:{sport} -> {dst_ip}:{dport}",
                    "severity": "warning"
                })
            elif "gobuster" in decoded_lower or "dirbuster" in decoded_lower:
                self.malware_detections.append({
                    "timestamp": timestamp_str,
                    "title": "تخمين مسارات ويب (Directory Bruteforce)",
                    "details": "تم رصد استخدام أدوات تخمين الأدلة والملفات (Gobuster/DirBuster). المهاجم يبحث عن لوحات تحكم أو ملفات نسخ احتياطي.",
                    "meta": f"المصدر: {src_ip}:{sport} -> {dst_ip}:{dport}",
                    "severity": "warning"
                })
            
            # 2. HTTP Web Attacks (SQLi, XSS, Path Traversal, Log4j)
            if "union select" in decoded_lower or "or 1=1" in decoded_lower or "sysdatabases" in decoded_lower:
                self.malware_detections.append({
                    "timestamp": timestamp_str,
                    "title": "محاولة حقن قواعد البيانات (SQL Injection)",
                    "details": "تم رصد كلمات مفتاحية لحقن استعلامات SQL (مثل UNION SELECT أو OR 1=1). مهاجم يحاول سرقة أو تخطي حماية قواعد البيانات.",
                    "meta": f"المصدر: {src_ip}:{sport} -> {dst_ip}:{dport}",
                    "severity": "critical"
                })
            if "<script>" in decoded_lower or "onerror=" in decoded_lower or "javascript:" in decoded_lower:
                self.malware_detections.append({
                    "timestamp": timestamp_str,
                    "title": "محاولة اختراق متصفح (XSS Injection)",
                    "details": "تم رصد محاولة إدخال كود جافا سكربت خبيث (Cross-Site Scripting). مهاجم يحاول سرقة كوكيز الجلسات والتنصت على المستخدمين.",
                    "meta": f"المصدر: {src_ip}:{sport} -> {dst_ip}:{dport}",
                    "severity": "critical"
                })
            if "../" in decoded_lower or "..%2f" in decoded_lower or "/etc/passwd" in decoded_lower or "win.ini" in decoded_lower:
                self.malware_detections.append({
                    "timestamp": timestamp_str,
                    "title": "محاولة قراءة ملفات النظام (Path Traversal)",
                    "details": "تم رصد محاولة الرجوع للمجلدات الأبوية (../) أو قراءة ملفات حساسة كـ etc/passwd. مهاجم يسعى لقراءة إعدادات السيرفر وسرقة مفاتيح الحماية.",
                    "meta": f"المصدر: {src_ip}:{sport} -> {dst_ip}:{dport}",
                    "severity": "critical"
                })
            if "${jndi:ldap://" in decoded_lower or "${jndi:rmi://" in decoded_lower:
                self.malware_detections.append({
                    "timestamp": timestamp_str,
                    "title": "استغلال ثغرة Log4Shell (Log4j)",
                    "details": "تم رصد محاولة استغلال ثغرة Log4j الشهيرة عبر بروتوكول JNDI/LDAP. هذه محاولة اختراق خطيرة جداً للتحكم بالسيرفر عن بعد.",
                    "meta": f"المصدر: {src_ip}:{sport} -> {dst_ip}:{dport}",
                    "severity": "critical"
                })
                
            # 3. Suspicious hacker ports
            if dport in [4444, 1337, 31337] or sport in [4444, 1337, 31337]:
                self.malware_detections.append({
                    "timestamp": timestamp_str,
                    "title": "اتصال عبر منفذ اختراق مشبوه",
                    "details": f"تم رصد اتصال خارجي على منفذ مشبوه جداً ({dport if sport not in [4444, 1337, 31337] else sport}) يرتبط افتراضياً بأدوات الاختراق والتحكم (منفذ 4444 لـ Metasploit، أو 1337 للبرمجيات الخبيثة).",
                    "meta": f"المصدر: {src_ip}:{sport} -> {dst_ip}:{dport}",
                    "severity": "critical"
                })
                
            # 4. Command Line / PowerShell Downloaders
            if "windowspowershell" in decoded_lower and any(kw in decoded_lower for kw in ["downloadstring", "downloadfile", "invoke-webrequest"]):
                self.malware_detections.append({
                    "timestamp": timestamp_str,
                    "title": "تحميل ملف خبيث عبر PowerShell",
                    "details": "تم رصد محاولة تنزيل ملف من الإنترنت وتشغيله عبر أوامر PowerShell التلقائية (DownloadString/Invoke-WebRequest). تكتيك أساسي للـ Droppers.",
                    "meta": f"المصدر: {src_ip}:{sport} -> {dst_ip}:{dport}",
                    "severity": "critical"
                })
            elif "curl/" in decoded_lower or "wget/" in decoded_lower:
                if any(ext in decoded_lower for ext in [".sh", ".exe", ".ps1", ".bat", ".elf", ".bin"]):
                    self.malware_detections.append({
                        "timestamp": timestamp_str,
                        "title": "تنزيل سكربت تنفيذي عبر Terminal (Curl/Wget)",
                        "details": "تم رصد أداة Curl أو Wget تقوم بتحميل ملف تنفيذي أو سكربت. قد يشير ذلك إلى تثبيت برمجية خبيثة عبر سطر الأوامر.",
                        "meta": f"المصدر: {src_ip}:{sport} -> {dst_ip}:{dport}",
                        "severity": "warning"
                    })
            
            # 5. Web brute force check
            if "POST " in decoded and any(x in decoded_lower for x in ["/login", "/signin", "/wp-login", "/admin"]):
                self.web_brute_force_tracker[src_ip] += 1
                if self.web_brute_force_tracker[src_ip] == 15:
                    self.malware_detections.append({
                        "timestamp": timestamp_str,
                        "title": "محاولة تخمين حسابات ويب (HTTP Brute Force)",
                        "details": "تم رصد محاولات إرسال طلبات تسجيل دخول POST متكررة بشكل غير اعتيادي. يشير هذا لهجوم تخمين كلمات مرور (Credential Stuffing / Brute Force).",
                        "meta": f"المصدر: {src_ip} -> {dst_ip}",
                        "severity": "critical"
                    })
            
            # 6. FTP brute force check
            if (sport == 21 or dport == 21) and "530 " in decoded:
                self.ftp_failed_logins[dst_ip] += 1
                if self.ftp_failed_logins[dst_ip] == 5:
                    self.malware_detections.append({
                        "timestamp": timestamp_str,
                        "title": "محاولة تخمين حسابات FTP (FTP Brute Force)",
                        "details": "تم رصد 5 محاولات تسجيل دخول فاشلة متكررة (FTP 530 error). يشير هذا لهجوم تخمين كلمات مرور نشط على خدمة FTP.",
                        "meta": f"المهاجم: {dst_ip} -> الخادم: {src_ip}",
                        "severity": "critical"
                    })
            
            # 7. Weak TLS check
            if len(payload) > 5 and payload[0] == 0x16 and payload[1] == 0x03 and payload[2] in [0x00, 0x01, 0x02]:
                tls_version = "SSLv3" if payload[2] == 0x00 else "TLS 1.0" if payload[2] == 0x01 else "TLS 1.1"
                self.malware_detections.append({
                    "timestamp": timestamp_str,
                    "title": "استخدم بروتوكول تشفير ضعيف (Weak SSL/TLS)",
                    "details": f"تم رصد اتصال يستخدم بروتوكول تشفير قديم وغير آمن ({tls_version}) وهو عرضة للاختراق وفك التشفير.",
                    "meta": f"المصدر: {src_ip}:{sport} -> {dst_ip}:{dport}",
                    "severity": "warning"
                })
                
            # 8. Additional C2 and Attack User-Agents
            if any(tool in decoded_lower for tool in ["hydra", "medusa", "wfuzz", "acunetix", "zap/", "havoc", "cobaltstrike", "sliver"]):
                matched_tool = [tool for tool in ["hydra", "medusa", "wfuzz", "acunetix", "zap", "havoc", "cobaltstrike", "sliver"] if tool in decoded_lower][0]
                self.malware_detections.append({
                    "timestamp": timestamp_str,
                    "title": f"كشف استخدام أداة هجومية ({matched_tool.upper()})",
                    "details": f"تم رصد بصمة الأداة الهجومية أو إطار التحكم C2 المسمى ({matched_tool.upper()}) في حركة المرور. يشير هذا لنشاط اختراق أو تحكم خارجي.",
                    "meta": f"المصدر: {src_ip}:{sport} -> {dst_ip}:{dport}",
                    "severity": "critical"
                })
            
            # 9. Webshell & Command Injection parameters
            if any(param in decoded_lower for param in ["?cmd=", "&cmd=", "?exec=", "system(", "passthru(", "popen(", "shell_exec("]):
                self.malware_detections.append({
                    "timestamp": timestamp_str,
                    "title": "محاولة حقن أوامر نظام (Webshell/RCE)",
                    "details": "تم رصد محاولة إرسال أوامر تشغيل للنظام أو استدعاء دوال تنفيذ خبيثة في طلب الويب. يشير هذا لموجة اختراق RCE أو webshell نشط.",
                    "meta": f"المصدر: {src_ip}:{sport} -> {dst_ip}:{dport}",
                    "severity": "critical"
                })
            
            # 10. DLP (Data Loss Prevention) checks: Credit Card & API Key Leaks
            cc_matches = self.cc_pattern.findall(decoded)
            if cc_matches:
                self.malware_detections.append({
                    "timestamp": timestamp_str,
                    "title": "سرب بيانات حساسة (DLP - بطاقة ائتمان)",
                    "details": "تم رصد رقم بطاقة ائتمان (Visa/Mastercard) مرسل بشكل واضح وغير مشفر في الشبكة. يعرض هذا البيانات للسرقة والتنصت المباشر.",
                    "meta": f"المصدر: {src_ip}:{sport} -> {dst_ip}:{dport}",
                    "severity": "critical"
                })
            api_matches = self.api_key_pattern.findall(decoded)
            if api_matches:
                matched_key = api_matches[0]
                key_type = "Google Cloud API Key" if matched_key.startswith("AIza") else "AWS Access Key"
                self.malware_detections.append({
                    "timestamp": timestamp_str,
                    "title": f"سرب مفاتيح سحابية حساسة (DLP - {key_type})",
                    "details": f"تم رصد مفتاح مصادقة سحابي ({key_type}) مرسل بشكل مكشوف في الشبكة. قد يستغل المهاجم هذا المفتاح للوصول إلى الخدمات والملفات السحابية.",
                    "meta": f"المصدر: {src_ip}:{sport} -> {dst_ip}:{dport}",
                    "severity": "critical"
                })
                
            # 11. SSRF (Server-Side Request Forgery) attempts
            if any(x in decoded_lower for x in ["url=http", "uri=http", "link=http", "file=http"]) and any(ip in decoded_lower for ip in ["169.254.169.254", "127.0.0.1", "localhost"]):
                self.malware_detections.append({
                    "timestamp": timestamp_str,
                    "title": "محاولة اختراق السيرفر الداخلي (SSRF)",
                    "details": "تم رصد طلب ويب يحمل معلمات تحاول إجبار السيرفر على مراسلة واجهة الـ Metadata (169.254.169.254) أو المضيف المحلي (localhost). هذه محاولة استغلال ثغرة SSRF.",
                    "meta": f"المصدر: {src_ip}:{sport} -> {dst_ip}:{dport}",
                    "severity": "critical"
                })
                
            # 12. Local File Inclusion (LFI) & Remote File Inclusion (RFI)
            if any(x in decoded_lower for x in ["file=", "page=", "path=", "include="]):
                if any(path in decoded_lower for path in ["wp-config.php", "config.php", ".htaccess", "web.xml", "/etc/hosts", "/etc/passwd"]):
                    self.malware_detections.append({
                        "timestamp": timestamp_str,
                        "title": "محاولة تضمين ملفات داخلية (LFI Attempt)",
                        "details": "تم رصد طلب ويب يحاول استدعاء ملفات إعدادات حساسة للنظام أو الموقع (LFI). يسعى المهاجم لقراءة كلمات المرور أو شفرة المصدر.",
                        "meta": f"المصدر: {src_ip}:{sport} -> {dst_ip}:{dport}",
                        "severity": "critical"
                    })
                elif "http://" in decoded_lower or "https://" in decoded_lower:
                    if any(param in decoded_lower for param in ["?file=http", "&file=http", "?page=http", "&page=http", "?path=http", "&path=http"]):
                        self.malware_detections.append({
                            "timestamp": timestamp_str,
                            "title": "محاولة تضمين ملفات خارجية (RFI Attempt)",
                            "details": "تم رصد محاولة إجبار الموقع على تحميل سكربت خارجي وتشغيله (Remote File Inclusion). قد تؤدي للتحكم الكامل بالسيرفر.",
                            "meta": f"المصدر: {src_ip}:{sport} -> {dst_ip}:{dport}",
                            "severity": "critical"
                        })
            
            # 13. Command Injection / Shell execution
            if any(inj in decoded_lower for inj in [";whoami", ";whoami", "|whoami", "whoami", ";whoami", ";id", ";cat", "ping -c", "ping -n"]):
                if any(char in decoded_lower for char in ["; whoami", "&& whoami", "| whoami", "; id", "; cat", "&& cat"]):
                    self.malware_detections.append({
                        "timestamp": timestamp_str,
                        "title": "محاولة حقن أوامر نظام (Command Injection)",
                        "details": "تم رصد إدراج رموز حقن أوامر النظام (مثل ; whoami أو && cat) في المعلمات. مهاجم يسعى لتشغيل أوامر مباشرة على خادم الويب.",
                        "meta": f"المصدر: {src_ip}:{sport} -> {dst_ip}:{dport}",
                        "severity": "critical"
                    })
                    
            # 14. HTTP Response Code Anomalies (Web Directory Brute Force - 404 Spike)
            if "http/" in decoded_lower and " 404 " in decoded:
                lines = decoded.split('\r\n')
                if len(lines) > 0 and "404" in lines[0]:
                    self.web_404_tracker[dst_ip] += 1
                    if self.web_404_tracker[dst_ip] == 30:
                        self.malware_detections.append({
                            "timestamp": timestamp_str,
                            "title": "تخمين مسارات ويب (404 Path Enumeration)",
                            "details": "تم رصد عدد كبير من أخطاء الصفحات غير الموجودة (404 Not Found) من جهة العميل. يشير هذا لمسح وتخمين نشط للمجلدات والمسارات.",
                            "meta": f"العميل المستكشف: {dst_ip} -> الخادم: {src_ip}",
                            "severity": "warning"
                        })
                        
            # 15. Cryptomining Stratum protocol detection
            if any(x in decoded_lower for x in ["mining.subscribe", "mining.authorize", "mining.submit"]):
                self.malware_detections.append({
                    "timestamp": timestamp_str,
                    "title": "أنشطة تعدين عملات مشفرة (Stratum Protocol)",
                    "details": "تم رصد استخدام بروتوكول Stratum الخاص بتعدين العملات الرقمية (Cryptomining) في الشبكة. قد يشير هذا لإصابة أحد الأجهزة ببرمجية تعدين خفية (Cryptojacking).",
                    "meta": f"المصدر: {src_ip}:{sport} -> {dst_ip}:{dport}",
                    "severity": "warning"
                })
                
            # 16. Shellshock Vulnerability (CVE-2014-6271) Exploit Attempt
            if "() {" in decoded_lower and "};" in decoded_lower:
                self.malware_detections.append({
                    "timestamp": timestamp_str,
                    "title": "محاولة استغلال ثغرة Shellshock",
                    "details": "تم رصد محاولة استغلال ثغرة Shellshock (CVE-2014-6271) في ترويسات الطلب لتشغيل أوامر نظام باش (Bash) عن بعد.",
                    "meta": f"المصدر: {src_ip}:{sport} -> {dst_ip}:{dport}",
                    "severity": "critical"
                })
                
            # 17. Automated script/scraping client user agent
            if "user-agent:" in decoded_lower:
                ua_line = [line for line in decoded_lower.split("\n") if "user-agent:" in line]
                if ua_line:
                    ua_val = ua_line[0]
                    if any(lib in ua_val for lib in ["python-requests", "go-http-client", "libcurl", "java/", "apache-httpclient", "perl", "ruby"]):
                        matched_lib = [lib for lib in ["python-requests", "go-http-client", "libcurl", "java/", "apache-httpclient", "perl", "ruby"] if lib in ua_val][0]
                        self.malware_detections.append({
                            "timestamp": timestamp_str,
                            "title": "استخدام مكتبة أتمتة برمجية (Automated HTTP Script)",
                            "details": f"تم رصد طلب ويب تم إرساله بواسطة مكتبة برمجية ({matched_lib.upper()}) وليس متصفحاً حقيقياً. هذا السلوك شائع في السكربتات التلقائية ومحاولات الفحص الأمني.",
                            "meta": f"المصدر: {src_ip}:{sport} -> {dst_ip}:{dport}",
                            "severity": "warning"
                        })
                        
            # 18. Ransomware & SMB share auditing
            if sport == 445 or dport == 445:
                # Check NTLM Auth Logon Failures (c000006d status)
                if b"\x6d\x00\x00\xc0" in payload or b"\x6a\x00\x00\xc0" in payload:
                    self.malware_detections.append({
                        "timestamp": timestamp_str,
                        "title": "فشل مصادقة SMB (SMB Auth Failure)",
                        "details": "تم رصد رمز خطأ فشل مصادقة SMB (NTLM Logon Error c000006d/c000006a). تكرار هذا الخطأ قد يشير لمحاولة تخمين كلمات مرور SMB.",
                        "meta": f"المصدر: {src_ip}:{sport} -> {dst_ip}:{dport}",
                        "severity": "warning"
                    })
                # Check SMB2 Write requests (indicates active encryption/writing of ransomware)
                if b"\xfeSMB" in payload and b"\x09\x00" in payload:
                    self.smb_write_tracker[src_ip] += 1
                    if self.smb_write_tracker[src_ip] == 100:
                        self.malware_detections.append({
                            "timestamp": timestamp_str,
                            "title": "حركة كتابة مكثفة على SMB (Ransomware Threat)",
                            "details": "تم رصد عمليات كتابة SMB2 متكررة (>100 عملية) بشكل سريع للغاية. هذا المؤشر متطابق تماماً مع قيام برمجيات الفدية (Ransomware) بتشفير ملفات المشاركة على الشبكة.",
                            "meta": f"الجهاز الكاتب: {src_ip} -> خادم الملفات: {dst_ip}",
                            "severity": "critical"
                        })
        except Exception:
            pass

    def audit_forensic_evidence(self, payload, src_ip, dst_ip, sport, dport, timestamp_str, pkt_time):
        try:
            # 1. Reconstruct connection intervals for C2 Beaconing analysis
            flow_key = (src_ip, dst_ip, dport)
            if len(self.connection_timestamps[flow_key]) < 30:
                if not self.connection_timestamps[flow_key] or (pkt_time - self.connection_timestamps[flow_key][-1] > 1.5):
                    self.connection_timestamps[flow_key].append(pkt_time)

            # 2. File Signature Carving (Network Magic Bytes Carving)
            if len(payload) > 16:
                file_type = None
                magic_desc = ""
                # Executables / Binaries
                if payload.startswith(b"MZ"):
                    file_type = "EXE/DLL (Windows Executable)"
                    magic_desc = "Windows Executable or DLL binary discovered in network transit."
                elif payload.startswith(b"\x7fELF"):
                    file_type = "ELF (Linux Binary)"
                    magic_desc = "Linux Executable Linkable Format binary discovered in network transit."
                # Documents & Compressed
                elif payload.startswith(b"PK\x03\x04"):
                    file_type = "ZIP/Office (Archive/Document)"
                    magic_desc = "ZIP compressed archive or modern Microsoft Office (DOCX/XLSX) document."
                elif payload.startswith(b"%PDF"):
                    file_type = "PDF (Document)"
                    magic_desc = "Adobe Portable Document Format (PDF) file."
                # Media/Images
                elif payload.startswith(b"\x89PNG\r\n\x1a\n"):
                    file_type = "PNG (Image)"
                    magic_desc = "Portable Network Graphics image file."
                elif payload.startswith(b"\xff\xd8\xff"):
                    file_type = "JPEG (Image)"
                    magic_desc = "JPEG image file."
                
                if file_type:
                    is_duplicate = False
                    for f in self.forensic_files_carved[-5:]:
                        if f["src"] == f"{src_ip}:{sport}" and f["dst"] == f"{dst_ip}:{dport}" and f["file_type"] == file_type:
                            try:
                                t_diff = abs(pkt_time - f.get("_raw_time", 0))
                                if t_diff < 3.0:
                                    is_duplicate = True
                                    break
                            except Exception:
                                pass
                                
                    if not is_duplicate:
                        self.forensic_files_carved.append({
                            "timestamp": timestamp_str,
                            "src": f"{src_ip}:{sport}",
                            "dst": f"{dst_ip}:{dport}",
                            "file_type": file_type,
                            "details": magic_desc,
                            "size_approx": len(payload),
                            "_raw_time": pkt_time
                        })
                        
            # 3. Mismatch OS Fingerprinting (TTL vs User-Agent)
            decoded = payload.decode('utf-8', errors='ignore')
            decoded_lower = decoded.lower()
            if "user-agent:" in decoded_lower:
                guessed_os = self.hosts.get(src_ip, {}).get("os_guess", "Unknown")
                ua_line = [line for line in decoded_lower.split("\n") if "user-agent:" in line]
                if ua_line and "unknown" not in guessed_os.lower():
                    ua_val = ua_line[0]
                    is_windows_ua = "windows" in ua_val
                    is_linux_ua = any(x in ua_val for x in ["linux", "ubuntu", "debian", "centos"])
                    is_mac_ua = any(x in ua_val for x in ["macintosh", "mac os x", "darwin"])
                    
                    mismatch = False
                    if is_windows_ua and "linux" in guessed_os.lower():
                        mismatch = True
                    elif (is_linux_ua or is_mac_ua) and "windows" in guessed_os.lower():
                        mismatch = True
                        
                    if mismatch:
                        self.malware_detections.append({
                            "timestamp": timestamp_str,
                            "title": "مخالفة بصمة نظام التشغيل (OS Fingerprint Mismatch)",
                            "details": f"تم رصد ترويسة User-Agent تشير إلى نظام تشغيل مختلف عن خصائص حزم الشبكة (TTL). قد يشير هذا إلى استخدام بروكسي، جدار ناري، أو محاولة تمويه من المهاجم.",
                            "meta": f"العميل: {src_ip} (بصمة الشبكة: {guessed_os} vs العميل المصرح: {ua_val.split('user-agent:')[-1].strip()[:60]})",
                            "severity": "warning"
                        })
        except Exception:
            pass

    def analyze_plaintext_payload(self, payload, src_ip, dst_ip, sport, dport, proto_name, timestamp_str):
        """
        Inspects TCP raw payloads for sensitive credentials or session keys sent in the clear.
        """
        try:
            decoded_payload = payload.decode('utf-8', errors='ignore')
        except Exception:
            return
        
        # Basic check to avoid scanning large binaries
        if len(decoded_payload) > 10000:
            return
            
        # Search for username/password keywords
        matches = self.cred_pattern.findall(decoded_payload)
        if matches:
            # Check for HTTP POST or GET with credentials
            if "Authorization: Basic" in decoded_payload:
                self.credential_leaks.append({
                    "timestamp": timestamp_str,
                    "src": f"{src_ip}:{sport}",
                    "dst": f"{dst_ip}:{dport}",
                    "protocol": proto_name,
                    "type": "HTTP Basic Authentication",
                    "detail": "Found HTTP Basic authentication header containing base64 encoded credentials."
                })
            elif "password" in decoded_payload.lower() or "passwd" in decoded_payload.lower():
                # Extract surrounding context of the leak (limit size)
                lines = decoded_payload.split('\n')
                for line in lines:
                    if any(kw in line.lower() for kw in ['pass', 'user', 'login', 'admin']):
                        # Clean up sensitive data slightly to prevent visual clutter but show the leak
                        cleaned_line = line.strip()
                        if len(cleaned_line) > 150:
                            cleaned_line = cleaned_line[:150] + "..."
                        self.credential_leaks.append({
                            "timestamp": timestamp_str,
                            "src": f"{src_ip}:{sport}",
                            "dst": f"{dst_ip}:{dport}",
                            "protocol": proto_name,
                            "type": "Cleartext Credentials",
                            "detail": f"Pattern matched in raw stream: '{cleaned_line}'"
                        })
                        break

    def process_packet(self, pkt):
        self.packet_count += 1
        pkt_time = float(pkt.time)
        
        # Tracks first and last timestamps
        if self.first_packet_time is None:
            self.first_packet_time = pkt_time
        self.last_packet_time = pkt_time
        
        pkt_len = len(pkt)
        self.total_payload_bytes += pkt_len
        
        # Throughput over time binning
        if self.first_packet_time is not None:
            bin_idx = int(pkt_time - self.first_packet_time)
            self.throughput_bins[bin_idx] += pkt_len
        timestamp_str = datetime.fromtimestamp(pkt_time).strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]
        
        # Protocol Breakdown & Parsing Layers
        has_ip = IP in pkt
        has_ipv6 = IPv6 in pkt
        has_tcp = TCP in pkt
        has_udp = UDP in pkt
        has_arp = ARP in pkt
        has_dns = DNS in pkt
        
        # Layer 2 (Ethernet/ARP)
        src_mac = None
        dst_mac = None
        if Ether in pkt:
            src_mac = pkt[Ether].src
            dst_mac = pkt[Ether].dst
            self.protocols["Ethernet"] += 1
            
        # ARP Spoofing and Discovery
        if has_arp:
            self.protocols["ARP"] += 1
            arp_layer = pkt[ARP]
            arp_ip = arp_layer.psrc
            arp_mac = arp_layer.hwsrc
            
            # ARP Sweep tracking (op == 1 means request)
            if arp_layer.op == 1 and arp_layer.psrc and arp_layer.pdst:
                self.arp_sweep_tracker[arp_layer.psrc].add(arp_layer.pdst)
                if len(self.arp_sweep_tracker[arp_layer.psrc]) > 15:
                    self.port_scan_alerts[arp_layer.psrc] = {
                        "ports_count": len(self.arp_sweep_tracker[arp_layer.psrc]),
                        "type": "ARP Discovery Ping Sweep",
                        "details": f"Host sent ARP requests to {len(self.arp_sweep_tracker[arp_layer.psrc])} distinct IP addresses. Heavily associated with internal network reconnaissance and host discovery sweeps."
                    }
            
            # Map IP to MAC for ARP Spoofing Detection
            if arp_ip and arp_ip != "0.0.0.0":
                self.arp_ip_mac_map[arp_ip].add(arp_mac)
                
                # Update Host Inventory for ARP host
                if arp_ip not in self.hosts:
                    self.hosts[arp_ip] = {
                        "mac": arp_mac,
                        "os_guess": "Unknown (ARP Only)",
                        "hostname": "Unknown",
                        "sent_packets": 0, "recv_packets": 0,
                        "sent_bytes": 0, "recv_bytes": 0,
                        "open_ports": set(), "mac_vendors": set()
                    }
                else:
                    self.hosts[arp_ip]["mac"] = arp_mac

        # Layer 3 (IP/IPv6)
        src_ip = None
        dst_ip = None
        ttl = None
        
        if has_ip:
            self.protocols["IPv4"] += 1
            src_ip = pkt[IP].src
            dst_ip = pkt[IP].dst
            ttl = pkt[IP].ttl
        elif has_ipv6:
            self.protocols["IPv6"] += 1
            src_ip = pkt[IPv6].src
            dst_ip = pkt[IPv6].dst
            ttl = pkt[IPv6].hlim
            
        if src_ip and dst_ip:
            # Update Host Inventory
            for ip, role in [(src_ip, "sent"), (dst_ip, "recv")]:
                if ip not in self.hosts:
                    mac = src_mac if role == "sent" else dst_mac
                    vendor = self.resolve_mac_vendor(mac) if mac else "Unknown"
                    self.hosts[ip] = {
                        "mac": mac,
                        "os_guess": self.guess_os_from_ttl(ttl) if ttl else "Unknown",
                        "hostname": "Unknown",
                        "sent_packets": 0, "recv_packets": 0,
                        "sent_bytes": 0, "recv_bytes": 0,
                        "open_ports": set(), "mac_vendors": {vendor} if vendor != "Unknown" else set()
                    }
                else:
                    mac = src_mac if role == "sent" else dst_mac
                    if mac and not self.hosts[ip]["mac"]:
                        self.hosts[ip]["mac"] = mac
                        vendor = self.resolve_mac_vendor(mac)
                        if vendor != "Unknown":
                            self.hosts[ip]["mac_vendors"].add(vendor)
                            
                if role == "sent":
                    self.hosts[ip]["sent_packets"] += 1
                    self.hosts[ip]["sent_bytes"] += pkt_len
                else:
                    self.hosts[ip]["recv_packets"] += 1
                    self.hosts[ip]["recv_bytes"] += pkt_len
            
            # Layer 4 (TCP/UDP)
            sport = None
            dport = None
            proto_name = "IP"
            
            if has_tcp:
                self.protocols["TCP"] += 1
                proto_name = "TCP"
                tcp_layer = pkt[TCP]
                sport = tcp_layer.sport
                dport = tcp_layer.dport
                
                self.hosts[src_ip]["open_ports"].add(sport)
                self.hosts[dst_ip]["open_ports"].add(dport)
                self.port_traffic[dport] += pkt_len
                
                # Check TCP Flags for scans and state transitions
                flags = tcp_layer.flags
                
                if flags == 0x02: 
                    self.syn_times[(src_ip, sport, dst_ip, dport)] = pkt_time
                    self.port_scan_tracker[src_ip].add(dport)
                    
                    # SYN Flood detection
                    self.syn_flood_tracker[src_ip] += 1
                    if self.syn_flood_tracker[src_ip] == 300:
                        self.malware_detections.append({
                            "timestamp": timestamp_str,
                            "title": "هجوم حجب الخدمة (TCP SYN Flood)",
                            "details": "تم رصد معدل إرسال حزم SYN متكرر بشكل هائل من هذا العنوان دون إتمام المصافحة الثلاثية. هذا يشير إلى هجوم حجب الخدمة (DDoS/SYN Flood).",
                            "meta": f"المهاجم: {src_ip} -> المستهدف: {dst_ip}",
                            "severity": "critical"
                        })
                        
                    # Passive OS Fingerprinting (p0f style)
                    try:
                        win_size = tcp_layer.window
                        options = tcp_layer.options
                        
                        opt_sig = []
                        for opt in options:
                            name = opt[0]
                            if name == 'MSS': opt_sig.append('M')
                            elif name == 'WScale': opt_sig.append('W')
                            elif name == 'SAckOK': opt_sig.append('S')
                            elif name == 'Timestamp': opt_sig.append('T')
                            elif name == 'NOP': opt_sig.append('N')
                            
                        # Matching signature
                        os_guess = "Unknown"
                        if ttl == 128 or (ttl == 127 and win_size in [8192, 64240, 65535]):
                            os_guess = "Windows (OS Fingerprint)"
                        elif ttl == 64 and (win_size in [5840, 29200, 14600] or 'T' in opt_sig):
                            os_guess = "Linux/Android (OS Fingerprint)"
                        elif ttl == 64 and win_size == 65535 and 'W' in opt_sig:
                            os_guess = "macOS/iOS (OS Fingerprint)"
                        elif ttl == 128:
                            os_guess = "Windows (TTL Guess)"
                        elif ttl == 64:
                            os_guess = "Linux/macOS (TTL Guess)"
                            
                        if os_guess != "Unknown" and src_ip in self.hosts:
                            current_os = self.hosts[src_ip]["os_guess"]
                            if current_os == "Unknown" or "TTL Guess" in current_os or "guess" in current_os.lower():
                                self.hosts[src_ip]["os_guess"] = os_guess
                    except Exception:
                        pass
                elif flags == 0x12: # SYN-ACK
                    syn_key = (dst_ip, dport, src_ip, sport)
                    if syn_key in self.syn_times:
                        try:
                            rtt = pkt_time - self.syn_times[syn_key]
                            self.tcp_handshake_rtts.append(rtt)
                            del self.syn_times[syn_key]
                        except Exception:
                            pass
                
                # TCP Retransmission detection
                # Simplistic tracking: if same seq number for the connection
                conn_key = (src_ip, sport, dst_ip, dport)
                seq = tcp_layer.seq
                if seq in self.tcp_seq_numbers[conn_key]:
                    self.tcp_retransmissions += 1
                else:
                    # Keep track of last 1000 seq numbers per connection to avoid overflow
                    if len(self.tcp_seq_numbers[conn_key]) > 1000:
                        self.tcp_seq_numbers[conn_key].clear()
                    self.tcp_seq_numbers[conn_key].add(seq)
                
                # TCP Reset flag check (R = 0x04)
                if flags & 0x04:
                    self.tcp_resets += 1
                    
                # TCP Zero Window check (advertising window == 0)
                if tcp_layer.window == 0 and not (flags & 0x01) and not (flags & 0x04) and not (flags & 0x02):
                    self.tcp_zero_window_events.append({
                        "timestamp": timestamp_str,
                        "ip": src_ip,
                        "port": sport,
                        "target": dst_ip,
                        "target_port": dport,
                        "reason": "ذاكرة الجهاز المؤقتة ممتلئة تماماً (Zero Window) - تشير لتعطل التطبيق أو بطء شديد بالمعالجة"
                    })
                    
                # Analyze TCP payload for malware signatures and decrypted TLS data
                raw_payload = None
                try:
                    if pkt.haslayer(TLSApplicationData):
                        decrypted_data = pkt[TLSApplicationData].data
                        if decrypted_data:
                            raw_payload = decrypted_data
                            self.protocols["Decrypted HTTPS"] += 1
                            self.detect_malware_signatures(raw_payload, src_ip, dst_ip, sport, dport, timestamp_str)
                            self.audit_forensic_evidence(raw_payload, src_ip, dst_ip, sport, dport, timestamp_str, pkt_time)
                            self.analyze_plaintext_payload(raw_payload, src_ip, dst_ip, sport, dport, "Decrypted HTTPS", timestamp_str)
                except Exception:
                    pass
                
                if not raw_payload and tcp_layer.payload:
                    raw_payload = bytes(tcp_layer.payload)
                    if raw_payload:
                        self.detect_malware_signatures(raw_payload, src_ip, dst_ip, sport, dport, timestamp_str)
                        self.audit_forensic_evidence(raw_payload, src_ip, dst_ip, sport, dport, timestamp_str, pkt_time)
                        self.audit_tls_certificates(raw_payload, src_ip, dst_ip, sport, dport, timestamp_str)
                        
                # Inspect HTTP/FTP/Telnet on standard ports
                if dport in [80, 8080, 21, 23, 25, 110, 143] or sport in [80, 8080, 21, 23, 25, 110, 143]:
                    # Determine application-layer protocol
                    app_proto = "HTTP" if dport in [80, 8080] or sport in [80, 8080] else \
                                "FTP" if dport == 21 or sport == 21 else \
                                "Telnet" if dport == 23 or sport == 23 else "Cleartext SMTP/POP/IMAP"
                                
                    self.unencrypted_protocols_used.add(app_proto)
                    
                    # Analyze TCP payload for credentials
                    if tcp_layer.payload:
                        raw_payload = bytes(tcp_layer.payload)
                        if raw_payload:
                            self.analyze_plaintext_payload(raw_payload, src_ip, dst_ip, sport, dport, app_proto, timestamp_str)
                            
            elif has_udp:
                self.protocols["UDP"] += 1
                proto_name = "UDP"
                udp_layer = pkt[UDP]
                sport = udp_layer.sport
                dport = udp_layer.dport
                
                self.hosts[src_ip]["open_ports"].add(sport)
                self.hosts[dst_ip]["open_ports"].add(dport)
                self.port_traffic[dport] += pkt_len
                
                # Tracking UDP scan (massive number of destination ports)
                self.port_scan_tracker[src_ip].add(dport)
                
                # UDP Flood detection
                self.udp_flood_tracker[src_ip] += 1
                if self.udp_flood_tracker[src_ip] == 500:
                    self.malware_detections.append({
                        "timestamp": timestamp_str,
                        "title": "هجوم حجب الخدمة (UDP Flood)",
                        "details": "تم رصد تدفق سريع وكثيف لحزم UDP من هذا العنوان نحو الشبكة. هذا السلوك متطابق مع هجمات حجب الخدمة (UDP Flood DDoS).",
                        "meta": f"المصدر: {src_ip} -> المستهدف: {dst_ip}",
                        "severity": "critical"
                    })
                
                # DHCP Hostname Extraction (Forensic Device Discovery)
                try:
                    if pkt.haslayer(DHCP):
                        options = pkt[DHCP].options
                        for opt in options:
                            if isinstance(opt, tuple) and opt[0] == 'hostname':
                                hostname = opt[1].decode('utf-8', errors='ignore') if isinstance(opt[1], bytes) else str(opt[1])
                                if hostname:
                                    self.hosts[src_ip]["hostname"] = hostname
                except Exception:
                    pass
                
                # DNS Analysis
                if has_dns:
                    self.protocols["DNS"] += 1
                    self.unencrypted_protocols_used.add("DNS")
                    dns_layer = pkt[DNS]
                    
                    # DNS Query (qr == 0)
                    if dns_layer.qr == 0 and dns_layer.qd:
                        try:
                            # Store DNS query time for latency tracking
                            self.dns_query_times[(dns_layer.id, src_ip, dst_ip)] = pkt_time
                            
                            qname = dns_layer.qd.qname.decode('utf-8', errors='ignore').strip('.')
                            qtype = dns_layer.qd.qtype
                            
                            # Log DNS query count
                            if qname not in self.dns_mappings:
                                self.dns_mappings[qname] = {"ips": set(), "count": 0}
                            self.dns_mappings[qname]["count"] += 1
                            
                            # DNS Tunneling Heuristics
                            # 1. Extremely long subdomains (e.g. exfiltration payloads)
                            if len(qname) > 65:
                                self.dns_anomalies.append({
                                    "timestamp": timestamp_str,
                                    "client": src_ip,
                                    "query": qname,
                                    "type": "Length Anomaly",
                                    "reason": f"Domain query length is abnormally long ({len(qname)} chars), potential DNS Exfiltration."
                                })
                            # 2. TXT records query spike (frequently used in C2 communication)
                            if qtype == 16: # TXT
                                self.dns_anomalies.append({
                                    "timestamp": timestamp_str,
                                    "client": src_ip,
                                    "query": qname,
                                    "type": "TXT Record Query",
                                    "reason": "TXT records are commonly leveraged by Command & Control (C2) servers for tunneling."
                                })
                            # 3. Suspicious TLD check (often used by C2s and phishing, e.g. .top, .xyz)
                            suspicious_tlds = ('.top', '.xyz', '.click', '.link', '.download', '.work', '.zip', '.gq', '.cf', '.tk', '.ml')
                            if qname.endswith(suspicious_tlds):
                                self.dns_anomalies.append({
                                    "timestamp": timestamp_str,
                                    "client": src_ip,
                                    "query": qname,
                                    "type": "Suspicious TLD Query",
                                    "reason": f"Query to highly abused TLD ({'.' + qname.split('.')[-1]}), heavily associated with malware C2 and phishing."
                                })
                            # 4. ClickFix and KongTuke ClickFix patterns
                            if any(kw in qname.lower() for kw in ["captcha", "verification", "checkin", "hiddenplanet", "smartape", "kongtuke"]):
                                self.dns_anomalies.append({
                                    "timestamp": timestamp_str,
                                    "client": src_ip,
                                    "query": qname,
                                    "type": "ClickFix Domain Detection",
                                    "reason": "DNS query matches keywords associated with ClickFix fake verification and CAPTCHA campaigns."
                                })
                            # 5. Dynamic DNS (DDNS) Check (often used by njRAT/AsyncRAT/Quasar C2s)
                            ddns_providers = ("duckdns.org", "no-ip.biz", "no-ip.info", "no-ip.org", "no-ip.com", "ddns.net", "dyndns.org", "ngrok.io", "ngrok-free.app", "localtunnel.me")
                            if qname.endswith(ddns_providers):
                                self.dns_anomalies.append({
                                    "timestamp": timestamp_str,
                                    "client": src_ip,
                                    "query": qname,
                                    "type": "Dynamic DNS / Tunnel Query",
                                    "reason": f"Query to a Dynamic DNS or tunnel provider ({qname.split('.')[-2] + '.' + qname.split('.')[-1]}). Heavily abused by RATs to host dynamic C2 IPs."
                                })
                            # 6. High Entropy DNS check (possible encrypted exfiltration / DNS tunneling)
                            if len(qname) > 30:
                                entropy = self.calculate_entropy(qname)
                                if entropy > 4.2:
                                    self.dns_anomalies.append({
                                        "timestamp": timestamp_str,
                                        "client": src_ip,
                                        "query": qname,
                                        "type": "High-Entropy DNS Query",
                                        "reason": f"DNS query contains unusually high randomness (entropy: {round(entropy, 2)}), highly typical of encrypted DNS tunneling/exfiltration."
                                    })
                            # 7. Cryptomining Pool Domain Check
                            miner_pools = ("nanopool.org", "ethermine.org", "slushpool.com", "f2pool.com", "supportxmr.com", "moneropool.com", "nicehash.com", "pool.supportxmr", "pool.supportxmr.com")
                            if any(pool in qname.lower() for pool in miner_pools):
                                self.dns_anomalies.append({
                                    "timestamp": timestamp_str,
                                    "client": src_ip,
                                    "query": qname,
                                    "type": "Cryptomining Pool Connection",
                                    "reason": "DNS query to a known cryptocurrency mining pool. Indicates potential unauthorized cryptojacking activity."
                                })
                        except Exception:
                            pass
                            
                    # DNS Response (qr == 1)
                    elif dns_layer.qr == 1:
                        try:
                            # DNS Latency check
                            dns_key = (dns_layer.id, dst_ip, src_ip)
                            if dns_key in self.dns_query_times:
                                rtt = pkt_time - self.dns_query_times[dns_key]
                                self.dns_latencies.append(rtt)
                                del self.dns_query_times[dns_key]
                                
                            rcode = dns_layer.rcode
                            if rcode in [2, 3, 5]:
                                qname = "Unknown"
                                if dns_layer.qd:
                                    qname = dns_layer.qd.qname.decode('utf-8', errors='ignore').rstrip('.')
                                rcodes_map = {
                                    2: "فشل خادم الـ DNS (SERVFAIL)",
                                    3: "النطاق غير موجود (NXDOMAIN) - خطأ في التهيئة أو العنوان",
                                    5: "الطلب مرفوض من خادم الـ DNS (REFUSED)"
                                }
                                self.dns_failures.append({
                                    "timestamp": timestamp_str,
                                    "client": dst_ip,
                                    "query": qname,
                                    "status": rcodes_map.get(rcode, f"DNS Error {rcode}")
                                })
                            
                            if dns_layer.an:
                                qname = dns_layer.qd.qname.decode('utf-8', errors='ignore').strip('.')
                                for i in range(dns_layer.ancount):
                                    rdata = dns_layer.an[i].rdata
                                    if isinstance(rdata, str) and re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', rdata):
                                        if qname not in self.dns_mappings:
                                            self.dns_mappings[qname] = {"ips": set(), "count": 0}
                                            
                                        # DNS Cache Poisoning / Spoofing Check
                                        if self.dns_mappings[qname]["ips"] and rdata not in self.dns_mappings[qname]["ips"]:
                                            prev_ips = list(self.dns_mappings[qname]["ips"])
                                            self.dns_anomalies.append({
                                                "timestamp": timestamp_str,
                                                "client": dst_ip,
                                                "query": qname,
                                                "type": "DNS Hijack / Spoofing Suspect",
                                                "reason": f"Domain resolved to {rdata} but previously resolved to {prev_ips[0]} in the same capture. Indicates potential DNS cache poisoning or DNS injection."
                                            })
                                            
                                        self.dns_mappings[qname]["ips"].add(rdata)
                        except Exception:
                            pass
                            
            elif ICMP in pkt:
                self.protocols["ICMP"] += 1
                proto_name = "ICMP"
                icmp_layer = pkt[ICMP]
                
                # Check for ICMP Destination Unreachable (type == 3)
                if icmp_layer.type == 3:
                    try:
                        router_ip = src_ip
                        original_dst = "Unknown"
                        # Extract original target from encapsulated IP header
                        if icmp_layer.payload and hasattr(icmp_layer.payload, 'dst'):
                            original_dst = icmp_layer.payload.dst
                            
                        reasons_map = {
                            0: "الشبكة المستهدفة غير متصلة (Network Unreachable)",
                            1: "الجهاز المستهدف غير متصل (Host Unreachable) - قد يكون قاطع كابل أو طاقة",
                            3: "المنفذ مغلق بالجهاز المستهدف (Port Unreachable)",
                            4: "الحزم تتجاوز حجم الحد الأقصى للمسار (MTU Fragmentation Needed)"
                        }
                        reason_text = reasons_map.get(icmp_layer.code, f"خطأ اتصال غير معروف (ICMP Code {icmp_layer.code})")
                        
                        self.icmp_errors.append({
                            "timestamp": timestamp_str,
                            "router": router_ip,
                            "target": original_dst,
                            "reason": reason_text,
                            "code": icmp_layer.code
                        })
                    except Exception:
                        pass
                
                # Check for ICMP Ping Sweep (type 8 means echo request)
                if icmp_layer.type == 8 and src_ip and dst_ip:
                    self.icmp_sweep_tracker[src_ip].add(dst_ip)
                    if len(self.icmp_sweep_tracker[src_ip]) > 15:
                        self.port_scan_alerts[src_ip] = {
                            "ports_count": len(self.icmp_sweep_tracker[src_ip]),
                            "type": "ICMP Ping Host Sweep",
                            "details": f"Host sent ICMP Echo Requests (pings) to {len(self.icmp_sweep_tracker[src_ip])} distinct IP addresses. Highly indicative of active network host discovery."
                        }
                        
                # Check for large ICMP payloads (possible ICMP tunneling)
                if icmp_layer.payload:
                    icmp_pay_len = len(icmp_layer.payload)
                    if icmp_pay_len > 150:
                        self.malware_detections.append({
                            "timestamp": timestamp_str,
                            "title": "شبهة نفق ICMP (ICMP Tunneling)",
                            "details": f"تم رصد حزمة ICMP (Ping) ذات حجم بيانات كبير بشكل مريب ({icmp_pay_len} بايت). غالباً ما تُستغل هذه الثغرة لتجاوز جدران الحماية ونقل البيانات خفية.",
                            "meta": f"المصدر: {src_ip} -> {dst_ip}",
                            "severity": "warning"
                        })
                        
                # ICMP Flood detection
                self.icmp_flood_tracker[src_ip] += 1
                if self.icmp_flood_tracker[src_ip] == 300:
                    self.malware_detections.append({
                        "timestamp": timestamp_str,
                        "title": "هجوم حجب الخدمة (ICMP Ping Flood)",
                        "details": "تم رصد معدل إرسال حزم ICMP (Ping) ضخم ومتلاحق من هذا العنوان بهدف إغراق الشبكة وتعطيلها (Ping Flood DDoS).",
                        "meta": f"المصدر: {src_ip} -> المستهدف: {dst_ip}",
                        "severity": "critical"
                    })
                
            # Log conversation
            conv_key = (src_ip, dst_ip, proto_name)
            self.conversations[conv_key]["packets"] += 1
            self.conversations[conv_key]["bytes"] += pkt_len

    def analyze(self, progress_callback=None):
        """
        Parses the PCAP file packet-by-packet, updating metrics and triggering callbacks.
        """
        if not os.path.exists(self.pcap_path):
            raise FileNotFoundError(f"PCAP file not found: {self.pcap_path}")
            
        last_callback_time = 0
        
        with PcapReader(self.pcap_path) as reader:
            for pkt in reader:
                try:
                    self.process_packet(pkt)
                except Exception as e:
                    # Log packet parse error silently and continue
                    pass
                
                # Run progress callback occasionally to avoid dragging speed
                if progress_callback and (self.packet_count % 500 == 0):
                    progress = self.get_progress(reader)
                    progress_callback(self.packet_count, progress)
                    
            # Run final 100% callback
            if progress_callback:
                progress_callback(self.packet_count, 100.0)

        # Post-processing calculations
        if self.last_packet_time and self.first_packet_time:
            self.duration = round(self.last_packet_time - self.first_packet_time, 2)
        else:
            self.duration = 0.0

        # Run Port Scanning analysis
        for ip, ports in self.port_scan_tracker.items():
            if len(ports) > 20:
                self.port_scan_alerts[ip] = {
                    "ports_count": len(ports),
                    "type": "TCP/UDP Port Sweep",
                    "details": f"Host contacted {len(ports)} distinct ports. Highly indicative of active network reconnaissance."
                }
                
        # Format and compile results
        return self.compile_results()

    def compile_results(self):
        # Convert DNS sets to lists for JSON serialization
        formatted_dns = []
        for domain, info in self.dns_mappings.items():
            formatted_dns.append({
                "domain": domain,
                "count": info["count"],
                "resolved_ips": list(info["ips"])
            })
            
        # Format hosts
        formatted_hosts = []
        for ip, host_info in self.hosts.items():
            formatted_hosts.append({
                "ip": ip,
                "mac": host_info["mac"] or "Unknown",
                "os_guess": host_info["os_guess"],
                "hostname": host_info.get("hostname", "Unknown"),
                "sent_packets": host_info["sent_packets"],
                "recv_packets": host_info["recv_packets"],
                "sent_bytes": host_info["sent_bytes"],
                "recv_bytes": host_info["recv_bytes"],
                "total_bytes": host_info["sent_bytes"] + host_info["recv_bytes"],
                "open_ports": sorted(list(host_info["open_ports"]))[:100] # Cap ports shown in dashboard
            })
            
        # Format conversations
        formatted_conversations = []
        for conv_key, data in self.conversations.items():
            formatted_conversations.append({
                "src": conv_key[0],
                "dst": conv_key[1],
                "protocol": conv_key[2],
                "packets": data["packets"],
                "bytes": data["bytes"]
            })
            
        # Group conversations by (local_ip, remote_ip) to compute upload/download ratio
        flow_bytes = collections.defaultdict(lambda: {"sent": 0, "recv": 0})
        for conv in formatted_conversations:
            src = conv["src"]
            dst = conv["dst"]
            src_is_private = src.startswith(("10.", "192.168.", "127.", "172.16.", "172.17.", "172.18.", "172.19.", "172.20.", "172.21.", "172.22.", "172.23.", "172.24.", "172.25.", "172.26.", "172.27.", "172.28.", "172.29.", "172.30.", "172.31."))
            dst_is_private = dst.startswith(("10.", "192.168.", "127.", "172.16.", "172.17.", "172.18.", "172.19.", "172.20.", "172.21.", "172.22.", "172.23.", "172.24.", "172.25.", "172.26.", "172.27.", "172.28.", "172.29.", "172.30.", "172.31."))
            
            if src_is_private and not dst_is_private:
                flow_bytes[(src, dst)]["sent"] += conv["bytes"]
            elif not src_is_private and dst_is_private:
                flow_bytes[(dst, src)]["recv"] += conv["bytes"]
                
        for (local, remote), bytes_info in flow_bytes.items():
            sent = bytes_info["sent"]
            recv = bytes_info["recv"]
            if sent > 250000: # Upload > 250KB
                ratio = sent / (recv + 1)
                if ratio > 10.0: # Upload is 10x download
                    self.forensic_exfiltrations.append({
                        "local_host": local,
                        "remote_host": remote,
                        "bytes_sent": sent,
                        "bytes_received": recv,
                        "ratio": round(ratio, 1),
                        "details": f"High ratio data exfiltration detected. Local host sent {round(sent/1024, 1)} KB but received only {round(recv/1024, 1)} KB (Ratio: {round(ratio, 1)}x)."
                    })
                    # Add alert
                    self.malware_detections.append({
                        "timestamp": datetime.fromtimestamp(self.first_packet_time).strftime('%Y-%m-%d %H:%M:%S') if self.first_packet_time else "Unknown",
                        "title": "شبهة تهريب بيانات مكثفة (High Ratio Exfiltration)",
                        "details": f"تم رصد تدفق بيانات غير متوازن للغاية نحو مضيف خارجي ({remote}). العميل المحلي أرسل {round(sent/1024, 1)} KB واستقبل {round(recv/1024, 1)} KB بنسبة رفع للمستلم تبلغ {round(ratio, 1)} ضعفاً. مؤشر قوي على سرقة وتصدير ملفات الشبكة الجنائية.",
                        "meta": f"العميل: {local} -> الوجهة: {remote}",
                        "severity": "critical"
                    })
            
        # Format ARP Spoofing alerts
        arp_alerts = []
        for ip, macs in self.arp_ip_mac_map.items():
            if len(macs) > 1:
                arp_alerts.append({
                    "ip": ip,
                    "macs": list(macs),
                    "type": "ARP Poisoning / Spoofing",
                    "details": f"Multiple MAC addresses ({', '.join(macs)}) are associated with the same IP {ip}."
                })
                
        # Format port scan alerts
        scan_alerts_list = []
        for ip, alert in self.port_scan_alerts.items():
            scan_alerts_list.append({
                "ip": ip,
                "ports_count": alert["ports_count"],
                "type": alert["type"],
                "details": alert["details"]
            })
            
        # Security Score calculation (heuristic)
        # Base 100, deduct points for alerts found
        security_score = 100
        security_score -= len(self.credential_leaks) * 15
        security_score -= len(scan_alerts_list) * 20
        security_score -= len(arp_alerts) * 35
        security_score -= len(self.dns_anomalies) * 10
        security_score -= len(self.malware_detections) * 35
        security_score = max(5, security_score) # Ensure minimum score of 5

        # C2 Beaconing Detection post-processing
        for flow_key, times in self.connection_timestamps.items():
            if len(times) >= 8:
                intervals = []
                for i in range(len(times) - 1):
                    intervals.append(times[i+1] - times[i])
                
                avg_interval = sum(intervals) / len(intervals)
                variance = sum((x - avg_interval) ** 2 for x in intervals) / len(intervals)
                std_dev = math.sqrt(variance)
                
                # Highly consistent check-ins
                if std_dev < 2.0 and avg_interval > 2.0:
                    src_ip, dst_ip, dport = flow_key
                    timestamp_str = datetime.fromtimestamp(times[0]).strftime('%Y-%m-%d %H:%M:%S')
                    self.beaconing_alerts.append({
                        "timestamp": timestamp_str,
                        "src": src_ip,
                        "dst": f"{dst_ip}:{dport}",
                        "interval": f"{round(avg_interval, 1)}s",
                        "consistency": f"High (std_dev: {round(std_dev, 2)}s)",
                        "connections_count": len(times),
                        "details": f"Periodic network connection behavior (beaconing) detected at exact intervals of {round(avg_interval, 1)}s. Strongly matches Command & Control (C2) beaconing patterns."
                    })
                    # Also append as malware detection alert to trigger score deduction
                    self.malware_detections.append({
                        "timestamp": timestamp_str,
                        "title": "رصد تواصل دوري ثابت لـ C2 Beaconing",
                        "details": f"تم رصد سلوك تواصل دوري ثابت جداً نحو العنوان ({dst_ip}:{dport}) بمعدل كل {round(avg_interval, 1)} ثانية. يطابق تماماً سلوك استدعاء الأوامر لبرمجيات التحكم C2.",
                        "meta": f"المصدر: {src_ip} -> الوجهة: {dst_ip}:{dport}",
                        "severity": "critical"
                    })

        # Format bandwidth speed (avg bytes/sec)
        avg_speed = 0.0
        if self.duration > 0:
            avg_speed = round(self.total_payload_bytes / self.duration, 2)

        # Remove temporary raw time key from carved files for clean JSON output
        clean_carved_files = []
        for f in self.forensic_files_carved:
            clean_file = f.copy()
            clean_file.pop("_raw_time", None)
            clean_carved_files.append(clean_file)

        # Collect unanswered SYNs (Connection timeouts / severed links)
        for conn, syn_time in self.syn_times.items():
            src_ip, sport, dst_ip, dport = conn
            self.connection_timeouts.append({
                "timestamp": datetime.fromtimestamp(syn_time).isoformat() if syn_time else "Unknown",
                "src": f"{src_ip}:{sport}",
                "dst": f"{dst_ip}:{dport}",
                "reason": "لا يوجد استجابة (Handshake Timeout) - قد يشير إلى خادم معطل أو قاطع في مسار الشبكة"
            })

        # Calculate average TCP RTT
        avg_rtt_sec = 0.0
        if self.tcp_handshake_rtts:
            avg_rtt_sec = sum(self.tcp_handshake_rtts) / len(self.tcp_handshake_rtts)

        # Calculate average DNS RTT
        avg_dns_rtt_sec = 0.0
        if self.dns_latencies:
            avg_dns_rtt_sec = sum(self.dns_latencies) / len(self.dns_latencies)

        # Calculate TCP handshake success rate
        successful_handshakes = len(self.tcp_handshake_rtts)
        failed_handshakes = len(self.connection_timeouts)
        total_handshakes = successful_handshakes + failed_handshakes
        handshake_success_rate = 100.0
        if total_handshakes > 0:
            handshake_success_rate = (successful_handshakes / total_handshakes) * 100.0

        # Resolve top services traffic
        services_traffic = []
        for port, num_bytes in self.port_traffic.items():
            services_traffic.append({
                "port": port,
                "service": self.resolve_port_service(port),
                "bytes": num_bytes
            })
        services_traffic = sorted(services_traffic, key=lambda x: x["bytes"], reverse=True)[:10]

        # Format throughput chart points
        chart_points = []
        for sec, num_bytes in sorted(self.throughput_bins.items()):
            chart_points.append({"time": sec, "bytes": num_bytes})
            
        if len(chart_points) > 150:
            step = len(chart_points) // 150
            chart_points = chart_points[::step]

        return {
            "summary": {
                "packet_count": self.packet_count,
                "duration_seconds": self.duration,
                "total_bytes": self.total_payload_bytes,
                "avg_speed_bps": avg_speed * 8, # bits per second
                "security_score": security_score,
                "first_packet_time": datetime.fromtimestamp(self.first_packet_time).isoformat() if self.first_packet_time else None,
                "last_packet_time": datetime.fromtimestamp(self.last_packet_time).isoformat() if self.last_packet_time else None
            },
            "protocols": dict(self.protocols),
            "hosts": formatted_hosts,
            "conversations": sorted(formatted_conversations, key=lambda x: x["bytes"], reverse=True)[:100], # Top 100 conversations
            "dns_records": sorted(formatted_dns, key=lambda x: x["count"], reverse=True)[:100],
            "alerts": {
                "credential_leaks": self.credential_leaks,
                "arp_spoofs": arp_alerts,
                "port_scans": scan_alerts_list,
                "dns_anomalies": self.dns_anomalies,
                "malware_detections": self.malware_detections,
                "unencrypted_protocols": list(self.unencrypted_protocols_used),
                "forensic_files_carved": clean_carved_files,
                "beaconing_alerts": self.beaconing_alerts,
                "forensic_exfiltrations": self.forensic_exfiltrations
            },
            "network_diagnostics": {
                "avg_rtt_seconds": avg_rtt_sec,
                "avg_dns_rtt_seconds": avg_dns_rtt_sec,
                "tcp_success_rate": handshake_success_rate,
                "top_services": services_traffic,
                "connection_timeouts": self.connection_timeouts[:100],
                "icmp_errors": self.icmp_errors[:100],
                "dns_failures": self.dns_failures[:100],
                "tcp_zero_window_events": self.tcp_zero_window_events[:100],
                "throughput_timeline": chart_points
            }
        }

    def audit_tls_certificates(self, raw_payload, src_ip, dst_ip, sport, dport, timestamp_str):
        # Scan for TLS Handshake Record (Content Type = 0x16, Version = 0x03)
        if len(raw_payload) > 5 and raw_payload[0] == 0x16 and raw_payload[1] == 0x03:
            # Check Handshake Type: 0x0b (Certificate)
            if len(raw_payload) > 9 and raw_payload[5] == 0x0b:
                self.audit_tls_certificate_payload(raw_payload[9:], src_ip, dst_ip, sport, dport, timestamp_str)

    def audit_tls_certificate_payload(self, cert_payload, src_ip, dst_ip, sport, dport, timestamp_str):
        # Extract readable ASCII/printable strings from DER cert bytes
        strings = []
        current = []
        for b in cert_payload:
            if 32 <= b <= 126:
                current.append(chr(b))
            else:
                if len(current) >= 3:
                    strings.append("".join(current))
                current = []
        if len(current) >= 3:
            strings.append("".join(current))
            
        if not strings:
            return
            
        is_suspicious = False
        reason = ""
        
        # Threat intelligence / default signatures
        cobalt_strike_hints = ["cobaltstrike", "Cobalt Strike", "cobalt"]
        havoc_hints = ["Havoc", "havoc", "Havoc C2"]
        sliver_hints = ["Sliver", "sliver"]
        
        for s in strings:
            if any(hint in s for hint in cobalt_strike_hints):
                is_suspicious = True
                reason = "Cobalt Strike Default SSL/TLS Certificate"
            elif any(hint in s for hint in havoc_hints):
                is_suspicious = True
                reason = "Havoc C2 Default SSL/TLS Certificate"
            elif any(hint in s for hint in sliver_hints):
                is_suspicious = True
                reason = "Sliver C2 Default SSL/TLS Certificate"
                
        # Self-signed and generic certificate alerts
        for s in strings:
            if s.lower() in ["localhost", "localhost.localdomain", "default", "temp"]:
                is_suspicious = True
                reason = f"Temporary/Localhost Certificate ({s})"
                
        if is_suspicious:
            self.malware_detections.append({
                "timestamp": timestamp_str,
                "title": "شهادة تشفير مريبة (TLS Certificate Threat)",
                "details": f"تم الكشف عن مصافحة TLS باستخدام شهادة مريبة تطابق بصمات خوادم C2 أو شهادات مؤقتة غير موثوقة: {reason}",
                "meta": f"المصدر: {src_ip}:{sport} -> الوجهة: {dst_ip}:{dport}",
                "severity": "critical",
                "src_ip": src_ip,
                "dst_ip": dst_ip
            })

    def resolve_mac_vendor(self, mac):
        if not mac or not isinstance(mac, str):
            return "Unknown"
        mac_clean = mac.replace(":", "").replace("-", "").upper()[:6]
        oui_db = {
            "00000C": "Cisco", "00037F": "Atheros", "0005B9": "Cisco",
            "000C29": "VMware", "005056": "VMware", "00155D": "Microsoft",
            "001A11": "Google", "3C5A37": "Apple", "001C42": "Parallels",
            "001C7F": "Intel", "0021cc": "Intel", "002590": "Supermicro",
            "0026BB": "Apple", "0028F8": "Cisco", "00E04C": "Realtek",
            "248A07": "Apple", "34159E": "Apple", "3C0754": "Apple",
            "406C8F": "Apple", "482C6A": "Apple", "54E43A": "Apple",
            "640980": "Apple", "705681": "Apple", "7081EB": "Apple",
            "74D435": "Apple", "784F43": "Apple", "843835": "Apple",
            "907240": "Apple", "ACBC32": "Apple", "B8098A": "Apple",
            "C03896": "Apple", "C8B5B7": "Apple", "D8A25E": "Apple",
            "F01898": "Apple", "F0DBF8": "Apple", "F81ED9": "Apple",
            "FCFC48": "Apple", "001422": "Dell", "001D09": "Dell",
            "0026B9": "Dell", "180373": "Dell", "24B6FD": "Dell",
            "3417EB": "Dell", "7054D2": "Dell", "90B11C": "Dell",
            "A41F72": "Dell", "B4B52F": "Dell", "D4BED9": "Dell",
            "F8BC12": "Dell", "000854": "HP", "000F20": "HP",
            "00110A": "HP", "001708": "HP", "001A4B": "HP",
            "001E0B": "HP", "00215A": "HP", "002264": "HP",
            "002481": "HP", "0025B3": "HP", "002655": "HP",
            "0030C1": "HP", "00508B": "HP", "00E0B1": "HP",
            "040973": "HP", "081196": "HP", "0C1108": "HP",
            "101F74": "HP", "1458D0": "HP", "18233C": "HP",
            "1C98EC": "HP", "20677C": "HP", "24811A": "HP",
            "2C59E5": "HP", "3085A9": "HP", "3464A9": "HP",
            "3822E2": "HP", "3C4A92": "HP", "40A8F8": "HP",
            "441EA1": "HP", "480FCF": "HP", "4C38CC": "HP",
            "5065F3": "HP", "549F35": "HP", "5820B1": "HP",
            "5C5B35": "HP", "6014B3": "HP", "643150": "HP",
            "68B599": "HP", "6C3B6B": "HP", "70106F": "HP",
            "7446A0": "HP", "782BCB": "HP", "7C04D0": "HP",
            "80C16E": "HP", "843497": "HP", "8851FB": "HP",
            "8C1645": "HP", "9457A5": "HP", "984BE1": "HP",
            "9C8E99": "HP", "A01D48": "HP", "A45D36": "HP",
            "A83049": "HP", "AC162D": "HP", "B05AD5": "HP",
            "B499BA": "HP", "B83861": "HP", "BC305B": "HP",
            "C025A5": "HP", "C4346B": "HP", "C81F66": "HP",
            "CC3F1D": "HP", "D067E5": "HP", "D4C9EF": "HP",
            "D8973B": "HP", "DC4A3E": "HP", "E00709": "HP",
            "E4115B": "HP", "E83935": "HP", "EC8EB5": "HP",
            "F0921C": "HP", "F430B9": "HP", "F80BBE": "HP",
            "FC15B4": "HP", "001372": "Intel", "001B21": "Intel",
            "001F3B": "Intel", "00270E": "Intel", "487397": "Intel",
            "5891CF": "Intel", "A41566": "Intel", "A44E31": "Intel",
            "00001D": "Cabletron", "0000A2": "Bay Networks", "0000A9": "Network Systems",
            "000130": "Extreme Networks", "000142": "Cisco", "000164": "HP",
            "000197": "F5 Networks", "0003BA": "Oracle", "000423": "Intel",
            "000475": "3Com", "000480": "HP", "0004DD": "ASUS",
            "00055D": "D-Link", "0005CD": "Denon", "000625": "Linksys",
            "0007E9": "Intel", "000802": "HP", "00095B": "Netgear",
            "0009B6": "Samsung", "000A95": "Apple", "000C41": "Cisco",
            "000D3A": "Microsoft", "000E0C": "Cisco", "000E7F": "HP",
            "000F66": "Cisco", "001049": "HP", "0010E0": "Cisco",
            "00112F": "HP", "001143": "Dell", "001185": "Cisco",
            "001217": "Cisco", "00127F": "Cisco", "001319": "Intel",
            "0013C3": "Cisco", "0014A8": "Cisco", "001565": "Yealink",
            "0015C5": "Dell", "00163E": "Xen", "001646": "Cisco",
            "001851": "OpenVZ", "00188B": "Dell", "0018B9": "Cisco",
            "00193B": "Cisco", "001955": "Cisco", "001997": "Cisco",
            "001B0D": "Cisco", "001B2A": "Cisco", "001B54": "Cisco",
            "00211B": "Cisco", "00211C": "Cisco", "002155": "Cisco",
            "00270D": "Cisco", "002790": "Cisco", "003A7D": "Cisco",
            "00B064": "Cisco", "00B08E": "Cisco", "00B0C2": "Cisco",
            "B827EB": "Raspberry Pi", "E45F01": "Raspberry Pi", "D83A9D": "Raspberry Pi"
        }
        return oui_db.get(mac_clean, "Generic/Other")

    def resolve_port_service(self, port):
        services = {
            80: "HTTP (Cleartext Web)", 443: "HTTPS (Encrypted Web)",
            53: "DNS (Name Resolution)", 22: "SSH (Secure Remote Management)",
            23: "Telnet (Cleartext Management)", 21: "FTP (File Transfer)",
            25: "SMTP (Email Routing)", 110: "POP3 (Email Retrieval)",
            143: "IMAP (Email Retrieval)", 445: "SMB (Windows File Sharing)",
            137: "NetBIOS (Windows Discovery)", 138: "NetBIOS (Windows Discovery)",
            139: "NetBIOS (Windows Discovery)", 3389: "RDP (Remote Desktop)",
            5353: "mDNS (Local Multicast Discovery)", 1900: "SSDP (UPnP)",
            67: "DHCP (IP Assignment)", 68: "DHCP (IP Assignment)",
            123: "NTP (Time Mapped Sync)", 161: "SNMP (Network Management)",
            389: "LDAP (Active Directory)", 636: "LDAPS (Active Directory)",
            1433: "MSSQL (Database)", 3306: "MySQL (Database)",
            5432: "PostgreSQL (Database)", 27017: "MongoDB (Database)",
            8080: "HTTP-Alt (Web Service)", 8443: "HTTPS-Alt (Web Service)"
        }
        return services.get(port, f"Custom Port {port}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python analyzer.py <pcap_file>")
        sys.exit(1)
        
    pcap = sys.argv[1]
    if not os.path.exists(pcap):
        print(f"Error: {pcap} not found.")
        sys.exit(1)
        
    print(f"[*] Starting offline analysis on: {pcap}")
    analyzer = PacketSpectreAnalyzer(pcap)
    
    def cb(count, progress):
        print(f"\r[*] Processed {count} packets... ({progress}%)", end="", flush=True)
        
    results = analyzer.analyze(progress_callback=cb)
    print("\n[+] Analysis complete!")
    
    import json
    with open("results.json", "w") as f:
        json.dump(results, f, indent=4)
    print("[*] Sample results saved to results.json")
