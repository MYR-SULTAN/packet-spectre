import os
import json
import uuid
import shutil
import urllib.request
import urllib.error
import threading
import uvicorn
import webbrowser
from fastapi import FastAPI, UploadFile, File, BackgroundTasks, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, FileResponse
from fastapi.middleware.cors import CORSMiddleware

# Import local analyzer
from backend.analyzer import PacketSpectreAnalyzer

app = FastAPI(title="Packet Spectre API", version="1.0.0")

# Enable CORS for development flexibility
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# In-memory storage for tasks
import sys

# task_id -> {status, progress, packet_count, results, error, file_name}
TASKS = {}

if getattr(sys, 'frozen', False):
    # Running in a PyInstaller bundle (executable)
    base_dir = sys._MEIPASS
    FRONTEND_DIR = os.path.abspath(os.path.join(base_dir, "frontend"))
    # Save uploads in the directory where the .exe resides
    UPLOAD_DIR = os.path.abspath(os.path.join(os.path.dirname(sys.executable), "uploads"))
else:
    FRONTEND_DIR = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "frontend"))
    UPLOAD_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "uploads")

# Ensure uploads directory exists
os.makedirs(UPLOAD_DIR, exist_ok=True)

def parse_pcap_task(task_id: str, file_path: str, keylog_path: str = None):
    """
    Background worker thread task to parse the PCAP file.
    """
    try:
        analyzer = PacketSpectreAnalyzer(file_path, keylog_path=keylog_path)
        
        def progress_cb(count, progress):
            if task_id in TASKS:
                TASKS[task_id]["progress"] = progress
                TASKS[task_id]["packet_count"] = count
                
        # Start analysis
        results = analyzer.analyze(progress_callback=progress_cb)
        
        if task_id in TASKS:
            TASKS[task_id]["status"] = "completed"
            TASKS[task_id]["progress"] = 100.0
            TASKS[task_id]["results"] = results
            
    except Exception as e:
        import traceback
        error_details = traceback.format_exc()
        print(f"[-] Error parsing task {task_id}: {e}\n{error_details}")
        if task_id in TASKS:
            TASKS[task_id]["status"] = "failed"
            TASKS[task_id]["error"] = str(e)
    finally:
        # Safely remove the temp keylog file if it exists to free disk space
        if keylog_path and os.path.exists(keylog_path):
            try:
                os.remove(keylog_path)
            except Exception:
                pass

@app.post("/api/upload")
async def upload_pcap(background_tasks: BackgroundTasks, file: UploadFile = File(...), keylog: UploadFile = None):
    """
    Endpoint to upload a PCAP file and begin parsing.
    """
    if not (file.filename.endswith('.pcap') or file.filename.endswith('.pcapng') or file.filename.endswith('.cap')):
        raise HTTPException(status_code=400, detail="Invalid file type. Only .pcap, .pcapng, and .cap are supported.")
        
    task_id = str(uuid.uuid4())
    temp_file_name = f"{task_id}_{file.filename}"
    temp_file_path = os.path.join(UPLOAD_DIR, temp_file_name)
    
    # Save the uploaded file
    try:
        with open(temp_file_path, "wb") as buffer:
            shutil.copyfileobj(file.file, buffer)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to save uploaded file: {str(e)}")
        
    # Save optional keylog file
    temp_keylog_path = None
    if keylog and keylog.filename:
        temp_keylog_name = f"{task_id}_{keylog.filename}"
        temp_keylog_path = os.path.join(UPLOAD_DIR, temp_keylog_name)
        try:
            with open(temp_keylog_path, "wb") as buffer:
                shutil.copyfileobj(keylog.file, buffer)
        except Exception as e:
            if os.path.exists(temp_file_path):
                try:
                    os.remove(temp_file_path)
                except Exception:
                    pass
            raise HTTPException(status_code=500, detail=f"Failed to save keylog file: {str(e)}")
        
    # Initialize task state
    TASKS[task_id] = {
        "status": "processing",
        "progress": 0.0,
        "packet_count": 0,
        "file_name": file.filename,
        "file_path": temp_file_path,
        "results": None,
        "error": None
    }
    
    # Spawn background worker
    background_tasks.add_task(parse_pcap_task, task_id, temp_file_path, temp_keylog_path)
    
    return {"task_id": task_id, "file_name": file.filename, "has_keylog": bool(temp_keylog_path)}

@app.get("/api/status/{task_id}")
async def get_task_status(task_id: str):
    """
    Endpoint to retrieve the current parsing progress/status.
    """
    if task_id not in TASKS:
        raise HTTPException(status_code=404, detail="Task not found.")
        
    task = TASKS[task_id]
    return {
        "task_id": task_id,
        "status": task["status"],
        "progress": task["progress"],
        "packet_count": task["packet_count"],
        "file_name": task["file_name"],
        "error": task["error"]
    }

@app.get("/api/results/{task_id}")
async def get_task_results(task_id: str):
    """
    Endpoint to fetch completed analysis metrics.
    """
    if task_id not in TASKS:
        raise HTTPException(status_code=404, detail="Task not found.")
        
    task = TASKS[task_id]
    if task["status"] == "processing":
        raise HTTPException(status_code=400, detail="Analysis is still in progress.")
    elif task["status"] == "failed":
        raise HTTPException(status_code=500, detail=f"Analysis failed: {task['error']}")
        
    return task["results"]

CONFIG_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "config.json")

def load_config():
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, "r") as f:
                return json.load(f)
        except Exception:
            pass
    return {}

@app.post("/api/ai-report/{task_id}")
async def generate_ai_report(task_id: str):
    if task_id not in TASKS:
        raise HTTPException(status_code=404, detail="Task not found.")
        
    task = TASKS[task_id]
    if task["status"] != "completed":
        raise HTTPException(status_code=400, detail="Analysis task is not complete.")
        
    config = load_config()
    api_key = config.get("deepseek_api_key", "")
    if not api_key:
        api_key = os.environ.get("DEEPSEEK_API_KEY", "")
        
    if not api_key:
        raise HTTPException(status_code=400, detail="DeepSeek API key is not configured. Please set it in the Settings panel.")
        
    results = task["results"]
    
    # Construct a lightweight JSON summary to fit in context window and save tokens
    summary_data = {
        "file_name": task["file_name"],
        "packet_count": results["summary"]["packet_count"],
        "duration_seconds": results["summary"]["duration_seconds"],
        "security_score": results["summary"]["security_score"],
        "protocols": results["protocols"],
        "active_hosts_count": len(results["hosts"]),
        "credential_leaks_count": len(results["alerts"]["credential_leaks"]),
        "arp_spoofs_count": len(results["alerts"]["arp_spoofs"]),
        "port_scans_count": len(results["alerts"]["port_scans"]),
        "dns_anomalies_count": len(results["alerts"]["dns_anomalies"]),
        "malware_detections": results["alerts"]["malware_detections"][:30],
        "forensic_files_carved": results["alerts"].get("forensic_files_carved", [])[:20],
        "beaconing_alerts": results["alerts"].get("beaconing_alerts", [])[:15],
        "forensic_exfiltrations": results["alerts"].get("forensic_exfiltrations", [])[:15]
    }
    
    # Construct prompt
    prompt = (
        "أنت خبير جنائي رقمي شبكي ومحلل حوادث أمنية محترف. لقد قمت بتحليل حركة مرور لملف تسجيل PCAP وهذه هي النتائج المكتشفة في الشبكة بصيغة JSON:\n"
        f"{json.dumps(summary_data, ensure_ascii=False, indent=2)}\n\n"
        "المطلوب منك كتابة تقرير جنائي استقصائي كامل ومفصل باللغة العربية يشرح المشهد العام لما حدث:\n"
        "1. الخلاصة التنفيذية (Executive Summary): فكرة عامة عن الهجمات المكتشفة، مستوى الخطورة الإجمالي، والأجهزة الرئيسية المتورطة.\n"
        "2. التحليل الجنائي للتهديدات (Deep Threat Forensics Analysis): تفصيل الأنشطة الخبيثة التي تم رصدها (مثل برمجيات RATs أو Stealers أو تسريب بطاقات وكلمات مرور DLP، أو هجمات حجب الخدمة، أو اتصالات C2 Beaconing) مع تتبع عناوين الـ IP المتورطة والملفات والمسارات المكتشفة.\n"
        "3. التوصيات الأمنية وعلاج الحادثة (Remediation & IR Actions): إرشادات واضحة خطوة بخطوة للسيطرة على الحادثة وتطهير الأجهزة المصابة وتأمين جدار الحماية بالشبكة.\n\n"
        "اجعل التقرير ذا أسلوب رسمي واحترافي رفيع المستوى يليق بمدير أمن معلومات، واستخدم الجداول التلخيصية والنقاط المنسقة بالمارك داون (Markdown) بشكل منظم للغاية."
    )
    
    try:
        api_url = "https://api.deepseek.com/chat/completions"
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {api_key}"
        }
        
        request_data = {
            "model": "deepseek-chat",
            "messages": [
                {"role": "system", "content": "You are a senior Digital Forensics and Incident Response (DFIR) specialist writing reports in Arabic."},
                {"role": "user", "content": prompt}
            ],
            "temperature": 0.2,
            "max_tokens": 3000
        }
        
        req_body = json.dumps(request_data).encode('utf-8')
        req = urllib.request.Request(api_url, data=req_body, headers=headers, method="POST")
        
        with urllib.request.urlopen(req, timeout=45) as response:
            res_body = response.read().decode('utf-8')
            res_json = json.loads(res_body)
            report_text = res_json["choices"][0]["message"]["content"]
            
        return {"report": report_text}
    except urllib.error.HTTPError as he:
        err_msg = he.read().decode('utf-8') if he.fp else str(he)
        print(f"[-] DeepSeek API HTTP Error: {he.code} - {err_msg}")
        raise HTTPException(status_code=502, detail=f"DeepSeek API error: {err_msg}")
    except Exception as e:
        import traceback
        traceback.print_exc()
        print(f"[-] DeepSeek API error: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to generate AI report: {str(e)}")

from pydantic import BaseModel

class DiffRequest(BaseModel):
    baseline_id: str
    active_id: str

@app.post("/api/diff")
async def diff_pcaps(req: DiffRequest):
    if req.baseline_id not in TASKS or req.active_id not in TASKS:
        raise HTTPException(status_code=404, detail="One or both tasks not found.")
        
    b_task = TASKS[req.baseline_id]
    a_task = TASKS[req.active_id]
    
    if b_task["status"] != "completed" or a_task["status"] != "completed":
        raise HTTPException(status_code=400, detail="Both tasks must be completed before comparison.")
        
    b_res = b_task["results"]
    a_res = a_task["results"]
    
    # 1. Compare Hosts
    b_hosts = {h["ip"]: h for h in b_res["hosts"]}
    a_hosts = {h["ip"]: h for h in a_res["hosts"]}
    
    new_hosts = []
    for ip, host in a_hosts.items():
        if ip not in b_hosts:
            new_hosts.append({
                "ip": ip,
                "mac": host["mac"],
                "os_guess": host["os_guess"],
                "hostname": host["hostname"],
                "total_bytes": host["total_bytes"],
                "open_ports": host["open_ports"]
            })
            
    # 2. Compare Protocols
    new_protocols = []
    for proto in a_res["protocols"].keys():
        if proto not in b_res["protocols"]:
            new_protocols.append(proto)
            
    # 3. Compare Conversations
    b_convs = {f"{c['src']}->{c['dst']}": c for c in b_res["conversations"]}
    new_conversations = []
    for c in a_res["conversations"]:
        key = f"{c['src']}->{c['dst']}"
        if key not in b_convs:
            new_conversations.append(c)
            
    # 4. Compare Alerts
    b_alerts_set = set()
    for a in b_res["alerts"]["malware_detections"]:
        b_alerts_set.add(a["title"])
    for a in b_res["alerts"]["credential_leaks"]:
        b_alerts_set.add(a["detail"])
        
    new_alerts = []
    for a in a_res["alerts"]["malware_detections"]:
        if a["title"] not in b_alerts_set:
            new_alerts.append({
                "type": "malware",
                "title": a["title"],
                "details": a["details"],
                "severity": a["severity"],
                "timestamp": a["timestamp"]
            })
    for a in a_res["alerts"]["credential_leaks"]:
        if a["detail"] not in b_alerts_set:
            new_alerts.append({
                "type": "credential",
                "title": f"Credential Leak ({a['protocol']})",
                "details": a["detail"],
                "severity": "critical",
                "timestamp": a["timestamp"]
            })
            
    security_score_delta = b_res["summary"]["security_score"] - a_res["summary"]["security_score"]
    
    return {
        "baseline_name": b_task["file_name"],
        "active_name": a_task["file_name"],
        "baseline_score": b_res["summary"]["security_score"],
        "active_score": a_res["summary"]["security_score"],
        "security_score_delta": security_score_delta,
        "new_hosts": new_hosts,
        "new_protocols": new_protocols,
        "new_conversations": new_conversations,
        "new_alerts": new_alerts
    }

from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.inet6 import IPv6

@app.get("/api/export-pcap")
async def export_pcap(task_id: str, src_ip: str = None, dst_ip: str = None, proto: str = None):
    if task_id not in TASKS:
        raise HTTPException(status_code=404, detail="Task not found.")
        
    task = TASKS[task_id]
    file_path = task.get("file_path")
    if not file_path or not os.path.exists(file_path):
        raise HTTPException(status_code=404, detail="Original PCAP file not found on server.")
        
    # We will slice packets using Scapy's PcapReader and PcapWriter
    sliced_pcap_name = f"sliced_{task_id}_{uuid.uuid4().hex[:8]}.pcap"
    sliced_pcap_path = os.path.join(UPLOAD_DIR, sliced_pcap_name)
    
    from scapy.utils import PcapWriter, PcapReader
    try:
        writer = PcapWriter(sliced_pcap_path, append=True, sync=True)
        count = 0
        
        with PcapReader(file_path) as reader:
            for pkt in reader:
                # Filter criteria
                matches = True
                if IP in pkt:
                    p_src = pkt[IP].src
                    p_dst = pkt[IP].dst
                    
                    if src_ip and dst_ip:
                        if not ((p_src == src_ip and p_dst == dst_ip) or (p_src == dst_ip and p_dst == src_ip)):
                            matches = False
                    elif src_ip:
                        if p_src != src_ip and p_dst != src_ip:
                            matches = False
                    elif dst_ip:
                        if p_src != dst_ip and p_dst != dst_ip:
                            matches = False
                            
                elif IPv6 in pkt:
                    p_src = pkt[IPv6].src
                    p_dst = pkt[IPv6].dst
                    
                    if src_ip and dst_ip:
                        if not ((p_src == src_ip and p_dst == dst_ip) or (p_src == dst_ip and p_dst == src_ip)):
                            matches = False
                    elif src_ip:
                        if p_src != src_ip and p_dst != src_ip:
                            matches = False
                    elif dst_ip:
                        if p_src != dst_ip and p_dst != dst_ip:
                            matches = False
                else:
                    if src_ip or dst_ip:
                        matches = False
                        
                if matches:
                    writer.write(pkt)
                    count += 1
                    if count >= 5000:
                        break
        writer.close()
        
        if count == 0:
            if os.path.exists(sliced_pcap_path):
                os.remove(sliced_pcap_path)
            raise HTTPException(status_code=400, detail="No packets matched the filter criteria.")
            
        return FileResponse(sliced_pcap_path, media_type="application/octet-stream", filename=f"sliced_{task['file_name']}")
        
    except Exception as e:
        if os.path.exists(sliced_pcap_path):
            try:
                os.remove(sliced_pcap_path)
            except Exception:
                pass
        raise HTTPException(status_code=500, detail=f"Failed to slice PCAP: {str(e)}")

# Serve Frontend static directory if it exists
if os.path.exists(FRONTEND_DIR):
    # Mount Static assets
    static_css = os.path.join(FRONTEND_DIR, "css")
    static_js = os.path.join(FRONTEND_DIR, "js")
    
    os.makedirs(static_css, exist_ok=True)
    os.makedirs(static_js, exist_ok=True)
    
    app.mount("/css", StaticFiles(directory=static_css), name="css")
    app.mount("/js", StaticFiles(directory=static_js), name="js")
    
    @app.get("/", response_class=HTMLResponse)
    async def get_index():
        index_path = os.path.join(FRONTEND_DIR, "index.html")
        if os.path.exists(index_path):
            return FileResponse(index_path)
        return """
        <html>
            <body style="background:#0F172A; color:#F8FAFC; font-family:sans-serif; text-align:center; padding-top:100px;">
                <h1>Packet Spectre UI is initializing...</h1>
                <p>Please wait a few seconds and refresh.</p>
            </body>
        </html>
        """
else:
    print(f"[!] Warning: Frontend folder not found at {FRONTEND_DIR}")

def start_server():
    uvicorn.run("backend.main:app", host="127.0.0.1", port=8000, log_level="info")

if __name__ == "__main__":
    # Auto-open browser in a secondary thread
    timer = threading.Timer(1.5, lambda: webbrowser.open("http://127.0.0.1:8000"))
    timer.start()
    
    # Start web server
    start_server()
