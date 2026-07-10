// Global references
const API_BASE = window.location.protocol === 'file:' ? 'http://127.0.0.1:8000' : '';
let currentTaskId = null;
let pollInterval = null;
let protocolsChartInstance = null;
let originalData = null; // Store final API result for client-side sorting & filters
let selectedAlertFilter = 'all';

// DOM elements
const dropZone = document.getElementById('dropZone');
const fileInput = document.getElementById('fileInput');
const progressCard = document.getElementById('progressCard');
const uploadProgressName = document.getElementById('uploadProgressName');
const uploadProgressPercent = document.getElementById('uploadProgressPercent');
const progressBarFill = document.getElementById('progressBarFill');
const progressStatusText = document.getElementById('progressStatusText');
const activeFileBadge = document.getElementById('activeFileBadge');
const activeFileName = document.getElementById('activeFileName');

const uploadView = document.getElementById('uploadView');
const dashboardView = document.getElementById('dashboardView');

// Event Listeners for Drag and Drop
dropZone.addEventListener('click', () => fileInput.click());

dropZone.addEventListener('dragover', (e) => {
    e.preventDefault();
    dropZone.classList.add('dragover');
});

dropZone.addEventListener('dragleave', () => {
    dropZone.classList.remove('dragover');
});

dropZone.addEventListener('drop', (e) => {
    e.preventDefault();
    dropZone.classList.remove('dragover');
    if (e.dataTransfer.files.length > 0) {
        handleFileUpload(e.dataTransfer.files[0]);
    }
});

fileInput.addEventListener('change', (e) => {
    if (e.target.files.length > 0) {
        handleFileUpload(e.target.files[0]);
    }
});

// Upload and Parse Triggers
function handleFileUpload(file) {
    // Basic verification
    const ext = file.name.split('.').pop().toLowerCase();
    if (!['pcap', 'pcapng', 'cap'].includes(ext)) {
        alert('نوع الملف غير صالح! يرجى اختيار ملف بامتداد .pcap أو .pcapng أو .cap');
        return;
    }

    // Show Progress Card
    progressCard.style.display = 'block';
    uploadProgressName.innerText = file.name;
    uploadProgressPercent.innerText = '0%';
    progressBarFill.style.width = '0%';
    progressStatusText.innerText = 'جاري رفع الملف إلى الخادم...';
    dropZone.style.pointerEvents = 'none';

    // Prepare FormData
    const formData = new FormData();
    formData.append('file', file);

    const keylogInput = document.getElementById('keylogInput');
    if (keylogInput && keylogInput.files.length > 0) {
        formData.append('keylog', keylogInput.files[0]);
    }

    // XHR for upload progress tracking
    const xhr = new XMLHttpRequest();
    xhr.open('POST', API_BASE + '/api/upload', true);

    xhr.upload.onprogress = function(e) {
        if (e.lengthComputable) {
            const percentComplete = Math.round((e.loaded / e.total) * 100);
            progressBarFill.style.width = (percentComplete * 0.3) + '%'; // Reserve 30% for upload, 70% for parsing
            uploadProgressPercent.innerText = Math.round(percentComplete * 0.3) + '%';
        }
    };

    xhr.onload = function() {
        if (xhr.status === 200) {
            const response = JSON.parse(xhr.responseText);
            currentTaskId = response.task_id;
            progressStatusText.innerText = 'تم رفع الملف بنجاح. جاري بدء التحليل ومعالجة الحزم...';
            // Start Polling
            startPolling(currentTaskId);
        } else {
            const err = JSON.parse(xhr.responseText || '{}');
            alert('حدث خطأ أثناء رفع الملف: ' + (err.detail || 'خطأ غير معروف'));
            resetToUpload();
        }
    };

    xhr.onerror = function() {
        alert('فشل الاتصال بالخادم.');
        resetToUpload();
    };

    xhr.send(formData);
}

// Progress Polling
function startPolling(taskId) {
    if (pollInterval) clearInterval(pollInterval);

    pollInterval = setInterval(async () => {
        try {
            const res = await fetch(`${API_BASE}/api/status/${taskId}`);
            if (!res.ok) throw new Error('Failed to fetch status');
            const data = await res.json();

            if (data.status === 'processing') {
                // Map parsing progress from 30% to 100%
                const parseProgress = data.progress || 0;
                const totalProgress = 30 + Math.round(parseProgress * 0.7);
                progressBarFill.style.width = totalProgress + '%';
                uploadProgressPercent.innerText = totalProgress + '%';
                progressStatusText.innerText = `جاري قراءة الحزم وتحليل الشبكة... تم معالجة (${data.packet_count.toLocaleString()}) حزمة.`;
            } else if (data.status === 'completed') {
                clearInterval(pollInterval);
                progressBarFill.style.width = '100%';
                uploadProgressPercent.innerText = '100%';
                progressStatusText.innerText = 'اكتمل التحليل! جاري جلب لوحة التحكم...';
                
                // Fetch final results
                fetchResults(taskId);
            } else if (data.status === 'failed') {
                clearInterval(pollInterval);
                alert('فشل تحليل الملف: ' + data.error);
                resetToUpload();
            }
        } catch (err) {
            console.error(err);
        }
    }, 800);
}

// Fetch Results and Render Dashboard
async function fetchResults(taskId) {
    try {
        const res = await fetch(`${API_BASE}/api/results/${taskId}`);
        if (!res.ok) throw new Error('Failed to load results');
        const results = await res.json();
        
        originalData = results;
        
        // Render all UI components
        renderDashboard(results);
        
        // Switch view
        uploadView.style.display = 'none';
        dashboardView.style.display = 'block';
        activeFileBadge.style.display = 'flex';
        
        // Reset upload controls
        dropZone.style.pointerEvents = 'auto';
        progressCard.style.display = 'none';
    } catch (err) {
        alert('حدث خطأ أثناء جلب تفاصيل التقرير: ' + err.message);
        resetToUpload();
    }
}

function resetToUpload() {
    if (pollInterval) clearInterval(pollInterval);
    currentTaskId = null;
    originalData = null;
    
    // UI Reset
    activeFileBadge.style.display = 'none';
    dashboardView.style.display = 'none';
    uploadView.style.display = 'flex';
    progressCard.style.display = 'none';
    dropZone.style.pointerEvents = 'auto';
    fileInput.value = '';
}

// Switch tabs inside dashboard
function switchTab(tabId) {
    // Hide all tab contents
    document.querySelectorAll('.tab-content').forEach(el => el.classList.remove('active'));
    // Deactivate all buttons
    document.querySelectorAll('.tab-btn').forEach(el => el.classList.remove('active'));
    
    // Show active tab
    document.getElementById(tabId).classList.add('active');
    
    // Find matching button
    const btn = Array.from(document.querySelectorAll('.tab-btn')).find(b => b.getAttribute('onclick').includes(tabId));
    if (btn) btn.classList.add('active');
}

// Populate Dashboard Data
function renderDashboard(data) {
    // Header file name
    activeFileName.innerText = data.summary.file_name || 'ملف تم رفعه';
    document.getElementById('metaFileName').innerText = data.summary.file_name || 'ملف تسجيل خارجي';
    
    // KPI metrics
    document.getElementById('statPacketCount').innerText = data.summary.packet_count.toLocaleString();
    document.getElementById('statDuration').innerText = data.summary.duration_seconds.toLocaleString() + ' ثانية';
    
    // Format File Size
    const mbSize = (data.summary.total_bytes / (1024 * 1024)).toFixed(2);
    document.getElementById('statTotalBytes').innerText = mbSize + ' MB';
    
    // Security score color management
    const scoreVal = data.summary.security_score;
    const scoreEl = document.getElementById('statSecurityScore');
    const scoreCard = document.getElementById('securityScoreCard');
    const scoreIcon = document.getElementById('scoreIcon');
    
    scoreEl.innerText = scoreVal + ' / 100';
    scoreIcon.className = 'kpi-icon';
    
    if (scoreVal >= 80) {
        scoreIcon.classList.add('score-safe');
        scoreIcon.innerHTML = '<i class="fa-solid fa-shield-halved"></i>';
    } else if (scoreVal >= 50) {
        scoreIcon.classList.add('score-warning');
        scoreIcon.innerHTML = '<i class="fa-solid fa-triangle-exclamation"></i>';
    } else {
        scoreIcon.classList.add('score-danger');
        scoreIcon.innerHTML = '<i class="fa-solid fa-circle-radiation"></i>';
    }

    // Set side panel counts for security
    const credsCount = data.alerts.credential_leaks.length;
    const spoofsCount = data.alerts.arp_spoofs.length;
    const scansCount = data.alerts.port_scans.length;
    const dnsCount = data.alerts.dns_anomalies.length;
    const malwareCount = data.alerts.malware_detections ? data.alerts.malware_detections.length : 0;
    const totalAlerts = credsCount + spoofsCount + scansCount + dnsCount + malwareCount;

    document.getElementById('alertCountAll').innerText = totalAlerts;
    document.getElementById('alertCountCreds').innerText = credsCount;
    document.getElementById('alertCountSpoofs').innerText = spoofsCount;
    document.getElementById('alertCountScans').innerText = scansCount;
    document.getElementById('alertCountDns').innerText = dnsCount;
    document.getElementById('alertCountMalware').innerText = malwareCount;

    // Security Alert Badge on Tab Header
    const tabBadge = document.getElementById('securityAlertBadge');
    if (totalAlerts > 0) {
        tabBadge.innerText = totalAlerts;
        tabBadge.style.display = 'inline-block';
    } else {
        tabBadge.style.display = 'none';
    }
    
    // Text summary details
    const startTimeStr = data.summary.first_packet_time ? new Date(data.summary.first_packet_time).toLocaleString('ar-SA') : 'غير متوفر';
    const endTimeStr = data.summary.last_packet_time ? new Date(data.summary.last_packet_time).toLocaleString('ar-SA') : 'غير متوفر';
    
    document.getElementById('metaStartTime').innerText = startTimeStr;
    document.getElementById('metaEndTime').innerText = endTimeStr;
    
    // Average Bandwidth speed format
    const speedBps = data.summary.avg_speed_bps;
    let speedStr = '0 bps';
    if (speedBps > 1000000) {
        speedStr = (speedBps / 1000000).toFixed(2) + ' Mbps';
    } else if (speedBps > 1000) {
        speedStr = (speedBps / 1000).toFixed(2) + ' Kbps';
    } else {
        speedStr = speedBps.toFixed(2) + ' bps';
    }
    document.getElementById('metaAvgSpeed').innerText = speedStr;

    // Detect Protocols Names
    const protoNames = Object.keys(data.protocols).join(', ');
    document.getElementById('metaDetectedProtos').innerText = protoNames || 'غير محدد';
    
    // TCP Health Metrics
    document.getElementById('tcpRetransmissionsVal').innerText = data.alerts.credential_leaks ? (originalData.alerts.retransmissions_count || 0).toLocaleString() : '0';
    // Wait, in analyzer we computed self.tcp_retransmissions and resets. Let's map it safely
    document.getElementById('tcpRetransmissionsVal').innerText = (originalData.tcp_retransmissions || 0).toLocaleString();
    document.getElementById('tcpResetsVal').innerText = (originalData.tcp_resets || 0).toLocaleString();
    
    // TCP health text opinion
    const tcpOpinionEl = document.getElementById('tcpHealthOpinion');
    const totalPackets = data.summary.packet_count;
    const retrPercent = totalPackets > 0 ? (originalData.tcp_retransmissions / totalPackets) * 100 : 0;
    
    if (retrPercent > 5) {
        tcpOpinionEl.innerHTML = `<span style="color:#FF0844"><strong>تنبيه هندسي:</strong> نسبة فقد الحزم وإعادة الإرسال مرتفعة (${retrPercent.toFixed(2)}%). قد يشير ذلك إلى اختناق في مسار الشبكة أو تشويش عالي.</span>`;
    } else if (originalData.tcp_resets > 100) {
        tcpOpinionEl.innerHTML = `<span style="color:#F59E0B"><strong>ملاحظة فنية:</strong> تم رصد عدد كبير من حزم قطع الاتصال المفاجئ (TCP RST). يرجى التحقق من جدار الحماية أو خوادم لا تستجيب للمنافذ.</span>`;
    } else {
        tcpOpinionEl.innerHTML = "صحة اتصالات الـ TCP ممتازة ومستقرة، ومعدل فقد الحزم في الحدود الطبيعية وآمن جداً.";
    }

    // Render Charts & Tables
    renderProtocolsChart(data.protocols);
    renderUnencryptedBadges(data.alerts.unencrypted_protocols);
    renderAlertsList();
    renderConversationsTable();
    renderDNSTable();
    renderHostsTable();
    renderTopologyMap(data);
    renderDiagnostics(data);
}

// 1. Protocols Chart (Chart.js)
function renderProtocolsChart(protocols) {
    const ctx = document.getElementById('protocolsChart').getContext('2d');
    
    // Destroy existing chart to prevent canvas redraw glitches
    if (protocolsChartInstance) {
        protocolsChartInstance.destroy();
    }
    
    const labels = Object.keys(protocols);
    const values = Object.values(protocols);
    
    // Premium dark palette colors
    const colors = [
        '#00F2FE', '#4FACFE', '#10B981', '#A855F7', '#3B82F6', 
        '#F59E0B', '#EF4444', '#EC4899', '#6366F1', '#14B8A6'
    ];
    
    protocolsChartInstance = new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: labels,
            datasets: [{
                data: values,
                backgroundColor: colors.slice(0, labels.length),
                borderWidth: 2,
                borderColor: '#0B0F19'
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    position: 'bottom',
                    labels: {
                        color: '#94A3B8',
                        font: {
                            family: 'Tajawal',
                            size: 11
                        },
                        padding: 15
                    }
                }
            },
            cutout: '65%'
        }
    });
}

// Unencrypted Protocols Badges
function renderUnencryptedBadges(protos) {
    const container = document.getElementById('unencryptedProtocolsBadges');
    container.innerHTML = '';
    
    if (!protos || protos.length === 0) {
        container.innerHTML = '<span style="color:#10B981; font-size:13px;"><i class="fa-solid fa-circle-check"></i> لم يتم العثور على أي بروتوكول غير مشفر. جميع الاتصالات مشفرة!</span>';
        return;
    }
    
    protos.forEach(proto => {
        const badge = document.createElement('span');
        badge.className = 'proto-badge';
        badge.innerHTML = `<i class="fa-solid fa-unlock"></i> ${proto}`;
        container.appendChild(badge);
    });
}

// 2. Filter & Render Alerts (Security Tab)
function filterAlerts(category) {
    selectedAlertFilter = category;
    
    // Style active sidebar item
    document.querySelectorAll('.alert-category-item').forEach(el => el.classList.remove('active'));
    
    let btn;
    if (category === 'all') {
        btn = document.querySelector(".alert-category-item[onclick=\"filterAlerts('all')\"]");
        document.getElementById('currentAlertCategoryTitle').innerText = 'كافة الثغرات والتهديدات المكتشفة';
    } else if (category === 'creds') {
        btn = document.querySelector(".alert-category-item[onclick=\"filterAlerts('creds')\"]");
        document.getElementById('currentAlertCategoryTitle').innerText = 'تسريبات الحسابات والبيانات المكشوفة';
    } else if (category === 'spoofs') {
        btn = document.querySelector(".alert-category-item[onclick=\"filterAlerts('spoofs')\"]");
        document.getElementById('currentAlertCategoryTitle').innerText = 'انتحال الهوية وهجمات طبقة الشبكة (ARP)';
    } else if (category === 'scans') {
        btn = document.querySelector(".alert-category-item[onclick=\"filterAlerts('scans')\"]");
        document.getElementById('currentAlertCategoryTitle').innerText = 'عمليات فحص المنافذ والتجسس النشط';
    } else if (category === 'dns') {
        btn = document.querySelector(".alert-category-item[onclick=\"filterAlerts('dns')\"]");
        document.getElementById('currentAlertCategoryTitle').innerText = 'طلبات DNS مريبة ومؤشرات خوادم C2';
    } else if (category === 'malware') {
        btn = document.querySelector(".alert-category-item[onclick=\"filterAlerts('malware')\"]");
        document.getElementById('currentAlertCategoryTitle').innerText = 'نشاط برمجيات خبيثة وخوادم تحكم (Malware & C2)';
    }
    
    if (btn) btn.classList.add('active');
    
    renderAlertsList();
}

function renderAlertsList() {
    const container = document.getElementById('alertsListContainer');
    container.innerHTML = '';
    
    if (!originalData) return;
    
    let alerts = [];
    
    // Collate alerts by type
    if (selectedAlertFilter === 'all' || selectedAlertFilter === 'creds') {
        originalData.alerts.credential_leaks.forEach(a => {
            alerts.push({
                ...a,
                severity: 'critical',
                title: `تسريب بيانات اعتماد (${a.protocol})`,
                desc: a.detail,
                meta: `المصدر: ${a.src}  |  الوجهة: ${a.dst}`
            });
        });
    }
    
    if (selectedAlertFilter === 'all' || selectedAlertFilter === 'spoofs') {
        originalData.alerts.arp_spoofs.forEach(a => {
            alerts.push({
                ...a,
                severity: 'critical',
                title: `انتحال عناوين ARP (ARP Spoofing)`,
                desc: a.details,
                meta: `عنوان الـ IP المتأثر: ${a.ip}  |  عناوين الـ MAC المرصودة: ${a.macs.join(' , ')}`
            });
        });
    }
    
    if (selectedAlertFilter === 'all' || selectedAlertFilter === 'scans') {
        originalData.alerts.port_scans.forEach(a => {
            alerts.push({
                ...a,
                severity: 'warning',
                title: `فحص المنافذ والشبكة الاستطلاعي (Port Scan)`,
                desc: a.details,
                meta: `الجهاز القائم بالفحص: ${a.ip}  |  عدد المنافذ المستهدفة: ${a.ports_count}`
            });
        });
    }
    
    if (selectedAlertFilter === 'all' || selectedAlertFilter === 'dns') {
        originalData.alerts.dns_anomalies.forEach(a => {
            alerts.push({
                ...a,
                severity: 'info',
                title: `طلب نطاق مريب (DNS anomaly) - ${a.type}`,
                desc: a.reason,
                meta: `صاحب الطلب: ${a.client}  |  النطاق المستعلم عنه: ${a.query}`
            });
        });
    }
    
    if (selectedAlertFilter === 'all' || selectedAlertFilter === 'malware') {
        if (originalData.alerts.malware_detections) {
            originalData.alerts.malware_detections.forEach(a => {
                alerts.push({
                    ...a,
                    severity: 'critical',
                    title: a.title,
                    desc: a.details,
                    meta: a.meta
                });
            });
        }
    }
    
    // Sort alerts by timestamp/severity if possible
    if (alerts.length === 0) {
        container.innerHTML = `
            <div class="empty-state">
                <i class="fa-solid fa-shield-heart icon-green"></i>
                <p>لم يتم العثور على تهديدات أمنية تندرج تحت هذا القسم.</p>
            </div>
        `;
        return;
    }
    
    alerts.forEach(alert => {
        const card = document.createElement('div');
        card.className = `alert-card ${alert.severity}-border`;
        
        // Extract src and dst IPs for action button
        let srcVal = '';
        let dstVal = '';
        if (alert.protocol && alert.src && alert.dst) { // Cred leaks
            srcVal = alert.src;
            dstVal = alert.dst;
        } else if (alert.ip) { // ARP spoofs or Port scans
            srcVal = alert.ip;
        } else if (alert.client) { // DNS
            srcVal = alert.client;
        } else if (alert.src_ip || alert.dst_ip) { // Malware
            srcVal = alert.src_ip || '';
            dstVal = alert.dst_ip || '';
        }
        
        card.innerHTML = `
            <div class="alert-header">
                <span class="alert-type-badge ${alert.severity}-badge">${alert.severity === 'critical' ? 'خطير جداً' : alert.severity === 'warning' ? 'متوسط الخطورة' : 'تنبيه إرشادي'}</span>
                <span class="alert-time">${alert.timestamp || ''}</span>
            </div>
            <div class="alert-title">${alert.title}</div>
            <div class="alert-desc">${alert.desc}</div>
            <div class="alert-meta">${alert.meta}</div>
            <div class="alert-actions" style="margin-top: 12px; display: flex; justify-content: flex-end;">
                <button class="btn-slice-pcap" onclick="downloadAlertPcap('${srcVal}', '${dstVal}')" style="background: rgba(168, 85, 247, 0.15); border: 1px solid rgba(168, 85, 247, 0.3); color: #d8b4fe; padding: 6px 12px; border-radius: 6px; cursor: pointer; font-size: 11px; display: flex; align-items: center; gap: 6px; transition: all 0.2s;">
                    <i class="fa-solid fa-download"></i> تحميل حزم هذا التهديد (PCAP Slice)
                </button>
            </div>
        `;
        
        container.appendChild(card);
    });
}

// Helper to download sliced PCAP for alerts or hosts
function downloadAlertPcap(src, dst) {
    if (!currentTaskId) {
        alert('جلسة التحليل غير متوفرة.');
        return;
    }
    const srcIp = src ? src.split(':')[0].trim() : '';
    const dstIp = dst ? dst.split(':')[0].trim() : '';
    
    let url = `${API_BASE}/api/export-pcap?task_id=${currentTaskId}`;
    if (srcIp) url += `&src_ip=${srcIp}`;
    if (dstIp) url += `&dst_ip=${dstIp}`;
    
    window.open(url, '_blank');
}

// 3. Render Conversations Table
function renderConversationsTable() {
    const tbody = document.getElementById('conversationsTableBody');
    tbody.innerHTML = '';
    
    if (!originalData || !originalData.conversations) return;
    
    originalData.conversations.forEach(conv => {
        const tr = document.createElement('tr');
        // Format byte sizes nicely
        let sizeStr = conv.bytes.toLocaleString() + ' B';
        if (conv.bytes > 1024 * 1024) {
            sizeStr = (conv.bytes / (1024 * 1024)).toFixed(2) + ' MB';
        } else if (conv.bytes > 1024) {
            sizeStr = (conv.bytes / 1024).toFixed(2) + ' KB';
        }
        
        tr.innerHTML = `
            <td><strong>${conv.src}</strong></td>
            <td><strong>${conv.dst}</strong></td>
            <td><span class="port-pill">${conv.protocol}</span></td>
            <td>${conv.packets.toLocaleString()}</td>
            <td>${sizeStr}</td>
        `;
        tbody.appendChild(tr);
    });
}

function filterConversationsTable() {
    const q = document.getElementById('searchConversations').value.toLowerCase();
    const rows = document.querySelectorAll('#conversationsTable tbody tr');
    
    rows.forEach(row => {
        const src = row.cells[0].textContent.toLowerCase();
        const dst = row.cells[1].textContent.toLowerCase();
        if (src.includes(q) || dst.includes(q)) {
            row.style.display = '';
        } else {
            row.style.display = 'none';
        }
    });
}

// 4. Render DNS Map Table
function renderDNSTable() {
    const tbody = document.getElementById('dnsTableBody');
    tbody.innerHTML = '';
    
    if (!originalData || !originalData.dns_records) return;
    
    if (originalData.dns_records.length === 0) {
        tbody.innerHTML = '<tr><td colspan="3" style="text-align:center; color:#64748B;">لا يوجد سجل استعلامات DNS في هذا الملف.</td></tr>';
        return;
    }
    
    originalData.dns_records.forEach(dns => {
        const ips = dns.resolved_ips && dns.resolved_ips.length > 0 
                    ? dns.resolved_ips.map(ip => `<span class="port-pill" style="color:#00F2FE">${ip}</span>`).join(' ')
                    : '<span style="color:#64748B">لم يحل بعد</span>';
        const tr = document.createElement('tr');
        tr.innerHTML = `
            <td style="font-family:monospace; direction:ltr; text-align:right;">${dns.domain}</td>
            <td>${dns.count}</td>
            <td>${ips}</td>
        `;
        tbody.appendChild(tr);
    });
}

// 5. Render Hosts Map Table
function renderHostsTable() {
    const tbody = document.getElementById('hostsTableBody');
    tbody.innerHTML = '';
    
    if (!originalData || !originalData.hosts) return;
    
    originalData.hosts.forEach(host => {
        const tr = document.createElement('tr');
        
        let sizeStr = host.total_bytes.toLocaleString() + ' B';
        if (host.total_bytes > 1024 * 1024) {
            sizeStr = (host.total_bytes / (1024 * 1024)).toFixed(2) + ' MB';
        } else if (host.total_bytes > 1024) {
            sizeStr = (host.total_bytes / 1024).toFixed(2) + ' KB';
        }
        
        // Generate Port pills
        let portsPills = '';
        if (host.open_ports && host.open_ports.length > 0) {
            portsPills = `<div class="ports-container">`;
            host.open_ports.slice(0, 8).forEach(p => {
                portsPills += `<span class="port-pill">${p}</span>`;
            });
            if (host.open_ports.length > 8) {
                portsPills += `<span class="port-pill" style="background:rgba(0,242,254,0.1); border-color:var(--color-primary);">+${host.open_ports.length - 8}</span>`;
            }
            portsPills += `</div>`;
        } else {
            portsPills = '<span style="color:#64748B">لا يوجد</span>';
        }
        
        // Custom color for OS Guess
        let osColor = '#94A3B8';
        if (host.os_guess.includes('Windows')) osColor = '#3B82F6';
        else if (host.os_guess.includes('Linux') || host.os_guess.includes('macOS')) osColor = '#10B981';
        
        tr.innerHTML = `
            <td><strong>${host.ip}</strong></td>
            <td style="font-family:monospace;">${host.mac}</td>
            <td style="color:${osColor}; font-weight:700;">${host.os_guess}</td>
            <td>${host.sent_packets.toLocaleString()}</td>
            <td>${host.recv_packets.toLocaleString()}</td>
            <td>${sizeStr}</td>
            <td>${portsPills}</td>
        `;
        
        tbody.appendChild(tr);
    });
}

function filterHostsTable() {
    const q = document.getElementById('searchHosts').value.toLowerCase();
    const rows = document.querySelectorAll('#hostsTable tbody tr');
    
    rows.forEach(row => {
        const ip = row.cells[0].textContent.toLowerCase();
        const mac = row.cells[1].textContent.toLowerCase();
        const os = row.cells[2].textContent.toLowerCase();
        if (ip.includes(q) || mac.includes(q) || os.includes(q)) {
            row.style.display = '';
        } else {
            row.style.display = 'none';
        }
    });
}

// ==========================================
// DeepSeek AI Integration Functions
// ==========================================

// Call backend to trigger DeepSeek AI Report generation
async function generateAiReport() {
    if (!currentTaskId) {
        alert('لا توجد جلسة تحليل نشطة. يرجى رفع ملف PCAP أولاً.');
        return;
    }
    
    const generateBtn = document.getElementById('generateAiReportBtn');
    const loader = document.getElementById('aiLoader');
    const outputContainer = document.getElementById('aiReportOutput');
    
    generateBtn.disabled = true;
    loader.style.display = 'flex';
    outputContainer.innerHTML = '';
    
    try {
        const res = await fetch(`${API_BASE}/api/ai-report/${currentTaskId}`, {
            method: 'POST'
        });
        
        if (res.ok) {
            const data = await res.json();
            outputContainer.innerHTML = renderMarkdown(data.report);
        } else {
            const err = await res.json();
            alert('فشل توليد التقرير بالذكاء الاصطناعي: ' + (err.detail || 'تأكد من إدخال مفتاح الـ API وصحته.'));
            outputContainer.innerHTML = `
                <div class="empty-state">
                    <i class="fa-solid fa-triangle-exclamation icon-red" style="color:var(--color-danger)"></i>
                    <p style="margin-top: 15px;">حدث خطأ: ${err.detail || 'فشل الاتصال بـ DeepSeek. يرجى التحقق من المفتاح والاتصال.'}</p>
                </div>
            `;
        }
    } catch (err) {
        alert('حدث خطأ أثناء الاتصال بالخادم: ' + err.message);
    } finally {
        generateBtn.disabled = false;
        loader.style.display = 'none';
    }
}

// Custom Markdown to HTML Renderer
function renderMarkdown(md) {
    if (!md) return '';
    let html = md
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;");
        
    // Headers
    html = html.replace(/^### (.*$)/gim, '<h3>$1</h3>');
    html = html.replace(/^## (.*$)/gim, '<h2>$1</h2>');
    html = html.replace(/^# (.*$)/gim, '<h1>$1</h1>');
    
    // Bold / Italic
    html = html.replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>');
    html = html.replace(/\*(.*?)\*/g, '<em>$1</em>');
    
    // Code blocks
    html = html.replace(/```([\s\S]*?)```/g, '<pre><code>$1</code></pre>');
    html = html.replace(/`(.*?)`/g, '<code>$1</code>');
    
    // Blockquotes (temp placeholder for &gt;)
    html = html.replace(/^&gt;\s+(.*)$/gim, '<blockquote>$1</blockquote>');
    
    // Lists
    html = html.replace(/^\s*[-*+]\s+(.*)$/gim, '<li>$1</li>');
    
    // Tables
    const lines = html.split('\n');
    let inTable = false;
    let tableHtml = '';
    
    for (let i = 0; i < lines.length; i++) {
        let line = lines[i].trim();
        if (line.startsWith('|') && line.endsWith('|')) {
            if (!inTable) {
                inTable = true;
                tableHtml = '<table><thead>';
            }
            
            let cells = line.split('|').map(c => c.trim()).filter((c, idx, arr) => idx > 0 && idx < arr.length - 1);
            
            if (tableHtml.endsWith('<thead>') && line.includes('---')) {
                tableHtml = tableHtml.replace('<thead>', '') + '<tbody>';
                continue;
            }
            
            let isHeader = tableHtml.endsWith('<thead>');
            let cellTag = isHeader ? 'th' : 'td';
            
            tableHtml += '<tr>' + cells.map(c => `<${cellTag}>${c}</${cellTag}>`).join('') + '</tr>';
            
            if (isHeader) {
                tableHtml += '</thead>';
            }
            lines[i] = '';
        } else {
            if (inTable) {
                inTable = false;
                tableHtml += '</tbody></table>';
                lines[i] = tableHtml + '\n' + lines[i];
                tableHtml = '';
            }
        }
    }
    
    html = lines.join('\n');
    
    // Replace double linebreaks with paragraphs
    html = html.split(/\n\n+/).map(p => {
        p = p.trim();
        if (p.startsWith('<h') || p.startsWith('<ul') || p.startsWith('<ol') || p.startsWith('<table') || p.startsWith('<blockquote') || p.startsWith('<pre')) {
            return p;
        }
        return `<p>${p.replace(/\n/g, '<br>')}</p>`;
    }).join('\n');
    
    return `<div class="ai-report-content">${html}</div>`;
}

// ==========================================
// Network Topology Map (Vis.js Rendering)
// ==========================================
let topologyNetworkInstance = null;

function renderTopologyMap(data) {
    const canvasContainer = document.getElementById('networkTopologyCanvas');
    if (!canvasContainer) return;
    
    // Clear details panel on reload
    document.getElementById('topologyHostDetails').innerHTML = `
        <div class="empty-state">
            <i class="fa-solid fa-mouse-pointer icon-blue"></i>
            <p style="margin-top:15px;">انقر على أي جهاز في المخطط الشبكي يساراً لاستعراض بصمته الجنائية وتفاصيل اتصالاته.</p>
        </div>
    `;

    if (!data || !data.hosts || data.hosts.length === 0) {
        canvasContainer.innerHTML = '<div class="empty-state"><p>لا توجد بيانات شبكة كافية لرسم المخطط.</p></div>';
        return;
    }

    // Build lists of hosts involved in alerts
    const infectedIPs = new Set();
    const scannerIPs = new Set();
    
    if (data.alerts) {
        if (data.alerts.malware_detections) {
            data.alerts.malware_detections.forEach(a => {
                if (a.src_ip) infectedIPs.add(a.src_ip);
                if (a.dst_ip) infectedIPs.add(a.dst_ip);
            });
        }
        if (data.alerts.credential_leaks) {
            data.alerts.credential_leaks.forEach(a => {
                if (a.src) infectedIPs.add(a.src.split(':')[0]);
                if (a.dst) infectedIPs.add(a.dst.split(':')[0]);
            });
        }
        if (data.alerts.port_scans) {
            data.alerts.port_scans.forEach(a => {
                if (a.ip) scannerIPs.add(a.ip);
            });
        }
    }

    const nodes = [];
    const edges = [];
    const nodeSet = new Set();

    // 1. Create Nodes (Hosts)
    data.hosts.forEach(host => {
        let nodeColor = '#3b82f6'; // Clean client IP - Blue
        let border = '#1e3a8a';
        let title = `جهاز شبكة: ${host.ip}`;
        
        if (infectedIPs.has(host.ip)) {
            nodeColor = '#ef4444'; // Infected - Red
            border = '#7f1d1d';
            title = `⚠️ جهاز مصاب / مشتبه به: ${host.ip}`;
        } else if (scannerIPs.has(host.ip)) {
            nodeColor = '#f59e0b'; // Port scanner - Yellow
            border = '#78350f';
            title = `🔍 جهاز يقوم بمسح المنافذ: ${host.ip}`;
        } else if (host.ip.startsWith('10.') || host.ip.startsWith('192.168.') || host.ip.startsWith('172.16.')) {
            nodeColor = '#10b981'; // Normal internal host - Green
            border = '#064e3b';
        }

        const size = 15 + Math.min(30, Math.log10(host.total_bytes + 1) * 3);
        const label = host.hostname !== 'Unknown' ? `${host.hostname}\n(${host.ip})` : host.ip;

        nodes.push({
            id: host.ip,
            label: label,
            title: title,
            shape: 'dot',
            size: size,
            color: {
                background: nodeColor,
                border: border,
                highlight: { background: '#a855f7', border: '#701a75' }
            },
            font: { color: '#f8fafc', face: 'Tajawal', size: 10 }
        });
        nodeSet.add(host.ip);
    });

    // 2. Create Edges (Conversations)
    data.conversations.forEach(conv => {
        if (!nodeSet.has(conv.src)) {
            nodes.push({
                id: conv.src,
                label: conv.src,
                shape: 'dot',
                size: 10,
                color: { background: '#64748b', border: '#334155' },
                font: { color: '#94a3b8', face: 'Tajawal', size: 9 }
            });
            nodeSet.add(conv.src);
        }
        if (!nodeSet.has(conv.dst)) {
            nodes.push({
                id: conv.dst,
                label: conv.dst,
                shape: 'dot',
                size: 10,
                color: { background: '#64748b', border: '#334155' },
                font: { color: '#94a3b8', face: 'Tajawal', size: 9 }
            });
            nodeSet.add(conv.dst);
        }

        const width = Math.max(1, Math.min(10, Math.log10(conv.bytes + 1)));

        edges.push({
            from: conv.src,
            to: conv.dst,
            width: width,
            color: { color: 'rgba(255, 255, 255, 0.15)', highlight: '#a855f7' },
            arrows: { to: { enabled: true, scaleFactor: 0.5 } }
        });
    });

    // Destroy existing network instance if active
    if (topologyNetworkInstance) {
        topologyNetworkInstance.destroy();
    }

    const networkData = {
        nodes: new vis.DataSet(nodes),
        edges: new vis.DataSet(edges)
    };

    const options = {
        physics: {
            stabilization: true,
            barnesHut: {
                gravitationalConstant: -2000,
                centralGravity: 0.3,
                springLength: 95
            }
        },
        interaction: {
            hover: true,
            tooltipDelay: 200
        }
    };

    canvasContainer.innerHTML = '';
    topologyNetworkInstance = new vis.Network(canvasContainer, networkData, options);

    // Node click details display
    topologyNetworkInstance.on("selectNode", function (params) {
        const clickedIp = params.nodes[0];
        const host = data.hosts.find(h => h.ip === clickedIp);
        const detailsEl = document.getElementById('topologyHostDetails');
        
        if (!host) {
            detailsEl.innerHTML = `
                <div class="diff-card-detail">
                    <h4 style="color:var(--color-primary);">${clickedIp}</h4>
                    <p style="margin-top:10px; font-size:12px; color:#94a3b8;">عنوان خارجي أو غير مدرج في السجل المحلي المباشر.</p>
                    <div style="margin-top:20px;">
                        <button class="btn-primary" onclick="downloadAlertPcap('${clickedIp}', '')" style="padding: 6px 12px; font-size: 11px;">
                            <i class="fa-solid fa-download"></i> تحميل كافة حزم هذا العنوان (PCAP Slice)
                        </button>
                    </div>
                </div>
            `;
            return;
        }

        const sizeStr = host.total_bytes.toLocaleString() + ' B';
        const portBadges = host.open_ports.length > 0 
            ? host.open_ports.map(p => `<span class="proto-badge" style="background:rgba(59, 130, 246, 0.2); border:1px solid rgba(59,130,246,0.3); color:#93c5fd; padding:3px 6px; font-size:10px;">${p}</span>`).join(' ') 
            : '<span style="color:#94a3b8; font-size:12px;">لا توجد منافذ مفتوحة مرصودة</span>';

        detailsEl.innerHTML = `
            <div class="host-detail-pane animate-fade-in" style="display:flex; flex-direction:column; gap:15px;">
                <div style="border-bottom:1px solid var(--border-color); padding-bottom:10px;">
                    <h4 style="color:var(--color-secondary); font-size:16px; margin:0;">${host.ip}</h4>
                    <span style="font-size:11px; color:#94a3b8;">الاسم: ${host.hostname || 'غير معروف'}</span>
                </div>
                
                <div style="display:grid; grid-template-columns:1fr 1fr; gap:10px; font-size:12px;">
                    <div><strong>عنوان الـ MAC:</strong></div>
                    <div style="color:#cbd5e1; text-align:left;">${host.mac}</div>
                    
                    <div><strong>تخمين النظام (OS):</strong></div>
                    <div style="color:#cbd5e1; text-align:left;">${host.os_guess}</div>
                    
                    <div><strong>حزم مرسلة:</strong></div>
                    <div style="color:#cbd5e1; text-align:left;">${host.sent_packets.toLocaleString()}</div>
                    
                    <div><strong>حزم مستقبلة:</strong></div>
                    <div style="color:#cbd5e1; text-align:left;">${host.recv_packets.toLocaleString()}</div>
                    
                    <div><strong>حجم البيانات:</strong></div>
                    <div style="color:#cbd5e1; text-align:left;">${sizeStr}</div>
                </div>
                
                <div style="margin-top:10px;">
                    <strong style="font-size:12px; display:block; margin-bottom:8px;">المنافذ النشطة المفتوحة:</strong>
                    <div style="display:flex; flex-wrap:wrap; gap:5px;">
                        ${portBadges}
                    </div>
                </div>

                <div style="margin-top:25px; border-top:1px solid var(--border-color); padding-top:15px;">
                    <button class="btn-primary" onclick="downloadAlertPcap('${host.ip}', '')" style="width:100%; padding: 8px 12px; font-size: 11px; display:flex; justify-content:center; align-items:center; gap:8px;">
                        <i class="fa-solid fa-download"></i> تحميل كافة حزم هذا الجهاز (PCAP Slice)
                    </button>
                </div>
            </div>
        `;
    });
}

// ==========================================
// PCAP Session Diffing Logic
// ==========================================
async function uploadAndPollForDiff(file, progressCallback) {
    return new Promise((resolve, reject) => {
        const formData = new FormData();
        formData.append('file', file);
        
        const xhr = new XMLHttpRequest();
        xhr.open('POST', API_BASE + '/api/upload', true);
        
        xhr.upload.onprogress = function(e) {
            if (e.lengthComputable && progressCallback) {
                const percent = Math.round((e.loaded / e.total) * 100);
                progressCallback(percent);
            }
        };
        
        xhr.onload = function() {
            if (xhr.status === 200) {
                const res = JSON.parse(xhr.responseText);
                const taskId = res.task_id;
                
                const interval = setInterval(async () => {
                    try {
                        const statusRes = await fetch(`${API_BASE}/api/status/${taskId}`);
                        if (!statusRes.ok) return;
                        const statusData = await statusRes.json();
                        
                        if (statusData.status === 'completed') {
                            clearInterval(interval);
                            resolve(taskId);
                        } else if (statusData.status === 'failed') {
                            clearInterval(interval);
                            reject(new Error(statusData.error || 'فشلت معالجة الملف.'));
                        }
                    } catch (err) {
                        clearInterval(interval);
                        reject(err);
                    }
                }, 1000);
            } else {
                reject(new Error('فشل الرفع للمخدم.'));
            }
        };
        
        xhr.onerror = () => reject(new Error('فشل الاتصال بالشبكة.'));
        xhr.send(formData);
    });
}

async function compareUploadedPcaps() {
    const baselineFile = document.getElementById('diffPcapBaseline').files[0];
    const activeFile = document.getElementById('diffPcapActive').files[0];
    
    if (!baselineFile || !activeFile) {
        alert('الرجاء اختيار كلا الملفين للمقارنة (ملف الأساس السليم والملف النشط).');
        return;
    }
    
    const compareBtn = document.getElementById('btnComparePcaps');
    const diffProgress = document.getElementById('diffProgressCard');
    const diffProgressBar = document.getElementById('diffProgressBarFill');
    const diffProgressText = document.getElementById('diffProgressText');
    const diffResults = document.getElementById('diffResultsContainer');
    
    compareBtn.disabled = true;
    diffProgress.style.display = 'block';
    diffResults.style.display = 'none';
    diffProgressBar.style.width = '0%';
    
    try {
        diffProgressText.innerText = 'جاري رفع وتحليل ملف الأساس (Baseline PCAP)...';
        const baselineId = await uploadAndPollForDiff(baselineFile, (percent) => {
            diffProgressBar.style.width = (percent * 0.4) + '%';
        });
        
        diffProgressText.innerText = 'جاري رفع وتحليل ملف الاشتباه (Active PCAP)...';
        const activeId = await uploadAndPollForDiff(activeFile, (percent) => {
            diffProgressBar.style.width = (40 + percent * 0.4) + '%';
        });
        
        diffProgressText.innerText = 'جاري دمج النتائج ومقارنتها عبر الـ AI...';
        diffProgressBar.style.width = '90%';
        
        const diffRes = await fetch(`${API_BASE}/api/diff`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ baseline_id: baselineId, active_id: activeId })
        });
        
        if (!diffRes.ok) {
            const err = await diffRes.json();
            throw new Error(err.detail || 'فشلت مقارنة الجلستين.');
        }
        
        const diffData = await diffRes.json();
        
        diffProgress.style.display = 'none';
        diffResults.style.display = 'block';
        
        document.getElementById('diffBaselineName').innerText = diffData.baseline_name;
        document.getElementById('diffActiveName').innerText = diffData.active_name;
        
        const delta = diffData.security_score_delta;
        const deltaEl = document.getElementById('diffScoreDelta');
        if (delta > 0) {
            deltaEl.innerHTML = `<span style="color:#ef4444"><i class="fa-solid fa-arrow-down"></i> -${delta} نقطة</span>`;
        } else if (delta < 0) {
            deltaEl.innerHTML = `<span style="color:#10b981"><i class="fa-solid fa-arrow-up"></i> +${Math.abs(delta)} نقطة</span>`;
        } else {
            deltaEl.innerHTML = `<span style="color:#94a3b8">0 (لا يوجد تغير)</span>`;
        }
        
        document.getElementById('diffNewHostsCount').innerText = diffData.new_hosts.length;
        document.getElementById('diffNewAlertsCount').innerText = diffData.new_alerts.length;
        
        const hostsBody = document.getElementById('diffNewHostsBody');
        hostsBody.innerHTML = '';
        if (diffData.new_hosts.length === 0) {
            hostsBody.innerHTML = `<tr><td colspan="5" style="text-align:center; color:#94a3b8; font-size:11px;">لم يتم رصد أي أجهزة جديدة. الأجهزة متطابقة في كلا الملفين.</td></tr>`;
        } else {
            diffData.new_hosts.forEach(h => {
                const tr = document.createElement('tr');
                tr.innerHTML = `
                    <td><strong>${h.ip}</strong></td>
                    <td style="font-family:monospace; font-size:11px;">${h.mac}</td>
                    <td>${h.os_guess}</td>
                    <td>${h.hostname || 'Unknown'}</td>
                    <td>${h.total_bytes.toLocaleString()} B</td>
                `;
                hostsBody.appendChild(tr);
            });
        }
        
        const alertsList = document.getElementById('diffNewAlertsList');
        alertsList.innerHTML = '';
        if (diffData.new_alerts.length === 0) {
            alertsList.innerHTML = `<div class="empty-state" style="padding:10px;"><p style="font-size:11px; color:#10b981;"><i class="fa-solid fa-circle-check"></i> لا توجد أي تهديدات أمنية إضافية في الملف النشط!</p></div>`;
        } else {
            diffData.new_alerts.forEach(a => {
                const alertCard = document.createElement('div');
                alertCard.className = `alert-card ${a.severity || 'critical'}-border`;
                alertCard.style.padding = '8px 12px';
                alertCard.style.background = 'rgba(255, 255, 255, 0.02)';
                alertCard.style.borderRadius = '6px';
                
                alertCard.innerHTML = `
                    <div style="display:flex; justify-content:space-between; font-size:10px; color:#94a3b8; margin-bottom:4px;">
                        <span>تنبيه مضاف حديثاً</span>
                        <span>${a.timestamp || ''}</span>
                    </div>
                    <div style="font-weight:bold; font-size:12px; color:#f8fafc; margin-bottom:3px;">${a.title}</div>
                    <div style="font-size:11px; color:#cbd5e1;">${a.details}</div>
                `;
                alertsList.appendChild(alertCard);
            });
        }
        
    } catch (err) {
        alert('فشلت المقارنة: ' + err.message);
        diffProgress.style.display = 'none';
    } finally {
        compareBtn.disabled = false;
    }
}

// ==========================================
// IT & Network Diagnostics Rendering
// ==========================================
function renderDiagnostics(data) {
    if (!data || !data.network_diagnostics) return;

    const diag = data.network_diagnostics;

    // 1.1 Average TCP Handshake Latency (RTT)
    const rtt = diag.avg_rtt_seconds;
    const rttStr = rtt > 0 ? (rtt >= 1.0 ? rtt.toFixed(3) + ' ثانية' : (rtt * 1000).toFixed(1) + ' ms') : 'N/A (لا توجد مصافحات)';
    document.getElementById('diagAvgRtt').innerText = rttStr;

    // 1.2 Average DNS Resolution Latency (RTT)
    const dnsRtt = diag.avg_dns_rtt_seconds;
    const dnsRttStr = dnsRtt > 0 ? (dnsRtt >= 1.0 ? dnsRtt.toFixed(3) + ' ثانية' : (dnsRtt * 1000).toFixed(1) + ' ms') : 'N/A (لا توجد طلبات)';
    document.getElementById('diagAvgDnsRtt').innerText = dnsRttStr;

    // 1.3 TCP Handshake Success Rate
    const successRate = diag.tcp_success_rate !== undefined ? diag.tcp_success_rate.toFixed(1) + '%' : '100%';
    document.getElementById('diagTcpSuccess').innerText = successRate;

    // 2. Render Timeouts / Unanswered Connection SYNs
    const timeoutsBody = document.getElementById('diagTimeoutsBody');
    timeoutsBody.innerHTML = '';
    if (!diag.connection_timeouts || diag.connection_timeouts.length === 0) {
        timeoutsBody.innerHTML = `<tr><td colspan="4" style="text-align:center; color:#94a3b8; font-size:12px; padding: 15px;">لا توجد أي محاولات اتصال معلقة. صحة الخدمة 100%!</td></tr>`;
    } else {
        diag.connection_timeouts.forEach(t => {
            const tr = document.createElement('tr');
            const cleanTime = t.timestamp ? t.timestamp.split('.')[0].replace('T', ' ') : 'N/A';
            tr.innerHTML = `
                <td>${cleanTime}</td>
                <td><strong>${t.src}</strong></td>
                <td>${t.dst}</td>
                <td><span style="color:#ef4444; font-size:11px;"><i class="fa-solid fa-circle-xmark"></i> ${t.reason}</span></td>
            `;
            timeoutsBody.appendChild(tr);
        });
    }

    // 3. Render ICMP Routing / Path Errors
    const icmpBody = document.getElementById('diagIcmpErrorsBody');
    icmpBody.innerHTML = '';
    if (!diag.icmp_errors || diag.icmp_errors.length === 0) {
        icmpBody.innerHTML = `<tr><td colspan="4" style="text-align:center; color:#94a3b8; font-size:12px; padding: 15px;">لا توجد أخطاء توجيه (ICMP Unreachable) في مسار الشبكة.</td></tr>`;
    } else {
        diag.icmp_errors.forEach(e => {
            const tr = document.createElement('tr');
            tr.innerHTML = `
                <td>${e.timestamp}</td>
                <td><strong>${e.router}</strong></td>
                <td>${e.target}</td>
                <td><span style="color:#f59e0b; font-size:11px;"><i class="fa-solid fa-circle-exclamation"></i> ${e.reason}</span></td>
            `;
            icmpBody.appendChild(tr);
        });
    }

    // 4. Render DNS Resolution Failures
    const dnsBody = document.getElementById('diagDnsFailuresBody');
    dnsBody.innerHTML = '';
    if (!diag.dns_failures || diag.dns_failures.length === 0) {
        dnsBody.innerHTML = `<tr><td colspan="4" style="text-align:center; color:#94a3b8; font-size:12px; padding: 15px;">جميع طلبات النطاقات (DNS) تمت ترجمتها بنجاح.</td></tr>`;
    } else {
        diag.dns_failures.forEach(f => {
            const tr = document.createElement('tr');
            tr.innerHTML = `
                <td>${f.timestamp}</td>
                <td><strong>${f.client}</strong></td>
                <td>${f.query}</td>
                <td><span style="color:#ef4444; font-size:11px;"><i class="fa-solid fa-bug"></i> ${f.status}</span></td>
            `;
            dnsBody.appendChild(tr);
        });
    }

    // 5. Render TCP Zero Window Buffer Full Errors
    const zeroWindowBody = document.getElementById('diagZeroWindowBody');
    zeroWindowBody.innerHTML = '';
    if (!diag.tcp_zero_window_events || diag.tcp_zero_window_events.length === 0) {
        zeroWindowBody.innerHTML = `<tr><td colspan="4" style="text-align:center; color:#94a3b8; font-size:12px; padding: 15px;">ذاكرة الأجهزة المؤقتة سليمة ولم يتم رصد Zero Window.</td></tr>`;
    } else {
        diag.tcp_zero_window_events.forEach(z => {
            const tr = document.createElement('tr');
            const cleanTime = z.timestamp ? z.timestamp.split('.')[0].split(' ')[1] : 'N/A';
            tr.innerHTML = `
                <td>${cleanTime}</td>
                <td><strong>${z.ip}:${z.port}</strong></td>
                <td>${z.target}:${z.target_port}</td>
                <td><span style="color:#f59e0b; font-size:11px;"><i class="fa-solid fa-triangle-exclamation"></i> ${z.reason}</span></td>
            `;
            zeroWindowBody.appendChild(tr);
        });
    }

    // 6. Throughput Chart Rendering
    const ctx = document.getElementById('throughputChart').getContext('2d');
    const timeline = diag.throughput_timeline || [];
    const labels = timeline.map(p => p.time + 's');
    const dataPoints = timeline.map(p => p.bytes);

    if (window.throughputChartInstance) {
        window.throughputChartInstance.destroy();
    }

    window.throughputChartInstance = new Chart(ctx, {
        type: 'line',
        data: {
            labels: labels,
            datasets: [{
                label: 'معدل نقل البيانات (Bytes/sec)',
                data: dataPoints,
                borderColor: '#00f2fe',
                backgroundColor: 'rgba(0, 242, 254, 0.08)',
                borderWidth: 2,
                fill: true,
                tension: 0.3,
                pointRadius: labels.length > 50 ? 0 : 2,
                pointHoverRadius: 5
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    display: false
                },
                tooltip: {
                    mode: 'index',
                    intersect: false
                }
            },
            scales: {
                x: {
                    grid: {
                        color: 'rgba(255, 255, 255, 0.05)'
                    },
                    ticks: {
                        color: '#94a3b8',
                        font: { size: 10 }
                    }
                },
                y: {
                    grid: {
                        color: 'rgba(255, 255, 255, 0.05)'
                    },
                    ticks: {
                        color: '#94a3b8',
                        font: { size: 10 },
                        callback: function(value) {
                            if (value >= 1024 * 1024) return (value / (1024 * 1024)).toFixed(1) + ' MB/s';
                            if (value >= 1024) return (value / 1024).toFixed(1) + ' KB/s';
                            return value + ' B/s';
                        }
                    }
                }
            }
        }
    });

    // 7. Top bandwidth consuming services
    const servicesBody = document.getElementById('diagTopServicesBody');
    servicesBody.innerHTML = '';
    const topServices = diag.top_services || [];
    if (topServices.length === 0) {
        servicesBody.innerHTML = `<tr><td colspan="3" style="text-align:center; color:#94a3b8; font-size:12px; padding: 15px;">لا توجد خدمات نشطة.</td></tr>`;
    } else {
        topServices.forEach(s => {
            const tr = document.createElement('tr');
            let sizeStr = s.bytes + ' B';
            if (s.bytes >= 1024 * 1024) sizeStr = (s.bytes / (1024 * 1024)).toFixed(1) + ' MB';
            else if (s.bytes >= 1024) sizeStr = (s.bytes / 1024).toFixed(1) + ' KB';
            
            tr.innerHTML = `
                <td><strong>${s.port}</strong></td>
                <td>${s.service}</td>
                <td><span style="color:#00f2fe">${sizeStr}</span></td>
            `;
            servicesBody.appendChild(tr);
        });
    }

    // 8. MAC Vendor mapping list
    const macVendorsBody = document.getElementById('diagMacVendorsBody');
    macVendorsBody.innerHTML = '';
    const hostsList = Object.entries(data.hosts || {}).map(([ip, info]) => {
        return {
            ip: ip,
            mac: info.mac || 'N/A',
            vendor: (info.mac_vendors && info.mac_vendors.length > 0) ? info.mac_vendors.join(', ') : 'Generic/Other'
        };
    }).filter(h => h.mac !== 'N/A' && h.mac !== 'Unknown');

    if (hostsList.length === 0) {
        macVendorsBody.innerHTML = `<tr><td colspan="3" style="text-align:center; color:#94a3b8; font-size:12px; padding: 15px;">لم يتم الكشف عن عناوين MAC في الحزم المارة.</td></tr>`;
    } else {
        hostsList.forEach(h => {
            const tr = document.createElement('tr');
            tr.innerHTML = `
                <td><strong>${h.ip}</strong></td>
                <td><code>${h.mac}</code></td>
                <td><span style="color:#a855f7">${h.vendor}</span></td>
            `;
            macVendorsBody.appendChild(tr);
        });
    }
}
