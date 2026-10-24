/* ==========================================================================
   HASTANE AĞ RISK PANELİ - GİRİŞ, FİLTRE VE ÖZEL IP DESTEKLİ JS
   ========================================================================== */

document.addEventListener('DOMContentLoaded', () => {
    
    function getEl(...possibleIds) {
        for (const id of possibleIds) {
            const el = document.getElementById(id);
            if (el) return el;
        }
        return null;
    }

    // Login Modal & Header Elemanları
    const loginModal = getEl('loginModal');
    const loginUsername = getEl('loginUsername');
    const loginPassword = getEl('loginPassword');
    const btnLoginSubmit = getEl('btnLoginSubmit');
    const loginError = getEl('loginError');
    const btnLogout = getEl('btnLogout');

    // Panel Elemanları
    const btnStartScan = getEl('btn-start', 'btnStartScan', 'btnStart');
    const btnPause = getEl('btn-pause');
    const btnReset = getEl('btn-reset');
    const btnDownloadReport = getEl('btn-download', 'btnDownloadReport');
    const searchInput = getEl('search-input', 'searchInput', 'search-filter');
    const subnetSelect = getEl('subnetSelect', 'subnet-select');
    const customIpInput = getEl('customIpInput');

    const progressBar = getEl('progress-fill', 'progress-bar-fill', 'progressBar') 
                      || document.querySelector('.progress-fill') 
                      || document.querySelector('.progress-bar > div');
                      
    const progressText = getEl('progress-text', 'progressText', 'progress-percentage');
    const scanSpeed = getEl('scan-speed');
    const terminalLogs = getEl('terminal-logs', 'terminalLogs', 'terminal-body', 'terminal-output');
    const statusPulse = getEl('status-pulse', 'statusPulse');
    const statusText = getEl('status-text', 'statusText');

    const statTotalScanned = getEl('stat-total-scanned', 'statTotalScanned', 'stat-scanned');
    const statCriticalRisk = getEl('stat-critical-risk', 'statCriticalRisk', 'stat-critical');
    const statHighRisk = getEl('stat-high-risk', 'statHighRisk', 'stat-high');
    const statMediumRisk = getEl('stat-medium-risk', 'statMediumRisk', 'stat-medium');
    const statLowRisk = getEl('stat-low-risk', 'statLowRisk', 'stat-low');

    const findingsTableBody = getEl('findings-table-body', 'findingsTableBody', 'findings-tbody') || document.querySelector('tbody');

    let currentFindings = [];
    let myChartInstance = null;
    let lastReportPath = null;
    let scanAbortController = null;
    let progressInterval = null;
    let isScanning = false;

    // --- 🔑 GİRİŞ VE OTURUM KONTROLÜ ---

    async function checkAuthStatus() {
        try {
            const res = await fetch('/api/check-auth');
            if (res.ok) {
                if (loginModal) loginModal.style.display = 'none';
                if (btnLogout) btnLogout.style.display = 'block';
            } else {
                if (loginModal) loginModal.style.display = 'flex';
                if (btnLogout) btnLogout.style.display = 'none';
            }
        } catch (e) {
            if (loginModal) loginModal.style.display = 'flex';
        }
    }

    checkAuthStatus();

    async function handleLogin() {
        const user = loginUsername ? loginUsername.value.trim() : '';
        const pass = loginPassword ? loginPassword.value.trim() : '';

        if (!user || !pass) {
            showLoginError("Lütfen kullanıcı adı ve şifre girin!");
            return;
        }

        try {
            const res = await fetch('/api/login', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ username: user, password: pass })
            });

            const data = await res.json();

            if (res.ok && data.status === 'success') {
                if (loginModal) loginModal.style.display = 'none';
                if (btnLogout) btnLogout.style.display = 'block';
                if (loginError) loginError.style.display = 'none';
                addLog(`Giriş Başarılı: Hoş geldiniz, ${data.user}`, 'success');
            } else {
                showLoginError(data.message || "Giriş başarısız!");
            }
        } catch (err) {
            showLoginError("Sunucuya bağlanılamadı!");
        }
    }

    if (btnLoginSubmit) {
        btnLoginSubmit.addEventListener('click', handleLogin);
    }

    // Enter tuşu ile login
    if (loginPassword) {
        loginPassword.addEventListener('keypress', (e) => {
            if (e.key === 'Enter') handleLogin();
        });
    }
    if (loginUsername) {
        loginUsername.addEventListener('keypress', (e) => {
            if (e.key === 'Enter') {
                if (loginPassword) loginPassword.focus();
            }
        });
    }

    if (btnLogout) {
        btnLogout.addEventListener('click', async () => {
            await fetch('/api/logout', { method: 'POST' });
            window.location.reload();
        });
    }

    function showLoginError(msg) {
        if (loginError) {
            loginError.textContent = msg;
            loginError.style.display = 'block';
        }
    }

    // --- 📊 TIKLANABİLİR GRAFİK (INTERACTIVE CHART) ---

    function renderRiskChart(stats) {
        const ctx = document.getElementById('riskChart');
        if (!ctx) return;

        const kritik = stats.kritik_count || 0;
        const yuksek = stats.yuksek_count || 0;
        const orta = stats.orta_count || 0;
        const dusuk = stats.dusuk_count || 0;
        const guvenli = Math.max(0, (stats.toplam_taranan || 0) - (stats.toplam_risk || 0));

        if (myChartInstance) myChartInstance.destroy();

        myChartInstance = new Chart(ctx, {
            type: 'doughnut',
            data: {
                labels: ['Kritik Risk', 'Yüksek Risk', 'Orta Risk', 'Düşük Risk', 'Güvenli Cihazlar'],
                datasets: [{
                    data: [kritik, yuksek, orta, dusuk, guvenli],
                    backgroundColor: ['#ff2a5f', '#ff9900', '#ffd200', '#00e676', '#26c6da'],
                    borderWidth: 2,
                    borderColor: '#1e1e2f'
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: { position: 'bottom', labels: { color: '#ffffff', font: { size: 10 }, padding: 10 } }
                },
                // 🎯 GRAFİK DİLİMİNE TIKLANDIĞINDA TABLO FİLTRELEME
                onClick: (event, activeElements) => {
                    if (activeElements.length > 0) {
                        const index = activeElements[0].index;
                        const selectedLabel = myChartInstance.data.labels[index];
                        
                        addLog(`[FİLTRE]: Grafikten "${selectedLabel}" seçildi.`, 'info');

                        if (selectedLabel === 'Kritik Risk') {
                            filterTableBySeverity('Kritik');
                        } else if (selectedLabel === 'Yüksek Risk') {
                            filterTableBySeverity('Yüksek');
                        } else if (selectedLabel === 'Orta Risk') {
                            filterTableBySeverity('Orta');
                        } else if (selectedLabel === 'Düşük Risk') {
                            filterTableBySeverity('Düşük');
                        } else {
                            renderTable(currentFindings);
                        }
                    }
                }
            }
        });
    }

    function filterTableBySeverity(severityKeyword) {
        const filtered = currentFindings.filter(item => item.seviye.includes(severityKeyword));
        renderTable(filtered);
    }

    function addLog(message, type = 'system') {
        if (!terminalLogs) return;
        const time = new Date().toLocaleTimeString('tr-TR');
        const logLine = document.createElement('div');
        logLine.className = `log-line ${type}`;
        logLine.style.margin = '3px 0';
        logLine.textContent = `[${time}] ${message}`;
        terminalLogs.appendChild(logLine);
        terminalLogs.scrollTop = terminalLogs.scrollHeight;
    }

    function renderTable(data) {
        if (!findingsTableBody) return;
        findingsTableBody.innerHTML = '';

        if (!data || data.length === 0) {
            findingsTableBody.innerHTML = `
                <tr>
                    <td colspan="7">
                        <div class="safe-message">
                            <span class="safe-icon">🛡️</span>
                            <h3>Risk Tespit Edilmedi</h3>
                            <p>Taranan cihazlarda herhangi bir güvenlik zafiyeti bulunamamıştır. 
                               Tüm portlar kapalı veya güvenli durumda görünmektedir. 
                               Düzenli tarama yaparak ağ güvenliğinizi izlemeye devam edin.</p>
                        </div>
                    </td>
                </tr>`;
            return;
        }

        data.forEach(item => {
            const tr = document.createElement('tr');
            let badgeClass = 'badge-medium';
            if (item.seviye.includes('Kritik')) badgeClass = 'badge-critical';
            else if (item.seviye.includes('Yüksek')) badgeClass = 'badge-high';
            else if (item.seviye.includes('Düşük')) badgeClass = 'badge-low';

            tr.innerHTML = `
                <td><strong>${item.ip}</strong></td>
                <td>${item.sw || 'SW-Core'} / ${item.port || 'Port-Auto'}</td>
                <td>Port ${item.acikPort} (${item.ad})</td>
                <td><span class="badge ${badgeClass}">${item.seviye}</span></td>
                <td>${item.ad}</td>
                <td>${item.aciklama}</td>
                <td>${item.cozum || 'Çözüm önerisi bulunmuyor'}</td>
            `;
            findingsTableBody.appendChild(tr);
        });
    }

    // --- 🔄 SIFIRLAMA FONKSİYONU ---
    function resetAll() {
        // Tarama devam ediyorsa durdur
        if (progressInterval) {
            clearInterval(progressInterval);
            progressInterval = null;
        }
        isScanning = false;

        // İstatistikleri sıfırla
        if (statTotalScanned) statTotalScanned.textContent = '0 / 3500';
        if (statCriticalRisk) statCriticalRisk.textContent = '0';
        if (statHighRisk) statHighRisk.textContent = '0';
        if (statMediumRisk) statMediumRisk.textContent = '0';
        if (statLowRisk) statLowRisk.textContent = '0';

        // Progress barı sıfırla
        if (progressBar) progressBar.style.width = '0%';
        if (progressText) progressText.textContent = '0% Tamamlandı';
        if (scanSpeed) scanSpeed.textContent = 'Hız: 0 cihaz/sn';

        // Tabloyu temizle
        currentFindings = [];
        if (findingsTableBody) {
            findingsTableBody.innerHTML = `<tr class="empty-row"><td colspan="7">Henüz bir tarama başlatılmadı veya risk bulunamadı.</td></tr>`;
        }

        // Grafiği temizle
        if (myChartInstance) {
            myChartInstance.destroy();
            myChartInstance = null;
        }

        // Terminal logları temizle
        if (terminalLogs) {
            terminalLogs.innerHTML = '';
            addLog('[SİSTEM] Panel sıfırlandı. Yeni tarama başlatılabilir.', 'system');
        }

        // Butonları varsayılan duruma getir
        if (btnStartScan) btnStartScan.disabled = false;
        if (btnPause) btnPause.disabled = true;
        if (btnDownloadReport) btnDownloadReport.disabled = true;
        if (statusPulse) statusPulse.className = 'pulse-dot';
        if (statusText) statusText.textContent = 'Sistem Hazır';

        lastReportPath = null;
    }

    // --- ⏸️ DURDURMA FONKSİYONU ---
    function pauseScan() {
        if (progressInterval) {
            clearInterval(progressInterval);
            progressInterval = null;
        }
        isScanning = false;

        if (statusPulse) statusPulse.className = 'pulse-dot paused';
        if (statusText) statusText.textContent = 'Tarama Duraklatıldı';
        if (btnPause) btnPause.disabled = true;
        if (btnStartScan) btnStartScan.disabled = false;

        addLog('[DURDURULDU] Tarama kullanıcı tarafından durduruldu.', 'warning');
    }

    // --- 📥 RAPOR İNDİRME ---
    function downloadReport() {
        if (lastReportPath) {
            // reports/ klasöründeki dosyayı indir
            const link = document.createElement('a');
            link.href = `/${lastReportPath}`;
            link.download = lastReportPath;
            link.click();
            addLog(`[İNDİRME] Rapor indiriliyor: ${lastReportPath}`, 'success');
        } else {
            addLog('[HATA] İndirilecek rapor bulunamadı. Önce bir tarama yapın.', 'critical');
        }
    }

    // --- 🚀 TARAMA BAŞLATMA (ÖZEL IP DESTEKLİ) ---

    async function startNetworkScan() {
        if (isScanning) return;

        const selectedSubnet = subnetSelect ? subnetSelect.value.trim() : "";
        const customIp = customIpInput ? customIpInput.value.trim() : "";

        if (!selectedSubnet && !customIp) {
            addLog('[HATA] Lütfen taranacak bir Ağ (Subnet) veya IP adresi girin.', 'critical');
            return;
        }

        isScanning = true;
        if (btnStartScan) btnStartScan.disabled = true;
        if (btnPause) btnPause.disabled = false;
        if (btnDownloadReport) btnDownloadReport.disabled = true;
        if (statusPulse) statusPulse.className = 'pulse-dot running';
        
        if (customIp) {
            if (statusText) statusText.textContent = `Hedef IP: ${customIp} Taranıyor...`;
            addLog(`[ÖZEL HEDEF IP]: ${customIp} analiz ediliyor...`, 'system');
        } else {
            if (statusText) statusText.textContent = `${selectedSubnet} Taranıyor...`;
            addLog(`[HEDEF AĞ SEÇİLDİ]: ${selectedSubnet}`, 'system');
        }

        if (terminalLogs) terminalLogs.innerHTML = '';
        addLog(`Tarama başlatılıyor...`, 'system');
        
        if (progressBar) progressBar.style.width = '0%';
        if (progressText) progressText.textContent = '%0';

        let currentProgress = 0;
        const scanStartTime = Date.now();

        progressInterval = setInterval(() => {
            if (currentProgress < 90) {
                currentProgress += Math.floor(Math.random() * 8) + 4;
                if (currentProgress > 90) currentProgress = 90;
                if (progressBar) progressBar.style.width = `${currentProgress}%`;
                if (progressText) progressText.textContent = `%${currentProgress}`;
                
                // Simüle edilmiş hız göstergesi
                const elapsed = (Date.now() - scanStartTime) / 1000;
                const speed = elapsed > 0 ? Math.round((currentProgress / 100) * 50 / elapsed) : 0;
                if (scanSpeed) scanSpeed.textContent = `Hız: ~${speed} port/sn`;
            }
        }, 150);

        // Spinner göster
        showSpinner('Ağ taranıyor, lütfen bekleyin...');

        try {
            const response = await fetch('/api/scan', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ subnet: selectedSubnet, custom_ip: customIp })
            });

            if (response.status === 401) throw new Error("Oturum açılmamış. Lütfen giriş yapın.");
            if (!response.ok) throw new Error(`Sunucu yanıtı: ${response.status}`);

            const data = await response.json();
            if (data.status === 'success' && data.task_id) {
                // Poll for results
                pollScanStatus(data.task_id, customIp);
            } else {
                throw new Error(data.message || "Bilinmeyen hata");
            }
        } catch (error) {
            clearInterval(progressInterval);
            progressInterval = null;
            if (progressBar) progressBar.style.width = '0%';
            if (progressText) progressText.textContent = 'Hata!';
            addLog(`Hata: ${error.message}`, 'critical');
            hideSpinner();
            isScanning = false;
            if (btnStartScan) btnStartScan.disabled = false;
            if (btnPause) btnPause.disabled = true;
            if (statusPulse) statusPulse.className = 'pulse-dot';
            if (statusText) statusText.textContent = 'Sistem Hazır';
        }
    }

    async function pollScanStatus(taskId, customIp) {
        try {
            const response = await fetch(`/api/scan-status/${taskId}`);
            const data = await response.json();

            if (data.status === 'running') {
                if (isScanning) {
                    setTimeout(() => pollScanStatus(taskId, customIp), 2000);
                }
            } else if (data.status === 'completed') {
                clearInterval(progressInterval);
                progressInterval = null;
                if (progressBar) progressBar.style.width = '100%';
                if (progressText) progressText.textContent = '%100';
                if (scanSpeed) scanSpeed.textContent = 'Tamamlandı ✓';

                currentFindings = data.findings;
                lastReportPath = data.report_path;

                if (statTotalScanned) statTotalScanned.textContent = customIp ? 1 : data.stats.toplam_taranan;
                if (statCriticalRisk) statCriticalRisk.textContent = data.stats.kritik_count;
                if (statHighRisk) statHighRisk.textContent = data.stats.yuksek_count;
                if (statMediumRisk) statMediumRisk.textContent = data.stats.orta_count || 0;
                if (statLowRisk) statLowRisk.textContent = data.stats.dusuk_count || 0;

                renderTable(currentFindings);
                renderRiskChart(data.stats);

                if (data.stats.toplam_risk === 0) {
                    addLog('✅ Tarama tamamlandı. Herhangi bir güvenlik riski tespit edilmedi.', 'success');
                } else {
                    addLog(`Tarama Tamamlandı! ${data.stats.toplam_risk} risk tespit edildi.`, 'success');
                }
                if (btnDownloadReport) btnDownloadReport.disabled = false;
                
                hideSpinner();
                isScanning = false;
                if (btnStartScan) btnStartScan.disabled = false;
                if (btnPause) btnPause.disabled = true;
                if (statusPulse) statusPulse.className = 'pulse-dot';
                if (statusText) statusText.textContent = 'Sistem Hazır';

            } else if (data.status === 'error') {
                throw new Error(data.message);
            }
        } catch (error) {
            clearInterval(progressInterval);
            progressInterval = null;
            if (progressBar) progressBar.style.width = '0%';
            if (progressText) progressText.textContent = 'Hata!';
            addLog(`Hata: ${error.message}`, 'critical');
            hideSpinner();
            isScanning = false;
            if (btnStartScan) btnStartScan.disabled = false;
            if (btnPause) btnPause.disabled = true;
            if (statusPulse) statusPulse.className = 'pulse-dot';
            if (statusText) statusText.textContent = 'Sistem Hazır';
        }
    }

    // --- 🌀 SPİNNER FONKSİYONLARI ---
    function showSpinner(message) {
        // Zaten varsa ekleme
        if (document.querySelector('.spinner-overlay')) return;

        const overlay = document.createElement('div');
        overlay.className = 'spinner-overlay';
        overlay.innerHTML = `
            <div class="spinner"></div>
            <span class="spinner-text">${message || 'Yükleniyor...'}</span>
        `;
        document.body.appendChild(overlay);
    }

    function hideSpinner() {
        const overlay = document.querySelector('.spinner-overlay');
        if (overlay) overlay.remove();
    }

    // --- 🎯 EVENT LISTENER'LAR ---
    if (btnStartScan) btnStartScan.addEventListener('click', startNetworkScan);
    if (btnPause) btnPause.addEventListener('click', pauseScan);
    if (btnReset) btnReset.addEventListener('click', resetAll);
    if (btnDownloadReport) btnDownloadReport.addEventListener('click', downloadReport);

    if (searchInput) {
        searchInput.addEventListener('input', (e) => {
            const query = e.target.value.toLowerCase().trim();
            if (!query) {
                renderTable(currentFindings);
                return;
            }
            const filtered = currentFindings.filter(item => 
                (item.ip || '').toLowerCase().includes(query) ||
                (item.ad || '').toLowerCase().includes(query) ||
                (item.aciklama || '').toLowerCase().includes(query) ||
                (item.seviye || '').toLowerCase().includes(query) ||
                (item.cozum || '').toLowerCase().includes(query) ||
                String(item.acikPort || '').includes(query)
            );
            renderTable(filtered);
        });
    }

    // --- 📋 GEÇMİŞ TARAMALAR ---
    const btnLoadHistory = getEl('btn-load-history');
    const historyTbody = getEl('history-tbody');

    async function loadHistory() {
        if (!historyTbody) return;
        historyTbody.innerHTML = '<tr><td colspan="9" style="text-align:center;color:var(--color-teal);">Yükleniyor...</td></tr>';

        try {
            const res = await fetch('/api/history?limit=10');
            if (!res.ok) throw new Error('Geçmiş yüklenemedi.');
            const data = await res.json();

            if (!data.history || data.history.length === 0) {
                historyTbody.innerHTML = '<tr class="empty-row"><td colspan="9">Henüz kaydedilmiş tarama bulunmuyor.</td></tr>';
                return;
            }

            historyTbody.innerHTML = '';
            data.history.forEach(row => {
                const tr = document.createElement('tr');
                const riskColor = row.critical_risk > 0 ? 'var(--color-red)' : row.high_risk > 0 ? 'var(--color-orange)' : 'var(--color-green)';
                tr.innerHTML = `
                    <td>${row.id}</td>
                    <td><code style="font-size:0.8rem;color:var(--color-teal);">${row.scan_date}</code></td>
                    <td><strong>${row.target_network}</strong></td>
                    <td>${row.total_scanned}</td>
                    <td style="color:${riskColor};font-weight:600;">${row.total_risk}</td>
                    <td style="color:var(--color-red);">${row.critical_risk}</td>
                    <td style="color:var(--color-orange);">${row.high_risk}</td>
                    <td style="color:var(--color-yellow);">${row.medium_risk}</td>
                    <td style="color:var(--color-green);">${row.low_risk}</td>
                `;
                historyTbody.appendChild(tr);
            });
        } catch (err) {
            historyTbody.innerHTML = `<tr class="empty-row"><td colspan="9">❌ Hata: ${err.message}</td></tr>`;
        }
    }

    if (btnLoadHistory) btnLoadHistory.addEventListener('click', loadHistory);
});