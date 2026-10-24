# -*- coding: utf-8 -*-
"""
HASTANE AĞ RISK ANALIZ SISTEMI - RISK ANALYZER ENGINE
"""

class RiskAnalyzer:
    def __init__(self):
        self.vulnerability_db = {
            23: {
                "ad": "Şifresiz Telnet Protokolü",
                "seviye": "Kritik Risk",
                "aciklama": "Veriler (kullanıcı adı/şifre) ağ üzerinde düz metin (plain-text) olarak iletilir. Araya girme (MITM) saldırılarına açıktır.",
                "cozum": "Telnet servisini kapatın ve şifreli SSH (Port 22) protokolüne geçin."
            },
            445: {
                "ad": "Windows SMBv1 / Zafiyetli Dosya Paylaşımı",
                "seviye": "Kritik Risk",
                "aciklama": "WannaCry / EternalBlue gibi fidye yazılımlarının (Ransomware) ağda yayılmasına neden olabilecek kritik SMB zafiyeti.",
                "cozum": "SMBv1 protokolünü PowerShell üzerinden devre dışı bırakın ve Port 445'i dış ağa kapatın."
            },
            104: {
                "ad": "PACS / DICOM Tıbbi Görüntüleme Servisi",
                "seviye": "Yüksek Risk",
                "aciklama": "Radyoloji ve MR/BT görüntü transfer servisi yetkisiz erişime açıktır. Patient/Hasta verilerinin sızma riski mevcuttur.",
                "cozum": "PACS sunucusuna sadece yetkili Radyoloji IP'lerinin erişebileceği Access Control List (ACL) tanımlayın."
            },
            3389: {
                "ad": "Açık RDP (Uzak Masaüstü Bağlantısı)",
                "seviye": "Yüksek Risk",
                "aciklama": "Kaba kuvvet (Brute-Force) parolaları kırma saldırılarına açık Uzak Masaüstü portu.",
                "cozum": "RDP erişimini VPN arkasına alın ve Ağ Seviyesinde Kimlik Doğrulamayı (NLA) aktif edin."
            },
            21: {
                "ad": "Güvenliksiz FTP Servisi",
                "seviye": "Orta Risk",
                "aciklama": "FTP bağlantıları şifresizdir, dosya transferleri izlenebilir.",
                "cozum": "SFTP veya FTPS kullanımına geçiş yapın."
            },
            135: {
                "ad": "Açık RPC Servisi",
                "seviye": "Orta Risk",
                "aciklama": "RPC servisi uzaktan prosedür çağrılarına izin verir. Yetkisiz erişime açık olabilir.",
                "cozum": "Gereksizse RPC servisini kapatın veya güvenlik duvarı ile kısıtlayın."
            },
            139: {
                "ad": "NetBIOS Servis Paylaşımı",
                "seviye": "Orta Risk",
                "aciklama": "NetBIOS üzerinden ağ keşfi ve oturum bilgisi sızıntısı riski mevcuttur.",
                "cozum": "NetBIOS servisini kapatın veya yalnızca iç ağla sınırlı tutun."
            },
            80: {
                "ad": "Şifresiz HTTP Web Servisi",
                "seviye": "Düşük Risk",
                "aciklama": "Web arayüzü SSL/TLS sertifikası barındırmıyor (HTTPS değil).",
                "cozum": "SSL sertifikası yükleyerek HTTP trafiğini HTTPS (Port 443) protokolüne yönlendirin."
            },
            8080: {
                "ad": "HTTP Proxy Servisi",
                "seviye": "Düşük Risk",
                "aciklama": "HTTP-Proxy portu dışa açık. Yetkisiz kullanıcılar proxy üzerinden ağ trafiği yönlendirebilir.",
                "cozum": "Proxy erişimini yalnızca yetkili IP adreslerine kısıtlayın."
            },
            9100: {
                "ad": "RAW Yazıcı Portu",
                "seviye": "Düşük Risk",
                "aciklama": "Ağ yazıcısının RAW portu dışa açık. Yetkisiz yazdırma veya bilgi sızıntısı riski.",
                "cozum": "Yazıcı portunu yalnızca iç ağdan erişilebilir şekilde kısıtlayın."
            }
        }

    def analyze_device(self, device):
        """Tek bir cihazı analiz eder. Test uyumluluğu için eklendi."""
        findings = []
        ip = device.get("ip", "Bilinmiyor")
        sw = device.get("switch_id") or device.get("switch", "Belirtilmedi")
        port_info = device.get("switch_port") or device.get("port", "-")

        # open_ports (eski format) veya open_services (yeni format) desteği
        open_ports = device.get("open_ports", [])
        open_services = device.get("open_services", [])

        # Eski format: open_ports listesi (sadece port numaraları)
        if open_ports and not open_services:
            for p_num in open_ports:
                vuln = self.vulnerability_db.get(p_num, {
                    "ad": f"Açık Servis (Port {p_num})",
                    "seviye": "Orta Risk",
                    "aciklama": f"Port {p_num} üzerinde aktif servis tespit edildi. Yetkisiz erişim riski barındırabilir.",
                    "cozum": "Gerekli değilse portu kapatın veya Güvenlik Duvarı (Firewall) ile kısıtlayın."
                })
                findings.append({
                    "ip": ip,
                    "sw": sw,
                    "port": port_info,
                    "acikPort": p_num,
                    "ad": vuln["ad"],
                    "seviye": vuln["seviye"],
                    "aciklama": vuln["aciklama"],
                    "cozum": vuln["cozum"]
                })

        # Yeni format: open_services listesi (port + service + banner)
        for srv in open_services:
            p_num = srv.get("port")
            service_name = srv.get("service")
            banner = srv.get("banner", "")

            vuln = self.vulnerability_db.get(p_num, {
                "ad": f"Açık Servis: {service_name}",
                "seviye": "Orta Risk",
                "aciklama": f"Port {p_num} üzerinde aktif servis tespit edildi ({banner}). Yetkisiz erişim riski barındırabilir.",
                "cozum": "Gerekli değilse portu kapatın veya Güvenlik Duvarı (Firewall) ile kısıtlayın."
            })

            findings.append({
                "ip": ip,
                "sw": sw,
                "port": port_info,
                "acikPort": p_num,
                "ad": vuln["ad"],
                "seviye": vuln["seviye"],
                "aciklama": f"{vuln['aciklama']} [İmza: {banner}]" if banner else vuln["aciklama"],
                "cozum": vuln["cozum"]
            })

        return findings

    def analyze_all(self, scanned_devices):
        """Tüm cihazları analiz eder ve istatistik döndürür."""
        findings = []
        kritik_count = 0
        yuksek_count = 0
        orta_count = 0
        dusuk_count = 0
        toplam_risk = 0

        for dev in scanned_devices:
            device_findings = self.analyze_device(dev)
            for item in device_findings:
                seviye = item["seviye"]
                toplam_risk += 1

                if "Kritik" in seviye:
                    kritik_count += 1
                elif "Yüksek" in seviye:
                    yuksek_count += 1
                elif "Orta" in seviye:
                    orta_count += 1
                elif "Düşük" in seviye:
                    dusuk_count += 1

                findings.append(item)

        stats = {
            "toplam_taranan": len(scanned_devices),
            "toplam_risk": toplam_risk,
            "kritik_count": kritik_count,
            "yuksek_count": yuksek_count,
            "orta_count": orta_count,
            "dusuk_count": dusuk_count
        }

        return findings, stats