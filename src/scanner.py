# -*- coding: utf-8 -*-
"""
HASTANE AĞ RISK ANALIZ SISTEMI - HIBRIT SCANNER ENGINE (MULTITHREADED + LOGGING)
"""

import socket
import nmap
import logging
import os
import subprocess
import re
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor
from src.switch_locator import SwitchLocator

# LOGLAMA AYARLARI (Audit Logging)
LOG_DIR = "logs"
if not os.path.exists(LOG_DIR):
    os.makedirs(LOG_DIR)

logging.basicConfig(
    filename=os.path.join(LOG_DIR, "scan_history.log"),
    level=logging.INFO,
    format="%(asctime)s - [TARAMA LOG] - %(message)s",
    encoding="utf-8"
)

# HTTP tabanlı servisler (banner grabbing için HTTP isteği gönderilecek portlar)
HTTP_PORTS = {80, 443, 8080, 8443, 8888}

class NetworkScanner:
    def __init__(self):
        self.switch_locator = SwitchLocator()
        # Hastane altyapılarında en kritik servis portları
        self.target_ports = {
            21: "FTP",
            22: "SSH",
            23: "Telnet",
            80: "HTTP (Web)",
            104: "DICOM / PACS",
            135: "RPC",
            139: "NetBIOS",
            443: "HTTPS",
            445: "SMB (Dosya Paylaşımı)",
            3389: "RDP (Uzak Masaüstü)",
            8080: "HTTP-Proxy",
            9100: "RAW-Printer"
        }

    def _get_mac_from_arp(self, ip):
        """ARP tablosundan MAC adresini çekmeye çalışır."""
        try:
            result = subprocess.run(
                ["arp", "-a", ip],
                capture_output=True, text=True, timeout=5
            )
            # Windows ARP çıktısından MAC'i bul (xx-xx-xx-xx-xx-xx formatı)
            mac_match = re.search(r'([0-9a-fA-F]{2}[-:][0-9a-fA-F]{2}[-:][0-9a-fA-F]{2}[-:][0-9a-fA-F]{2}[-:][0-9a-fA-F]{2}[-:][0-9a-fA-F]{2})', result.stdout)
            if mac_match:
                return mac_match.group(1).upper().replace('-', ':')
        except Exception:
            pass
        return "Tespit Edilemedi"

    def _check_port(self, target_ip, port, service_name):
        """Tek bir portu tarayan multithread yardımcı fonksiyonu."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1.0)
            result = sock.connect_ex((target_ip, port))
            
            if result == 0:
                banner = ""
                try:
                    # HTTP portları için HTTP isteği, diğerleri için basit recv
                    if port in HTTP_PORTS:
                        sock.send(b'HEAD / HTTP/1.0\r\n\r\n')
                    else:
                        sock.send(b'\r\n')
                    
                    banner_data = sock.recv(1024).decode('utf-8', errors='ignore').strip()
                    if banner_data:
                        banner = banner_data.split('\n')[0][:80]
                except Exception:
                    banner = "Servis Yanıt Verdi"

                sock.close()
                return {
                    "port": port,
                    "service": service_name,
                    "banner": banner or "Servis Aktif"
                }
            sock.close()
        except Exception:
            pass
        return None

    def scan_ip_socket(self, target_ip):
        """
        Multithreaded (Eşzamanlı) Socket Taraması
        """
        logging.info(f"Socket Taraması Başlatıldı: Hedef IP={target_ip}")
        open_services = []

        # 10 farklı thread ile aynı anda portları tara (Çok daha hızlı)
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = [
                executor.submit(self._check_port, target_ip, port, sname)
                for port, sname in self.target_ports.items()
            ]
            for future in futures:
                res = future.result()
                if res:
                    open_services.append(res)

        # Açık port bulunamadığında bilgilendirici mesaj (sahte veri yok)
        if not open_services:
            logging.info(f"Hedef {target_ip} üzerinde açık port bulunamadı. Cihaz güvenli görünüyor.")

        mac_address = self._get_mac_from_arp(target_ip)
        location_data = self.switch_locator.locate_mac(mac_address)
        logging.info(f"Socket Taraması Tamamlandı: {target_ip} - Bulunan Açık Port Sayısı: {len(open_services)}")

        return [{
            "ip": target_ip,
            "mac": mac_address,
            "switch": location_data["switch"],
            "port": location_data["port"],
            "open_services": open_services,
            "scan_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "status": "güvenli" if not open_services else "riskli"
        }]

    def scan_nmap_subnet(self, subnet):
        """
        Nmap Motoru + Fallback Mekanizması
        """
        logging.info(f"Nmap Subnet Taraması Başlatıldı: Subnet={subnet}")
        devices = []
        try:
            nm = nmap.PortScanner()
            # Taramayı hızlandıran özel argümanlar: 
            # -T5 (En hızlı mod), -n (DNS çözümleme yapma), --max-retries 0 (Tekrar deneme), --min-rate 1000 (Hızlı paket yollama)
            nm.scan(hosts=subnet, arguments='-sV -F -T5 -n --max-retries 0 --min-rate 1000')

            for host in nm.all_hosts():
                if nm[host].state() == 'up':
                    open_services = []
                    for proto in nm[host].all_protocols():
                        for port in nm[host][proto].keys():
                            if nm[host][proto][port]['state'] == 'open':
                                sname = nm[host][proto][port].get('name', 'Bilinmiyor')
                                pver = nm[host][proto][port].get('product', '') + " " + nm[host][proto][port].get('version', '')
                                open_services.append({
                                    "port": port,
                                    "service": sname.upper(),
                                    "banner": pver.strip() or "Servis Aktif"
                                })

                    mac_address = self._get_mac_from_arp(host)
                    location_data = self.switch_locator.locate_mac(mac_address)
                    devices.append({
                        "ip": host,
                        "mac": mac_address,
                        "switch": location_data["switch"],
                        "port": location_data["port"],
                        "open_services": open_services,
                        "scan_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                        "status": "güvenli" if not open_services else "riskli"
                    })
        except Exception as e:
            logging.error(f"Nmap Taraması Başarısız ({e}).")
            return devices

        if not devices:
            logging.info(f"Nmap taraması {subnet} üzerinde aktif cihaz bulamadı.")
            return devices

        return devices

    def scan_network(self, subnet=None, custom_ip=None):
        """
        Genel ağ taraması veya özel IP taraması.
        """
        logging.info(f"Genel ağ taraması başlatıldı (scan_network) - Subnet: {subnet}, Custom IP: {custom_ip}")
        if custom_ip:
            return self.scan_ip_socket(custom_ip)
        elif subnet:
            return self.scan_nmap_subnet(subnet)
        else:
            return self.scan_ip_socket("127.0.0.1")