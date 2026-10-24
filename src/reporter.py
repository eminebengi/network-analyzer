# -*- coding: utf-8 -*-
"""
HASTANE AĞ RISK ANALIZ SISTEMI - REPORT GENERATOR
"""

import os
from datetime import datetime

class ReportGenerator:
    def __init__(self, output_dir="reports"):
        self.output_dir = output_dir
        if not os.path.exists(self.output_dir):
            os.makedirs(self.output_dir)

    def generate_txt_report(self, findings, stats):
        filename = f"hastane_ag_risk_raporu_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        filepath = os.path.join(self.output_dir, filename)

        with open(filepath, "w", encoding="utf-8") as f:
            f.write("=" * 70 + "\n")
            f.write("       FIRAT ÜNİVERSİTESİ ARAŞTIRMA HASTANESİ\n")
            f.write("      BİLGİ İŞLEM BİRİMİ - AĞ RISK ANALİZ RAPORU\n")
            f.write("=" * 70 + "\n")
            f.write(f"Rapor Tarihi   : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Taranan Cihaz  : {stats.get('toplam_taranan', 0)}\n")
            f.write(f"Toplam Risk    : {stats.get('toplam_risk', 0)}\n")
            f.write(f"  - Kritik Risk: {stats.get('kritik_count', 0)}\n")
            f.write(f"  - Yüksek Risk: {stats.get('yuksek_count', 0)}\n")
            f.write(f"  - Orta Risk  : {stats.get('orta_count', 0)}\n")
            f.write(f"  - Düşük Risk : {stats.get('dusuk_count', 0)}\n")
            f.write("-" * 70 + "\n\n")

            if not findings:
                f.write("✅ SONUÇ: Ağda herhangi bir güvenlik riski veya zafiyet tespit edilmemiştir.\n")
                f.write("   Taranan cihazların tüm portları kapalı veya güvenli durumda görünmektedir.\n")
                f.write("   Bu durum, mevcut güvenlik politikalarının etkin şekilde uygulandığını göstermektedir.\n\n")
                f.write("   ÖNERİ: Düzenli aralıklarla tarama işlemini tekrarlayarak ağ güvenliğinizi\n")
                f.write("   sürekli izlemeye devam etmeniz önerilir.\n")
            else:
                f.write("TESPİT EDİLEN RİSKLER VE ÇÖZÜM ÖNERİLERİ:\n")
                f.write("-" * 70 + "\n")

                for idx, item in enumerate(findings, 1):
                    # riskTipi veya seviye ikisini de güvenli oku (KeyError engellendi)
                    seviye = item.get("seviye") or item.get("riskTipi") or "Bilinmiyor"
                    ip = item.get("ip", "Bilinmiyor")
                    sw = item.get("sw") or item.get("switch") or "Belirtilmedi"
                    port_num = item.get("acikPort") or item.get("port") or "-"
                    baslik = item.get("ad") or item.get("zafiyet") or "Açık Servis"
                    aciklama = item.get("aciklama", "Açıklama yok")
                    cozum = item.get("cozum", "Öneri bulunmuyor")

                    f.write(f"[{idx}] {ip} (Switch: {sw} | Port: {port_num})\n")
                    f.write(f"    Zafiyet   : {baslik}\n")
                    f.write(f"    Seviye    : {seviye}\n")
                    f.write(f"    Açıklama  : {aciklama}\n")
                    f.write(f"    Çözüm     : {cozum}\n")
                    f.write("-" * 70 + "\n")

            f.write("\n" + "=" * 70 + "\n")
            f.write("Rapor Sonu - Otomatik Oluşturulmuştur.\n")
            f.write("=" * 70 + "\n")

        return filename