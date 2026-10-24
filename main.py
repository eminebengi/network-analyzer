# -*- coding: utf-8 -*-
"""
HASTANE AĞ GÜVENLİĞİ VE RİSK ANALİZ SİSTEMİ - MAIN
Tüm modülleri (Scanner, Analyzer, Reporter) entegre bir şekilde çalıştıran ana sistem.
"""

import time
from src.scanner import NetworkScanner
from src.analyzer import RiskAnalyzer
from src.reporter import ReportGenerator

def main():
    print("=" * 60)
    print(" HASTANE AĞ GÜVENLİĞİ VE RİSK ANALİZ SİSTEMİ BAŞLATILIYOR...")
    print("=" * 60)
    time.sleep(1)

    # 1. Modüllerin Başlatılması
    scanner = NetworkScanner()
    analyzer = RiskAnalyzer()
    reporter = ReportGenerator()

    # 2. Ağ Taramasının Başlatılması (Scanner)
    print("\n[*] Ağ taraması başlatılıyor...")
    scanned_devices = scanner.scan_network()
    print(f"[+] Tarama tamamlandı! Toplam {len(scanned_devices)} cihaz tespit edildi.")

    # 3. Risk Analizinin Yapılması (Analyzer)
    print("[*] Zafiyet kütüphanesi ile risk analizi gerçekleştiriliyor...")
    findings, stats = analyzer.analyze_all(scanned_devices)

    # 4. Rapor Oluşturulması (Reporter)
    print("[*] Rapor oluşturuluyor...")
    rapor_yolu = reporter.generate_txt_report(findings, stats)

    # 5. Konsol Özet Çıktısı
    print("\n" + "=" * 60)
    print(" TARAMA VE ANALİZ TAMAMLANDI!")
    print("=" * 60)
    print(f"Toplam Taranan Cihaz : {stats['toplam_taranan']}")
    print(f"Tespit Edilen Risk   : {stats['toplam_risk']}")
    print(f"  --> Kritik Risk    : {stats['kritik_count']}")
    print(f"  --> Yüksek Risk    : {stats['yuksek_count']}")
    print(f"  --> Orta Risk      : {stats['orta_count']}")
    print(f"  --> Düşük Risk     : {stats['dusuk_count']}")

    if stats['toplam_risk'] == 0:
        print("\n  ✅ Taranan cihazlarda herhangi bir güvenlik riski tespit edilmemiştir.")
        print("     Tüm portlar kapalı veya güvenli durumda görünmektedir.")

    print("-" * 60)
    print(f"Detaylı metin raporu '{rapor_yolu}' dosyasına kaydedildi.")
    print("=" * 60 + "\n")

if __name__ == "__main__":
    main()