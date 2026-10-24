# -*- coding: utf-8 -*-
import os
import sys

# Ana proje klasörünü Python arama yoluna ekler
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import unittest
from src.analyzer import RiskAnalyzer


class TestRiskAnalyzer(unittest.TestCase):

    def setUp(self):
        """Testlerden önce çalışacak hazırlık fonksiyonu."""
        self.analyzer = RiskAnalyzer()

    def test_known_critical_port(self):
        """Port 445 (SMBv1) tespit edildiğinde Kritik risk üretilmeli."""
        mock_device = {
            "ip": "10.100.1.100",
            "switch": "SW-KAT1-1",
            "port": "Port-5",
            "open_services": [
                {"port": 445, "service": "SMB", "banner": "Windows SMBv1 Service"}
            ]
        }
        findings = self.analyzer.analyze_device(mock_device)
        self.assertEqual(len(findings), 1)
        self.assertIn("Kritik", findings[0]["seviye"])
        self.assertIn("SMB", findings[0]["ad"])

    def test_known_high_risk_port(self):
        """Port 3389 (RDP) tespit edildiğinde Yüksek risk üretilmeli."""
        mock_device = {
            "ip": "10.100.2.50",
            "switch": "SW-KAT2-3",
            "port": "Port-10",
            "open_services": [
                {"port": 3389, "service": "RDP", "banner": "Microsoft Terminal Services"}
            ]
        }
        findings = self.analyzer.analyze_device(mock_device)
        self.assertEqual(len(findings), 1)
        self.assertIn("Yüksek", findings[0]["seviye"])

    def test_known_medium_risk_port(self):
        """Port 21 (FTP) tespit edildiğinde Orta risk üretilmeli."""
        mock_device = {
            "ip": "10.100.3.10",
            "switch": "SW-KAT3-1",
            "port": "Port-2",
            "open_services": [
                {"port": 21, "service": "FTP", "banner": "vsftpd 3.0.3"}
            ]
        }
        findings = self.analyzer.analyze_device(mock_device)
        self.assertEqual(len(findings), 1)
        self.assertIn("Orta", findings[0]["seviye"])

    def test_known_low_risk_port(self):
        """Port 80 (HTTP) tespit edildiğinde Düşük risk üretilmeli."""
        mock_device = {
            "ip": "10.100.4.20",
            "switch": "SW-KAT4-1",
            "port": "Port-7",
            "open_services": [
                {"port": 80, "service": "HTTP", "banner": "Apache/2.4.41"}
            ]
        }
        findings = self.analyzer.analyze_device(mock_device)
        self.assertEqual(len(findings), 1)
        self.assertIn("Düşük", findings[0]["seviye"])

    def test_safe_device(self):
        """Açık portu olmayan cihazda risk bulunmamalı."""
        mock_device = {
            "ip": "10.100.1.101",
            "switch": "SW-KAT1-1",
            "port": "Port-6",
            "open_services": []
        }
        findings = self.analyzer.analyze_device(mock_device)
        self.assertEqual(len(findings), 0)

    def test_multiple_open_ports(self):
        """Birden fazla açık portta her biri için ayrı bulgu üretilmeli."""
        mock_device = {
            "ip": "10.100.5.15",
            "switch": "SW-KAT5-2",
            "port": "Port-3",
            "open_services": [
                {"port": 23, "service": "Telnet", "banner": "Telnet Service"},
                {"port": 445, "service": "SMB", "banner": "SMBv1"},
                {"port": 3389, "service": "RDP", "banner": "RDP Service"}
            ]
        }
        findings = self.analyzer.analyze_device(mock_device)
        self.assertEqual(len(findings), 3)

    def test_analyze_all_stats(self):
        """analyze_all() istatistikleri doğru hesaplamalı."""
        mock_devices = [
            {
                "ip": "10.100.1.1",
                "switch": "SW-1",
                "port": "Port-1",
                "open_services": [
                    {"port": 23, "service": "Telnet", "banner": "Telnet"},
                    {"port": 80, "service": "HTTP", "banner": "Apache"}
                ]
            },
            {
                "ip": "10.100.1.2",
                "switch": "SW-1",
                "port": "Port-2",
                "open_services": [
                    {"port": 3389, "service": "RDP", "banner": "RDP"}
                ]
            }
        ]
        findings, stats = self.analyzer.analyze_all(mock_devices)
        self.assertEqual(stats["toplam_taranan"], 2)
        self.assertEqual(stats["toplam_risk"], 3)
        self.assertEqual(stats["kritik_count"], 1)   # Telnet
        self.assertEqual(stats["yuksek_count"], 1)    # RDP
        self.assertEqual(stats["dusuk_count"], 1)     # HTTP
        self.assertIn("orta_count", stats)
        self.assertIn("dusuk_count", stats)

    def test_old_format_open_ports(self):
        """Eski format (open_ports listesi) de desteklenmeli."""
        mock_device = {
            "ip": "10.100.6.1",
            "switch_id": "SW-KAT6-1",
            "switch_port": 5,
            "open_ports": [445]
        }
        findings = self.analyzer.analyze_device(mock_device)
        self.assertEqual(len(findings), 1)
        self.assertIn("Kritik", findings[0]["seviye"])


if __name__ == "__main__":
    unittest.main()