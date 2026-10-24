# -*- coding: utf-8 -*-
"""
HASTANE AĞ RISK ANALIZ SISTEMI - VERİTABANI YÖNETİMİ
"""

import sqlite3
import os
import json
from datetime import datetime
import logging

DB_PATH = "config/scans.db"

class DatabaseManager:
    def __init__(self):
        # config klasörü yoksa oluştur
        if not os.path.exists("config"):
            os.makedirs("config")
        self._initialize_db()

    def _get_connection(self):
        return sqlite3.connect(DB_PATH, check_same_thread=False)

    def _initialize_db(self):
        """Veritabanı tablolarını oluşturur."""
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                
                # Taramalar tablosu
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS scan_history (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        scan_date TEXT NOT NULL,
                        target_network TEXT NOT NULL,
                        total_scanned INTEGER,
                        total_risk INTEGER,
                        critical_risk INTEGER,
                        high_risk INTEGER,
                        medium_risk INTEGER,
                        low_risk INTEGER,
                        raw_findings TEXT
                    )
                ''')
                conn.commit()
        except Exception as e:
            logging.error(f"Veritabanı başlatılamadı: {e}")

    def save_scan_result(self, target, stats, findings):
        """Tarama sonucunu veritabanına kaydeder."""
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                
                # Findings listesini JSON string olarak kaydet
                findings_json = json.dumps(findings, ensure_ascii=False)
                
                cursor.execute('''
                    INSERT INTO scan_history 
                    (scan_date, target_network, total_scanned, total_risk, critical_risk, high_risk, medium_risk, low_risk, raw_findings)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    current_time,
                    target,
                    stats.get('toplam_taranan', 0),
                    stats.get('toplam_risk', 0),
                    stats.get('kritik_count', 0),
                    stats.get('yuksek_count', 0),
                    stats.get('orta_count', 0),
                    stats.get('dusuk_count', 0),
                    findings_json
                ))
                conn.commit()
                return cursor.lastrowid
        except Exception as e:
            logging.error(f"Tarama sonucu kaydedilemedi: {e}")
            return None

    def get_recent_scans(self, limit=10):
        """Geçmiş taramaları getirir."""
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    SELECT id, scan_date, target_network, total_scanned, total_risk, critical_risk, high_risk, medium_risk, low_risk
                    FROM scan_history
                    ORDER BY id DESC
                    LIMIT ?
                ''', (limit,))
                
                columns = [col[0] for col in cursor.description]
                results = []
                for row in cursor.fetchall():
                    results.append(dict(zip(columns, row)))
                return results
        except Exception as e:
            logging.error(f"Geçmiş taramalar okunamadı: {e}")
            return []
