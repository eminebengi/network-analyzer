# -*- coding: utf-8 -*-
"""
HASTANE AĞ RISK ANALIZ SISTEMI - FLASK API SERVER
"""

import os
from flask import Flask, jsonify, send_from_directory, request, session
from dotenv import load_dotenv
from src.scanner import NetworkScanner
from src.analyzer import RiskAnalyzer
from src.reporter import ReportGenerator
from src.database import DatabaseManager

load_dotenv() # .env dosyasını yükler

app = Flask(__name__, static_folder="reports", static_url_path="")
app.secret_key = os.environ.get("FLASK_SECRET_KEY") or "default_secret_key"

# Veritabanını Başlat
db = DatabaseManager()

ADMIN_USER = os.environ.get("ADMIN_USER")
ADMIN_PASS = os.environ.get("ADMIN_PASS")

@app.route("/")
def index():
    return send_from_directory("reports", "index.html")

# --- 🔐 OTURUM YÖNETİMİ ---
@app.route("/api/login", methods=["POST"])
def login():
    data = request.get_json(silent=True) or {}
    if data.get("username") == ADMIN_USER and data.get("password") == ADMIN_PASS:
        session["user"] = ADMIN_USER
        return jsonify({"status": "success", "message": "Giriş başarılı!", "user": ADMIN_USER})
    return jsonify({"status": "error", "message": "Hatalı kullanıcı adı veya şifre!"}), 401

@app.route("/api/logout", methods=["POST"])
def logout():
    session.pop("user", None)
    return jsonify({"status": "success", "message": "Çıkış yapıldı."})

@app.route("/api/check-auth", methods=["GET"])
def check_auth():
    if "user" in session:
        return jsonify({"authenticated": True, "user": session["user"]})
    return jsonify({"authenticated": False}), 401

import threading
import uuid

# --- ASENKRON GÖREV (TASK) YÖNETİMİ ---
active_tasks = {}

def background_scan_task(task_id, custom_ip, selected_subnet, user):
    try:
        scanner = NetworkScanner()
        analyzer = RiskAnalyzer()
        reporter = ReportGenerator()

        if custom_ip:
            print(f"🔍 [SOCKET TARAMASI] Hedef Özel IP: {custom_ip}")
            scanned_devices = scanner.scan_ip_socket(custom_ip)
        else:
            print(f"🔍 [NMAP TARAMASI] Hedef Ağ Bloğu: {selected_subnet}")
            scanned_devices = scanner.scan_nmap_subnet(selected_subnet)

        findings, stats = analyzer.analyze_all(scanned_devices)
        rapor_yolu = reporter.generate_txt_report(findings, stats)
        
        target_str = custom_ip if custom_ip else selected_subnet
        db.save_scan_result(target_str, stats, findings)

        active_tasks[task_id] = {
            "status": "completed",
            "subnet": target_str,
            "stats": stats,
            "findings": findings,
            "report_path": rapor_yolu
        }
    except Exception as e:
        print(f"[SERVER HATA]: {e}")
        active_tasks[task_id] = {
            "status": "error",
            "message": str(e)
        }

@app.route("/api/scan", methods=["POST"])
def run_scan():
    if "user" not in session:
        return jsonify({"status": "error", "message": "🔒 Yetkisiz Erişim!"}), 401

    try:
        data = request.get_json(silent=True) or {}
        selected_subnet = data.get("subnet", "").strip()
        custom_ip = data.get("custom_ip", "").strip()

        # Yeni bir görev ID'si oluştur
        task_id = str(uuid.uuid4())
        active_tasks[task_id] = {"status": "running"}

        # Taramayı arka planda başlat
        thread = threading.Thread(target=background_scan_task, args=(task_id, custom_ip, selected_subnet, session["user"]))
        thread.daemon = True
        thread.start()

        return jsonify({
            "status": "success",
            "message": "Tarama arka planda başlatıldı.",
            "task_id": task_id
        })

    except Exception as e:
        print(f"[SERVER HATA]: {e}")
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route("/api/scan-status/<task_id>", methods=["GET"])
def check_scan_status(task_id):
    if "user" not in session:
        return jsonify({"status": "error", "message": "🔒 Yetkisiz Erişim!"}), 401
        
    task_info = active_tasks.get(task_id)
    if not task_info:
        return jsonify({"status": "error", "message": "Görev bulunamadı!"}), 404
        
    return jsonify(task_info)

@app.route("/api/history", methods=["GET"])
def get_history():
    if "user" not in session:
        return jsonify({"status": "error", "message": "🔒 Yetkisiz Erişim!"}), 401
    
    try:
        limit = int(request.args.get('limit', 10))
        history = db.get_recent_scans(limit=limit)
        return jsonify({"status": "success", "history": history})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

if __name__ == "__main__":
    print("\n" + "=" * 60)
    print(" HASTANE AĞ RISK ANALIZ SUNUCUSU (SOCKET + NMAP & ANALIZ)")
    print(" 👉 http://127.0.0.1:5000")
    print("=" * 60 + "\n")
    app.run(debug=True, port=5000)