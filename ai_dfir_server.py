#!/usr/bin/env python3
"""
=============================================================
VELOCIRAPTOR AI-DFIR SERVER - Version 2.0 avec Console Web
=============================================================
"""

import os
import json
import requests
import logging
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime
from flask import Flask, request, jsonify, render_template_string, redirect, url_for
from typing import Dict, List

# =============================================================
# CONFIGURATION
# =============================================================

class Config:
    HOST = "0.0.0.0"
    PORT = 5000
    DEBUG = True

    # Microsoft Teams
    TEAMS_WEBHOOK_URL = os.getenv("TEAMS_WEBHOOK_URL", "")

    # Email SMTP
    SMTP_SERVER = os.getenv("SMTP_SERVER", "smtp.gmail.com")
    SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
    SMTP_USER = os.getenv("SMTP_USER", "")
    SMTP_PASSWORD = os.getenv("SMTP_PASSWORD", "")
    EMAIL_FROM = os.getenv("EMAIL_FROM", "")
    EMAIL_TO = os.getenv("EMAIL_TO", "").split(",") if os.getenv("EMAIL_TO") else []

    # AI Providers
    GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "")
    OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "")
    CLAUDE_API_KEY = os.getenv("CLAUDE_API_KEY", "")
    AI_PROVIDER = os.getenv("AI_PROVIDER", "gemini")

    # Thresholds
    SEVERITY_ALERT = int(os.getenv("SEVERITY_ALERT", "5"))
    SEVERITY_BLOCK = int(os.getenv("SEVERITY_BLOCK", "7"))
    SEVERITY_ISOLATE = int(os.getenv("SEVERITY_ISOLATE", "9"))

    VELOCIRAPTOR_URL = os.getenv("VELOCIRAPTOR_URL", "https://192.168.1.48:8889")

config = Config()

# =============================================================
# LOGGING
# =============================================================

LOG_FILE = os.path.expanduser("~/velociraptor-dfir-guide/ai_dfir.log")
os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[logging.FileHandler(LOG_FILE), logging.StreamHandler()]
)
logger = logging.getLogger(__name__)

app = Flask(__name__)
alerts_history = []

# =============================================================
# NOTIFICATIONS
# =============================================================

def send_teams_alert(analysis: Dict) -> bool:
    if not config.TEAMS_WEBHOOK_URL:
        return False

    severity = analysis.get("severity", 0)
    theme_color = "FF0000" if severity >= 9 else "FFA500" if severity >= 7 else "FFFF00" if severity >= 5 else "00FF00"

    card = {
        "@type": "MessageCard",
        "@context": "http://schema.org/extensions",
        "themeColor": theme_color,
        "summary": f"Alerte Sécurité - Sévérité {severity}/10",
        "sections": [{
            "activityTitle": "🚨 ALERTE VELOCIRAPTOR AI-DFIR",
            "activitySubtitle": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "facts": [
                {"name": "Sévérité", "value": f"{severity}/10"},
                {"name": "Résumé", "value": analysis.get("summary", "N/A")},
                {"name": "Type", "value": analysis.get("threat_type", "Unknown")},
                {"name": "MITRE", "value": ", ".join(analysis.get("mitre_techniques", []))},
            ]
        }]
    }

    try:
        r = requests.post(config.TEAMS_WEBHOOK_URL, json=card, timeout=10)
        return r.status_code == 200
    except:
        return False


def format_iocs(iocs):
    """Convert IOCs to string format (handles both str and dict)"""
    result = []
    for ioc in iocs:
        if isinstance(ioc, str):
            result.append(ioc)
        elif isinstance(ioc, dict):
            result.append(str(ioc.get("value", ioc.get("ioc_value", json.dumps(ioc)))))
    return result

def send_email_alert(analysis: Dict) -> bool:
    if not all([config.SMTP_USER, config.SMTP_PASSWORD, config.EMAIL_TO]):
        return False

    severity = analysis.get("severity", 0)
    subject = f"[ALERTE] Sévérité {severity}/10 - Velociraptor AI-DFIR"

    iocs_formatted = format_iocs(analysis.get("iocs", []))

    body = f"""
    <h2>🚨 Alerte Velociraptor AI-DFIR</h2>
    <p><b>Sévérité:</b> {severity}/10</p>
    <p><b>Résumé:</b> {analysis.get("summary", "N/A")}</p>
    <p><b>Type:</b> {analysis.get("threat_type", "Unknown")}</p>
    <p><b>MITRE:</b> {", ".join(analysis.get("mitre_techniques", []))}</p>
    <p><b>IOCs:</b> {", ".join(iocs_formatted)}</p>
    """

    try:
        msg = MIMEMultipart()
        msg["Subject"] = subject
        msg["From"] = config.EMAIL_FROM or config.SMTP_USER
        msg["To"] = ", ".join(config.EMAIL_TO)
        msg.attach(MIMEText(body, "html"))

        with smtplib.SMTP(config.SMTP_SERVER, config.SMTP_PORT) as s:
            s.starttls()
            s.login(config.SMTP_USER, config.SMTP_PASSWORD)
            s.sendmail(config.SMTP_USER, config.EMAIL_TO, msg.as_string())
        return True
    except Exception as e:
        logger.error(f"Email error: {e}")
        return False


# =============================================================
# AI ANALYSIS
# =============================================================

SYSTEM_PROMPT = """Expert DFIR. Analyse et réponds en JSON:
{"severity": 1-10, "summary": "...", "mitre_techniques": ["T1xxx"], "iocs": [], "recommendations": [], "auto_response": "ISOLATE|BLOCK|ALERT|NONE", "threat_type": "...", "confidence": 0-100}"""


def analyze_with_ai(data: Dict) -> Dict:
    if config.AI_PROVIDER == "gemini" and config.GEMINI_API_KEY:
        return analyze_gemini(data)
    elif config.AI_PROVIDER == "openai" and config.OPENAI_API_KEY:
        return analyze_openai(data)
    elif config.AI_PROVIDER == "claude" and config.CLAUDE_API_KEY:
        return analyze_claude(data)
    return {"error": "No AI configured", "severity": 5, "summary": "AI non configuré"}


def analyze_gemini(data: Dict) -> Dict:
    try:
        r = requests.post(
            f"https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent?key={config.GEMINI_API_KEY}",
            json={"contents": [{"parts": [{"text": f"{SYSTEM_PROMPT}\n\nData:\n{json.dumps(data)}"}]}]},
            timeout=30
        )
        if r.status_code == 200:
            text = r.json()["candidates"][0]["content"]["parts"][0]["text"]
            start, end = text.find("{"), text.rfind("}") + 1
            if start >= 0:
                return json.loads(text[start:end])
    except Exception as e:
        logger.error(f"Gemini error: {e}")
    return {"error": "Gemini failed", "severity": 5}


def analyze_openai(data: Dict) -> Dict:
    try:
        r = requests.post(
            "https://api.openai.com/v1/chat/completions",
            headers={"Authorization": f"Bearer {config.OPENAI_API_KEY}", "Content-Type": "application/json"},
            json={"model": "gpt-3.5-turbo", "messages": [{"role": "system", "content": SYSTEM_PROMPT}, {"role": "user", "content": json.dumps(data)}]},
            timeout=60
        )
        if r.status_code == 200:
            text = r.json()["choices"][0]["message"]["content"]
            start, end = text.find("{"), text.rfind("}") + 1
            if start >= 0:
                return json.loads(text[start:end])
        else:
            logger.error(f"OpenAI API error: {r.status_code} - {r.text[:200]}")
    except Exception as e:
        logger.error(f"OpenAI error: {e}")
    return {"error": "OpenAI failed", "severity": 5}


def analyze_claude(data: Dict) -> Dict:
    try:
        r = requests.post(
            "https://api.anthropic.com/v1/messages",
            headers={"x-api-key": config.CLAUDE_API_KEY, "anthropic-version": "2024-01-01"},
            json={"model": "claude-3-5-sonnet-20241022", "max_tokens": 2048, "system": SYSTEM_PROMPT, "messages": [{"role": "user", "content": json.dumps(data)}]},
            timeout=60
        )
        if r.status_code == 200:
            text = r.json()["content"][0]["text"]
            start, end = text.find("{"), text.rfind("}") + 1
            if start >= 0:
                return json.loads(text[start:end])
    except Exception as e:
        logger.error(f"Claude error: {e}")
    return {"error": "Claude failed", "severity": 5}


# =============================================================
# WEB PAGES
# =============================================================

MAIN_CSS = """
<style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body { font-family: 'Segoe UI', Arial; background: linear-gradient(135deg, #1a1a2e, #16213e); min-height: 100vh; color: white; }
    .container { max-width: 1200px; margin: 0 auto; padding: 20px; }
    header { text-align: center; padding: 30px; background: rgba(255,255,255,0.05); border-radius: 15px; margin-bottom: 30px; }
    header h1 { font-size: 2em; color: #667eea; }
    .nav { display: flex; justify-content: center; gap: 10px; margin: 20px 0; flex-wrap: wrap; }
    .nav a { background: linear-gradient(135deg, #667eea, #764ba2); color: white; padding: 12px 25px; border-radius: 8px; text-decoration: none; }
    .nav a:hover { opacity: 0.9; }
    .nav a.active { background: #38ef7d; color: #000; }
    .card { background: rgba(255,255,255,0.05); padding: 25px; border-radius: 15px; margin-bottom: 20px; }
    .card h2 { color: #667eea; margin-bottom: 20px; border-bottom: 2px solid #667eea; padding-bottom: 10px; }
    .form-group { margin-bottom: 20px; }
    .form-group label { display: block; margin-bottom: 8px; color: #a0a0a0; }
    .form-group input, .form-group select { width: 100%; padding: 12px; border: 1px solid #333; border-radius: 8px; background: #1a1a2e; color: white; font-size: 14px; }
    .form-group input:focus { border-color: #667eea; outline: none; }
    .form-row { display: grid; grid-template-columns: 1fr 1fr; gap: 20px; }
    .btn { background: linear-gradient(135deg, #667eea, #764ba2); color: white; border: none; padding: 15px 30px; border-radius: 8px; cursor: pointer; font-size: 16px; }
    .btn:hover { opacity: 0.9; }
    .btn-success { background: linear-gradient(135deg, #11998e, #38ef7d); }
    .btn-danger { background: linear-gradient(135deg, #ff416c, #ff4b2b); }
    .status { padding: 8px 15px; border-radius: 20px; display: inline-block; margin: 5px; }
    .status-ok { background: #38ef7d; color: #000; }
    .status-error { background: #ff416c; }
    .alert { padding: 15px; border-radius: 8px; margin: 10px 0; }
    .alert-success { background: rgba(56, 239, 125, 0.2); border: 1px solid #38ef7d; }
    .alert-error { background: rgba(255, 65, 108, 0.2); border: 1px solid #ff416c; }
    .stats { display: grid; grid-template-columns: repeat(4, 1fr); gap: 20px; margin-bottom: 30px; }
    .stat { background: rgba(255,255,255,0.05); padding: 25px; border-radius: 15px; text-align: center; }
    .stat-value { font-size: 2.5em; font-weight: bold; color: #667eea; }
    .stat-label { color: #a0a0a0; }
    table { width: 100%; border-collapse: collapse; }
    th, td { padding: 12px; text-align: left; border-bottom: 1px solid rgba(255,255,255,0.1); }
    th { color: #667eea; }
    footer { text-align: center; padding: 30px; color: #666; }
    footer a { color: #667eea; }
    .password-field { position: relative; }
    .password-field input { padding-right: 50px; }
    .toggle-password { position: absolute; right: 10px; top: 50%; transform: translateY(-50%); background: none; border: none; color: #667eea; cursor: pointer; }
</style>
"""

NAV_HTML = """
<div class="nav">
    <a href="/" class="{dashboard_active}">📊 Dashboard</a>
    <a href="/settings" class="{settings_active}">⚙️ Configuration</a>
    <a href="/test" class="{test_active}">🧪 Tests</a>
    <a href="/logs" class="{logs_active}">📋 Logs</a>
</div>
"""

@app.route("/")
def dashboard():
    stats = {
        "total": len(alerts_history),
        "critical": len([a for a in alerts_history if a.get("severity", 0) >= 9]),
        "high": len([a for a in alerts_history if 7 <= a.get("severity", 0) < 9]),
        "medium": len([a for a in alerts_history if 5 <= a.get("severity", 0) < 7])
    }

    html = f"""
    <!DOCTYPE html>
    <html><head><title>AI-DFIR Dashboard</title>{MAIN_CSS}</head>
    <body>
    <div class="container">
        <header>
            <h1>🦖 Velociraptor AI-DFIR Dashboard</h1>
            <p>Automated Threat Detection & Response</p>
        </header>

        {NAV_HTML.format(dashboard_active="active", settings_active="", test_active="", logs_active="")}

        <div class="stats">
            <div class="stat"><div class="stat-value">{stats['total']}</div><div class="stat-label">Total Alertes</div></div>
            <div class="stat"><div class="stat-value" style="color:#ff416c">{stats['critical']}</div><div class="stat-label">Critiques</div></div>
            <div class="stat"><div class="stat-value" style="color:#ffa500">{stats['high']}</div><div class="stat-label">Hautes</div></div>
            <div class="stat"><div class="stat-value" style="color:#38ef7d">{stats['medium']}</div><div class="stat-label">Moyennes</div></div>
        </div>

        <div class="card">
            <h2>📊 Status Configuration</h2>
            <p>
                <span class="status {'status-ok' if config.TEAMS_WEBHOOK_URL else 'status-error'}">Teams {'✓' if config.TEAMS_WEBHOOK_URL else '✗'}</span>
                <span class="status {'status-ok' if config.SMTP_USER else 'status-error'}">Email {'✓' if config.SMTP_USER else '✗'}</span>
                <span class="status {'status-ok' if config.GEMINI_API_KEY or config.OPENAI_API_KEY or config.CLAUDE_API_KEY else 'status-error'}">AI ({config.AI_PROVIDER}) {'✓' if config.GEMINI_API_KEY or config.OPENAI_API_KEY or config.CLAUDE_API_KEY else '✗'}</span>
            </p>
            <p style="margin-top:15px; color:#a0a0a0">
                Seuils: Alert ≥{config.SEVERITY_ALERT} | Block ≥{config.SEVERITY_BLOCK} | Isolate ≥{config.SEVERITY_ISOLATE}
            </p>
        </div>

        <div class="card">
            <h2>📋 Dernières Alertes</h2>
            <table>
                <tr><th>Date</th><th>Sévérité</th><th>Résumé</th><th>MITRE</th></tr>
                {"".join([f"<tr><td>{a.get('analyzed_at','')[:19]}</td><td>{a.get('severity',0)}/10</td><td>{a.get('summary','N/A')[:50]}</td><td>{', '.join(a.get('mitre_techniques',[]))}</td></tr>" for a in alerts_history[-10:][::-1]]) or "<tr><td colspan='4'>Aucune alerte</td></tr>"}
            </table>
        </div>

        <footer><p>Velociraptor AI-DFIR | <a href="https://github.com/Help4Info/velociraptor-dfir-guide">GitHub</a></p></footer>
    </div>
    </body></html>
    """
    return html


@app.route("/settings", methods=["GET", "POST"])
def settings():
    message = ""
    message_type = ""

    if request.method == "POST":
        # Update configuration
        config.TEAMS_WEBHOOK_URL = request.form.get("teams_webhook", "")
        config.SMTP_SERVER = request.form.get("smtp_server", "smtp.gmail.com")
        config.SMTP_PORT = int(request.form.get("smtp_port", 587))
        config.SMTP_USER = request.form.get("smtp_user", "")
        config.SMTP_PASSWORD = request.form.get("smtp_password", "") or config.SMTP_PASSWORD
        config.EMAIL_FROM = request.form.get("email_from", "")
        config.EMAIL_TO = [e.strip() for e in request.form.get("email_to", "").split(",") if e.strip()]
        config.GEMINI_API_KEY = request.form.get("gemini_key", "") or config.GEMINI_API_KEY
        config.OPENAI_API_KEY = request.form.get("openai_key", "") or config.OPENAI_API_KEY
        config.CLAUDE_API_KEY = request.form.get("claude_key", "") or config.CLAUDE_API_KEY
        config.AI_PROVIDER = request.form.get("ai_provider", "gemini")
        config.SEVERITY_ALERT = int(request.form.get("severity_alert", 5))
        config.SEVERITY_BLOCK = int(request.form.get("severity_block", 7))
        config.SEVERITY_ISOLATE = int(request.form.get("severity_isolate", 9))

        # Save to .env file
        save_config_to_env()

        message = "✓ Configuration sauvegardée avec succès!"
        message_type = "success"
        logger.info("Configuration updated via web interface")

    html = f"""
    <!DOCTYPE html>
    <html><head><title>Configuration - AI-DFIR</title>{MAIN_CSS}</head>
    <body>
    <div class="container">
        <header>
            <h1>⚙️ Configuration</h1>
            <p>Configurer les credentials et paramètres</p>
        </header>

        {NAV_HTML.format(dashboard_active="", settings_active="active", test_active="", logs_active="")}

        {f'<div class="alert alert-{message_type}">{message}</div>' if message else ''}

        <form method="POST">
            <div class="card">
                <h2>📢 Microsoft Teams Webhook</h2>
                <div class="form-group">
                    <label>Webhook URL</label>
                    <input type="text" name="teams_webhook" value="{config.TEAMS_WEBHOOK_URL}" placeholder="https://outlook.office.com/webhook/...">
                </div>
                <p style="color:#a0a0a0; font-size:12px;">
                    Créer: Teams → Canal → Connecteurs → Incoming Webhook
                </p>
            </div>

            <div class="card">
                <h2>📧 Email SMTP</h2>
                <div class="form-row">
                    <div class="form-group">
                        <label>Serveur SMTP</label>
                        <input type="text" name="smtp_server" value="{config.SMTP_SERVER}" placeholder="smtp.gmail.com">
                    </div>
                    <div class="form-group">
                        <label>Port</label>
                        <input type="number" name="smtp_port" value="{config.SMTP_PORT}" placeholder="587">
                    </div>
                </div>
                <div class="form-row">
                    <div class="form-group">
                        <label>Utilisateur SMTP</label>
                        <input type="email" name="smtp_user" value="{config.SMTP_USER}" placeholder="votre@email.com">
                    </div>
                    <div class="form-group password-field">
                        <label>Mot de passe SMTP</label>
                        <input type="password" name="smtp_password" placeholder="{'••••••••' if config.SMTP_PASSWORD else 'App Password'}">
                    </div>
                </div>
                <div class="form-row">
                    <div class="form-group">
                        <label>Email From</label>
                        <input type="email" name="email_from" value="{config.EMAIL_FROM}" placeholder="alerts@example.com">
                    </div>
                    <div class="form-group">
                        <label>Email To (séparés par virgule)</label>
                        <input type="text" name="email_to" value="{','.join(config.EMAIL_TO)}" placeholder="admin@example.com,soc@example.com">
                    </div>
                </div>
            </div>

            <div class="card">
                <h2>🤖 Intelligence Artificielle</h2>
                <div class="form-group">
                    <label>Provider AI</label>
                    <select name="ai_provider">
                        <option value="gemini" {'selected' if config.AI_PROVIDER == 'gemini' else ''}>Google Gemini (Recommandé - Gratuit)</option>
                        <option value="openai" {'selected' if config.AI_PROVIDER == 'openai' else ''}>OpenAI GPT-4</option>
                        <option value="claude" {'selected' if config.AI_PROVIDER == 'claude' else ''}>Anthropic Claude</option>
                    </select>
                </div>
                <div class="form-group">
                    <label>Gemini API Key <a href="https://aistudio.google.com/app/apikey" target="_blank" style="color:#667eea">(Obtenir)</a></label>
                    <input type="password" name="gemini_key" placeholder="{'••••••••' if config.GEMINI_API_KEY else 'AIza...'}">
                </div>
                <div class="form-group">
                    <label>OpenAI API Key <a href="https://platform.openai.com/api-keys" target="_blank" style="color:#667eea">(Obtenir)</a></label>
                    <input type="password" name="openai_key" placeholder="{'••••••••' if config.OPENAI_API_KEY else 'sk-...'}">
                </div>
                <div class="form-group">
                    <label>Claude API Key <a href="https://console.anthropic.com/" target="_blank" style="color:#667eea">(Obtenir)</a></label>
                    <input type="password" name="claude_key" placeholder="{'••••••••' if config.CLAUDE_API_KEY else 'sk-ant-...'}">
                </div>
            </div>

            <div class="card">
                <h2>🎚️ Seuils de Sévérité</h2>
                <div class="form-row">
                    <div class="form-group">
                        <label>Seuil Alerte (Teams/Email)</label>
                        <input type="number" name="severity_alert" value="{config.SEVERITY_ALERT}" min="1" max="10">
                    </div>
                    <div class="form-group">
                        <label>Seuil Block IOCs</label>
                        <input type="number" name="severity_block" value="{config.SEVERITY_BLOCK}" min="1" max="10">
                    </div>
                </div>
                <div class="form-group">
                    <label>Seuil Isolation</label>
                    <input type="number" name="severity_isolate" value="{config.SEVERITY_ISOLATE}" min="1" max="10">
                </div>
            </div>

            <button type="submit" class="btn btn-success" style="width:100%">💾 Sauvegarder la Configuration</button>
        </form>

        <footer><p>Velociraptor AI-DFIR | <a href="https://github.com/Help4Info/velociraptor-dfir-guide">GitHub</a></p></footer>
    </div>
    </body></html>
    """
    return html


@app.route("/test")
def test_page():
    html = f"""
    <!DOCTYPE html>
    <html><head><title>Tests - AI-DFIR</title>{MAIN_CSS}</head>
    <body>
    <div class="container">
        <header>
            <h1>🧪 Tests</h1>
            <p>Tester les différentes intégrations</p>
        </header>

        {NAV_HTML.format(dashboard_active="", settings_active="", test_active="active", logs_active="")}

        <div class="card">
            <h2>🧪 Tests Disponibles</h2>
            <p style="margin-bottom:20px">Cliquez sur un bouton pour tester l'intégration:</p>

            <div style="display:grid; grid-template-columns: repeat(3, 1fr); gap:15px;">
                <a href="/test/analysis" class="btn">🤖 Test Analyse AI</a>
                <a href="/test/teams" class="btn">📢 Test Teams</a>
                <a href="/test/email" class="btn">📧 Test Email</a>
            </div>
        </div>

        <div class="card">
            <h2>📊 Status Actuel</h2>
            <table>
                <tr><td>Microsoft Teams</td><td><span class="status {'status-ok' if config.TEAMS_WEBHOOK_URL else 'status-error'}">{'Configuré' if config.TEAMS_WEBHOOK_URL else 'Non configuré'}</span></td></tr>
                <tr><td>Email SMTP</td><td><span class="status {'status-ok' if config.SMTP_USER else 'status-error'}">{'Configuré' if config.SMTP_USER else 'Non configuré'}</span></td></tr>
                <tr><td>Gemini API</td><td><span class="status {'status-ok' if config.GEMINI_API_KEY else 'status-error'}">{'Configuré' if config.GEMINI_API_KEY else 'Non configuré'}</span></td></tr>
                <tr><td>OpenAI API</td><td><span class="status {'status-ok' if config.OPENAI_API_KEY else 'status-error'}">{'Configuré' if config.OPENAI_API_KEY else 'Non configuré'}</span></td></tr>
                <tr><td>Claude API</td><td><span class="status {'status-ok' if config.CLAUDE_API_KEY else 'status-error'}">{'Configuré' if config.CLAUDE_API_KEY else 'Non configuré'}</span></td></tr>
            </table>
        </div>

        <footer><p>Velociraptor AI-DFIR | <a href="https://github.com/Help4Info/velociraptor-dfir-guide">GitHub</a></p></footer>
    </div>
    </body></html>
    """
    return html


@app.route("/logs")
def logs_page():
    try:
        with open(LOG_FILE, 'r') as f:
            logs = f.readlines()[-100:]
    except:
        logs = ["No logs available"]

    html = f"""
    <!DOCTYPE html>
    <html><head><title>Logs - AI-DFIR</title>{MAIN_CSS}
    <style>.log-box {{ background: #0d0d0d; padding: 20px; border-radius: 8px; font-family: monospace; font-size: 12px; max-height: 600px; overflow-y: auto; }}</style>
    </head>
    <body>
    <div class="container">
        <header>
            <h1>📋 Logs</h1>
            <p>Journal d'activité du serveur</p>
        </header>

        {NAV_HTML.format(dashboard_active="", settings_active="", test_active="", logs_active="active")}

        <div class="card">
            <h2>📋 Derniers Logs</h2>
            <div class="log-box">
                {"".join([f"<div style='margin:5px 0; color:#a0a0a0'>{log.strip()}</div>" for log in logs[::-1]])}
            </div>
        </div>

        <footer><p>Velociraptor AI-DFIR | <a href="https://github.com/Help4Info/velociraptor-dfir-guide">GitHub</a></p></footer>
    </div>
    </body></html>
    """
    return html


# =============================================================
# API ENDPOINTS
# =============================================================

@app.route("/health")
def health():
    return jsonify({"status": "healthy", "timestamp": datetime.now().isoformat()})


@app.route("/test/analysis")
def test_analysis():
    test_data = {"events": [{"command": "Set-MpPreference -DisableRealtimeMonitoring $true"}]}
    analysis = analyze_with_ai(test_data)
    analysis["analyzed_at"] = datetime.now().isoformat()
    analysis["test"] = True

    if analysis.get("severity", 0) >= config.SEVERITY_ALERT:
        analysis["teams_sent"] = send_teams_alert(analysis)
        analysis["email_sent"] = send_email_alert(analysis)

    alerts_history.append(analysis)
    return jsonify({"test": "analysis", "result": analysis})


@app.route("/test/teams")
def test_teams():
    test = {"severity": 8, "summary": "TEST Teams Webhook", "mitre_techniques": ["T1059"], "iocs": [], "recommendations": [], "auto_response": "ALERT", "threat_type": "Test", "confidence": 100}
    success = send_teams_alert(test)
    return jsonify({"test": "teams", "success": success, "configured": bool(config.TEAMS_WEBHOOK_URL)})


@app.route("/test/email")
def test_email():
    test = {"severity": 7, "summary": "TEST Email", "mitre_techniques": ["T1059"], "iocs": [], "recommendations": [], "auto_response": "ALERT", "threat_type": "Test", "confidence": 100}
    success = send_email_alert(test)
    return jsonify({"test": "email", "success": success, "configured": bool(config.SMTP_USER)})


@app.route("/analyze", methods=["POST"])
def analyze():
    data = request.json
    if not data:
        return jsonify({"error": "No data"}), 400

    analysis = analyze_with_ai(data.get("data", data))
    analysis["analyzed_at"] = datetime.now().isoformat()

    if analysis.get("severity", 0) >= config.SEVERITY_ALERT:
        send_teams_alert(analysis)
        send_email_alert(analysis)

    alerts_history.append(analysis)
    return jsonify(analysis)


@app.route("/webhook/velociraptor", methods=["POST"])
def webhook():
    data = request.json
    logger.info(f"Webhook: {str(data)[:200]}")

    analysis = analyze_with_ai(data)
    analysis["analyzed_at"] = datetime.now().isoformat()

    if analysis.get("severity", 0) >= config.SEVERITY_ALERT:
        send_teams_alert(analysis)
        send_email_alert(analysis)

    alerts_history.append(analysis)
    return jsonify({"received": True, "analysis": analysis})


@app.route("/config", methods=["GET"])
def get_config():
    return jsonify({
        "teams": bool(config.TEAMS_WEBHOOK_URL),
        "email": bool(config.SMTP_USER),
        "ai_provider": config.AI_PROVIDER,
        "gemini": bool(config.GEMINI_API_KEY),
        "openai": bool(config.OPENAI_API_KEY),
        "claude": bool(config.CLAUDE_API_KEY)
    })


def save_config_to_env():
    """Sauvegarde la configuration dans le fichier .env"""
    env_content = f"""# AI-DFIR Configuration - Auto-generated
TEAMS_WEBHOOK_URL={config.TEAMS_WEBHOOK_URL}
SMTP_SERVER={config.SMTP_SERVER}
SMTP_PORT={config.SMTP_PORT}
SMTP_USER={config.SMTP_USER}
SMTP_PASSWORD={config.SMTP_PASSWORD}
EMAIL_FROM={config.EMAIL_FROM}
EMAIL_TO={','.join(config.EMAIL_TO)}
AI_PROVIDER={config.AI_PROVIDER}
GEMINI_API_KEY={config.GEMINI_API_KEY}
OPENAI_API_KEY={config.OPENAI_API_KEY}
CLAUDE_API_KEY={config.CLAUDE_API_KEY}
SEVERITY_ALERT={config.SEVERITY_ALERT}
SEVERITY_BLOCK={config.SEVERITY_BLOCK}
SEVERITY_ISOLATE={config.SEVERITY_ISOLATE}
"""
    env_file = os.path.expanduser("~/velociraptor-dfir-guide/.env")
    with open(env_file, 'w') as f:
        f.write(env_content)


if __name__ == "__main__":
    print("=" * 50)
    print("  VELOCIRAPTOR AI-DFIR SERVER v2.0")
    print("=" * 50)
    print(f"  Dashboard: http://0.0.0.0:{config.PORT}")
    print(f"  Settings:  http://0.0.0.0:{config.PORT}/settings")
    print("=" * 50)
    app.run(host=config.HOST, port=config.PORT, debug=config.DEBUG)
