#!/usr/bin/env python3
"""
Webhook Server pour Velociraptor AI Integration
===============================================
Reçoit les données de Velociraptor et les analyse avec AI

Installation:
    pip install flask requests google-generativeai

Lancement:
    python webhook_server.py

Author: Help4Info
"""

from flask import Flask, request, jsonify
import os
import json
import requests
from datetime import datetime

app = Flask(__name__)

# ============================================================
# CONFIGURATION
# ============================================================

GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "")
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "")
DEFAULT_PROVIDER = os.getenv("AI_PROVIDER", "gemini")

SLACK_WEBHOOK_URL = os.getenv("SLACK_WEBHOOK_URL", "")
TEAMS_WEBHOOK_URL = os.getenv("TEAMS_WEBHOOK_URL", "")

SEVERITY_THRESHOLD = 7  # Alerte si >= 7

# ============================================================
# AI ANALYSIS FUNCTIONS
# ============================================================

SYSTEM_PROMPT = """Tu es un expert en cybersécurité DFIR. Analyse ces données forensiques collectées par Velociraptor.

Réponds UNIQUEMENT en JSON valide avec ce format exact:
{
    "severity": <nombre 1-10>,
    "summary": "<description courte>",
    "mitre_techniques": ["T1xxx", "T1yyy"],
    "iocs": ["ioc1", "ioc2"],
    "recommendations": ["action1", "action2"],
    "auto_response": "ISOLATE|BLOCK|ALERT|NONE",
    "threat_type": "<type de menace>",
    "confidence": <nombre 0-100>
}

Sois précis et concis."""


def analyze_with_gemini(data: dict) -> dict:
    """Analyse avec Google Gemini Flash 2.0"""
    url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent?key={GEMINI_API_KEY}"

    payload = {
        "contents": [{
            "parts": [{
                "text": f"{SYSTEM_PROMPT}\n\nDonnées à analyser:\n{json.dumps(data, indent=2, default=str)}"
            }]
        }],
        "generationConfig": {
            "temperature": 0.1,
            "maxOutputTokens": 2048
        }
    }

    try:
        response = requests.post(url, json=payload, timeout=30)
        if response.status_code == 200:
            result = response.json()
            text = result["candidates"][0]["content"]["parts"][0]["text"]
            # Parser le JSON
            start = text.find("{")
            end = text.rfind("}") + 1
            if start != -1 and end > start:
                return json.loads(text[start:end])
        return {"error": f"Gemini error: {response.status_code}", "raw": response.text}
    except Exception as e:
        return {"error": str(e)}


def analyze_with_openai(data: dict) -> dict:
    """Analyse avec OpenAI GPT-4"""
    url = "https://api.openai.com/v1/chat/completions"

    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {OPENAI_API_KEY}"
    }

    payload = {
        "model": "gpt-4-turbo-preview",
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": f"Données à analyser:\n{json.dumps(data, indent=2, default=str)}"}
        ],
        "temperature": 0.1,
        "response_format": {"type": "json_object"}
    }

    try:
        response = requests.post(url, headers=headers, json=payload, timeout=60)
        if response.status_code == 200:
            result = response.json()
            return json.loads(result["choices"][0]["message"]["content"])
        return {"error": f"OpenAI error: {response.status_code}"}
    except Exception as e:
        return {"error": str(e)}


# ============================================================
# NOTIFICATION FUNCTIONS
# ============================================================

def send_slack_alert(analysis: dict, source_data: dict):
    """Envoie une alerte Slack"""
    if not SLACK_WEBHOOK_URL:
        return

    severity = analysis.get("severity", 0)
    color = "#ff0000" if severity >= 8 else "#ff9900" if severity >= 6 else "#36a64f"

    payload = {
        "attachments": [{
            "color": color,
            "title": f"🚨 Velociraptor Alert - Severity {severity}/10",
            "fields": [
                {"title": "Summary", "value": analysis.get("summary", "N/A"), "short": False},
                {"title": "MITRE Techniques", "value": ", ".join(analysis.get("mitre_techniques", [])), "short": True},
                {"title": "Threat Type", "value": analysis.get("threat_type", "Unknown"), "short": True},
                {"title": "Auto Response", "value": analysis.get("auto_response", "NONE"), "short": True},
                {"title": "Confidence", "value": f"{analysis.get('confidence', 0)}%", "short": True},
                {"title": "IOCs", "value": "\n".join(analysis.get("iocs", [])[:5]), "short": False},
                {"title": "Recommendations", "value": "\n".join(analysis.get("recommendations", [])[:3]), "short": False}
            ],
            "footer": "Velociraptor AI-DFIR",
            "ts": int(datetime.now().timestamp())
        }]
    }

    requests.post(SLACK_WEBHOOK_URL, json=payload)


def send_teams_alert(analysis: dict, source_data: dict):
    """Envoie une alerte Microsoft Teams"""
    if not TEAMS_WEBHOOK_URL:
        return

    severity = analysis.get("severity", 0)
    color = "ff0000" if severity >= 8 else "ff9900" if severity >= 6 else "36a64f"

    payload = {
        "@type": "MessageCard",
        "@context": "http://schema.org/extensions",
        "themeColor": color,
        "summary": f"Velociraptor Alert - Severity {severity}",
        "sections": [{
            "activityTitle": f"🚨 Security Alert - Severity {severity}/10",
            "facts": [
                {"name": "Summary", "value": analysis.get("summary", "N/A")},
                {"name": "MITRE Techniques", "value": ", ".join(analysis.get("mitre_techniques", []))},
                {"name": "Threat Type", "value": analysis.get("threat_type", "Unknown")},
                {"name": "Auto Response", "value": analysis.get("auto_response", "NONE")},
                {"name": "IOCs", "value": ", ".join(analysis.get("iocs", [])[:5])}
            ],
            "markdown": True
        }]
    }

    requests.post(TEAMS_WEBHOOK_URL, json=payload)


# ============================================================
# AUTO RESPONSE
# ============================================================

def execute_auto_response(analysis: dict, client_id: str = None):
    """Exécute la réponse automatique"""
    action = analysis.get("auto_response", "NONE")
    severity = analysis.get("severity", 0)

    if severity < SEVERITY_THRESHOLD:
        return {"action": "NONE", "reason": "Below severity threshold"}

    response_log = {
        "timestamp": datetime.now().isoformat(),
        "action": action,
        "client_id": client_id,
        "severity": severity
    }

    if action == "ISOLATE":
        # TODO: Appeler l'API Velociraptor pour isoler le client
        response_log["status"] = "ISOLATION_REQUESTED"

    elif action == "BLOCK":
        # TODO: Envoyer les IOCs au firewall/EDR
        response_log["status"] = "BLOCK_REQUESTED"
        response_log["iocs_blocked"] = analysis.get("iocs", [])

    elif action == "ALERT":
        send_slack_alert(analysis, {})
        send_teams_alert(analysis, {})
        response_log["status"] = "ALERT_SENT"

    else:
        response_log["status"] = "NO_ACTION"

    return response_log


# ============================================================
# API ENDPOINTS
# ============================================================

@app.route("/health", methods=["GET"])
def health_check():
    """Health check endpoint"""
    return jsonify({"status": "healthy", "timestamp": datetime.now().isoformat()})


@app.route("/analyze", methods=["POST"])
def analyze_endpoint():
    """Endpoint principal pour l'analyse AI"""
    data = request.json

    if not data:
        return jsonify({"error": "No data provided"}), 400

    provider = data.get("provider", DEFAULT_PROVIDER)
    client_id = data.get("client_id")
    artifact_data = data.get("data", data)

    # Analyse AI
    if provider == "gemini":
        analysis = analyze_with_gemini(artifact_data)
    elif provider == "openai":
        analysis = analyze_with_openai(artifact_data)
    else:
        return jsonify({"error": f"Unknown provider: {provider}"}), 400

    # Ajouter métadonnées
    analysis["analyzed_at"] = datetime.now().isoformat()
    analysis["provider"] = provider

    # Auto-response si sévérité élevée
    if analysis.get("severity", 0) >= SEVERITY_THRESHOLD:
        auto_response = execute_auto_response(analysis, client_id)
        analysis["auto_response_result"] = auto_response

        # Notifications
        send_slack_alert(analysis, artifact_data)
        send_teams_alert(analysis, artifact_data)

    return jsonify(analysis)


@app.route("/webhook/velociraptor", methods=["POST"])
def velociraptor_webhook():
    """Webhook pour recevoir les événements Velociraptor"""
    data = request.json

    print(f"[WEBHOOK] Received data from Velociraptor")
    print(json.dumps(data, indent=2, default=str)[:500])

    # Analyser automatiquement
    analysis = analyze_with_gemini(data) if GEMINI_API_KEY else {"error": "No API key"}

    return jsonify({
        "received": True,
        "analysis": analysis
    })


@app.route("/report", methods=["POST"])
def generate_report():
    """Génère un rapport d'analyse"""
    data = request.json
    analyses = data.get("analyses", [])

    report = {
        "generated_at": datetime.now().isoformat(),
        "total_events": len(analyses),
        "critical": len([a for a in analyses if a.get("severity", 0) >= 9]),
        "high": len([a for a in analyses if 7 <= a.get("severity", 0) < 9]),
        "medium": len([a for a in analyses if 4 <= a.get("severity", 0) < 7]),
        "low": len([a for a in analyses if a.get("severity", 0) < 4]),
        "mitre_techniques": list(set(
            t for a in analyses for t in a.get("mitre_techniques", [])
        )),
        "all_iocs": list(set(
            ioc for a in analyses for ioc in a.get("iocs", [])
        )),
        "analyses": analyses
    }

    return jsonify(report)


# ============================================================
# MAIN
# ============================================================

if __name__ == "__main__":
    print("="*60)
    print("Velociraptor AI-DFIR Webhook Server")
    print("="*60)
    print(f"AI Provider: {DEFAULT_PROVIDER}")
    print(f"Gemini API Key: {'✓' if GEMINI_API_KEY else '✗'}")
    print(f"OpenAI API Key: {'✓' if OPENAI_API_KEY else '✗'}")
    print(f"Slack Webhook: {'✓' if SLACK_WEBHOOK_URL else '✗'}")
    print(f"Teams Webhook: {'✓' if TEAMS_WEBHOOK_URL else '✗'}")
    print(f"Severity Threshold: {SEVERITY_THRESHOLD}")
    print("="*60)

    app.run(host="0.0.0.0", port=5000, debug=True)
