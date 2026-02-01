# AI-Augmented DFIR with Velociraptor

Integration of Large Language Models (LLMs) with Velociraptor for automated threat detection, analysis, and response.

## Features

- **Multi-AI Support**: Gemini Flash 2.0, GPT-4, Claude, Ollama (local)
- **Automated Analysis**: Real-time threat assessment
- **MITRE ATT&CK Mapping**: Automatic technique identification
- **Auto-Response**: Isolate, block, or alert based on severity
- **Notifications**: Slack and Teams integration

## Architecture

```
┌─────────────┐     ┌──────────────┐     ┌─────────────┐
│ Velociraptor│────►│ Webhook      │────►│ AI Engine   │
│ Server      │     │ Server       │     │ (Gemini/GPT)│
└─────────────┘     └──────────────┘     └──────┬──────┘
                                                │
                    ┌──────────────┐            │
                    │ Auto Response│◄───────────┘
                    │ - Isolate    │
                    │ - Block IOCs │
                    │ - Alert SOC  │
                    └──────────────┘
```

## Quick Start

### 1. Install Dependencies

```bash
pip install flask requests google-generativeai openai anthropic
```

### 2. Set Environment Variables

```bash
export GEMINI_API_KEY="your-gemini-api-key"
export OPENAI_API_KEY="your-openai-api-key"
export SLACK_WEBHOOK_URL="https://hooks.slack.com/..."
export TEAMS_WEBHOOK_URL="https://outlook.office.com/webhook/..."
```

### 3. Start Webhook Server

```bash
python webhook_server.py
```

### 4. Configure Velociraptor

Import the custom artifact from `velociraptor_ai_artifact.yaml`:
1. Go to **View Artifacts** > **Add Custom Artifact**
2. Paste the artifact YAML
3. Save and launch

## Files

| File | Description |
|------|-------------|
| `velociraptor_ai_analyzer.py` | Main Python library for AI integration |
| `webhook_server.py` | Flask server for receiving Velociraptor data |
| `velociraptor_ai_artifact.yaml` | Custom Velociraptor artifact for AI analysis |
| `architecture_ai_dfir.md` | Architecture documentation |

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/health` | GET | Health check |
| `/analyze` | POST | Analyze data with AI |
| `/webhook/velociraptor` | POST | Receive Velociraptor events |
| `/report` | POST | Generate consolidated report |

## Example Request

```bash
curl -X POST http://localhost:5000/analyze \
  -H "Content-Type: application/json" \
  -d '{
    "provider": "gemini",
    "client_id": "C.54b3f7d051fbbebd",
    "data": {
      "powershell_command": "Set-MpPreference -DisableRealtimeMonitoring $true",
      "files_found": ["C:\\Temp\\payload.exe"]
    }
  }'
```

## Example Response

```json
{
  "severity": 9,
  "summary": "Windows Defender disabled and suspicious executable found",
  "mitre_techniques": ["T1562.001", "T1105"],
  "iocs": ["C:\\Temp\\payload.exe"],
  "recommendations": [
    "Isolate the endpoint immediately",
    "Analyze payload.exe in sandbox",
    "Check for lateral movement"
  ],
  "auto_response": "ISOLATE",
  "threat_type": "Defense Evasion + Malware Delivery",
  "confidence": 95
}
```

## AI Providers

### Google Gemini Flash 2.0 (Recommended)
- **Speed**: ~200ms response time
- **Cost**: Free tier available
- **Best for**: Real-time analysis

### OpenAI GPT-4
- **Speed**: ~1-2s response time
- **Cost**: Pay-per-use
- **Best for**: Complex analysis

### Ollama (Local)
- **Speed**: Variable (depends on hardware)
- **Cost**: Free (runs locally)
- **Best for**: Air-gapped environments

## Auto-Response Actions

| Action | Trigger | Description |
|--------|---------|-------------|
| ISOLATE | Severity >= 9 | Isolate endpoint from network |
| BLOCK | Severity >= 7 | Block identified IOCs |
| ALERT | Severity >= 5 | Send alert to SOC |
| NONE | Severity < 5 | Log only |

## Customization

### Modify AI Prompt

Edit `SYSTEM_PROMPT` in the analyzer scripts to customize the analysis focus.

### Add Custom Detections

Add new VQL queries in `velociraptor_ai_artifact.yaml` to collect additional artifacts.

### Integrate with SOAR

The webhook server can be extended to integrate with:
- TheHive
- Cortex
- Shuffle SOAR
- Splunk SOAR

## License

MIT License - github.com/Help4Info/velociraptor-dfir-guide
