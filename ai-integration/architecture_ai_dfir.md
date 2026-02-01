# Architecture AI-Augmented DFIR avec Velociraptor

## Vue d'ensemble

```
┌─────────────────────────────────────────────────────────────────────────┐
│                        AI-AUGMENTED DFIR PLATFORM                       │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────────────────────┐ │
│  │ Endpoints   │───►│ Velociraptor│───►│  AI Analysis Engine         │ │
│  │ (Windows)   │    │ Server      │    │  - Gemini Flash 2.0         │ │
│  └─────────────┘    └──────┬──────┘    │  - GPT-4 / Claude           │ │
│                            │           │  - Local LLM (Ollama)       │ │
│                            ▼           └──────────────┬──────────────┘ │
│                     ┌──────────────┐                  │                │
│                     │ Event Queue  │                  ▼                │
│                     │ (Webhook)    │          ┌──────────────┐         │
│                     └──────────────┘          │ Auto Response│         │
│                                               │ - Isolate    │         │
│                                               │ - Block      │         │
│                                               │ - Alert      │         │
│                                               └──────────────┘         │
└─────────────────────────────────────────────────────────────────────────┘
```

## Options d'intégration AI

| AI Provider | Avantages | Latence | Coût |
|-------------|-----------|---------|------|
| Gemini Flash 2.0 | Très rapide, bon pour temps réel | ~200ms | Gratuit (limité) |
| GPT-4 Turbo | Puissant, bonne analyse | ~1-2s | Payant |
| Claude 3.5 | Excellent pour sécurité | ~1s | Payant |
| Ollama (Local) | Privé, pas de données externes | Variable | Gratuit |

## Cas d'usage

1. **Triage automatique** - L'AI analyse et priorise les alertes
2. **Explication en langage naturel** - Comprendre les IOCs
3. **Corrélation d'événements** - Relier plusieurs indicateurs
4. **Recommandations de remédiation** - Actions suggérées
5. **Génération de rapports** - Résumés automatiques
6. **Threat Intelligence** - Enrichissement contextuel
