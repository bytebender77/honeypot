# Honey: AI Scam Detection Honeypot

An agentic AI system that detects scam messages, safely engages scammers using a believable persona, and extracts actionable intelligence. Designed specifically for the India digital fraud context including UPI scams, phishing attacks, and impersonation schemes.

The system operates as a honeypot: it identifies scam messages, responds as a confused but cooperative victim persona to keep scammers engaged, and extracts verifiable indicators (UPI IDs, bank accounts, phishing URLs) from the conversation. It never engages with legitimate users.

---

## System Architecture

```
                    ┌─────────────────────────────────────────────────────────┐
                    │                    API REQUEST                          │
                    │         POST /api/v1/message                            │
                    │         { session_id, message }                         │
                    └─────────────────────────────────────────────────────────┘
                                            │
                                            ▼
                    ┌─────────────────────────────────────────────────────────┐
                    │              ScamClassifierAgent                        │
                    │  • Determines if message is scam or benign              │
                    │  • Temperature=0 for deterministic output               │
                    │  • Fail-safe: treats errors as scam                     │
                    └─────────────────────────────────────────────────────────┘
                                            │
                         ┌──────────────────┴──────────────────┐
                         │                                     │
                         ▼                                     ▼
                    ┌─────────┐                         ┌─────────────┐
                    │ BENIGN  │                         │    SCAM     │
                    │  Stop   │                         │   Engage    │
                    └─────────┘                         └─────────────┘
                                                               │
                                                               ▼
                    ┌─────────────────────────────────────────────────────────┐
                    │            HoneypotEngagementAgent                      │
                    │  • Responds as "Priya" - confused Indian homemaker      │
                    │  • Asks clarifying questions, delays action             │
                    │  • Never sends money, shares data, or clicks links      │
                    └─────────────────────────────────────────────────────────┘
                                            │
                                            ▼
                    ┌─────────────────────────────────────────────────────────┐
                    │              LangGraph Orchestration                    │
                    │  • Tracks conversation state per session                │
                    │  • Hard limit: MAX 6 turns                              │
                    │  • Exits on: turn limit, empty input, completion        │
                    └─────────────────────────────────────────────────────────┘
                                            │
                                            ▼ (on conversation complete)
                    ┌─────────────────────────────────────────────────────────┐
                    │              ScamIntelExtractor                         │
                    │  • Regex-first extraction (UPI, URLs, IFSC, accounts)   │
                    │  • LLM enhancement only for explicitly stated data      │
                    │  • Zero hallucination: no inference, no guessing        │
                    └─────────────────────────────────────────────────────────┘
                                            │
                                            ▼
                    ┌─────────────────────────────────────────────────────────┐
                    │                   API RESPONSE                          │
                    │  { classification, agent_reply, extracted_intel }       │
                    └─────────────────────────────────────────────────────────┘
```

### Components

| Component | Purpose |
|-----------|---------|
| **ScamClassifierAgent** | Gatekeeper that determines if a message is a scam. Uses strict prompting and temperature=0 for deterministic classification. |
| **HoneypotEngagementAgent** | Generates believable responses as a confused victim persona. Designed to keep scammers engaged and encourage them to reveal details. |
| **LangGraph Orchestration** | State machine that manages multi-turn conversations with hard limits. Prevents infinite loops and tracks session state. |
| **ScamIntelExtractor** | Extracts verifiable scam indicators using regex patterns first, with optional LLM enhancement. Never guesses or infers. |

---

## Ethical Safeguards

This system is designed with safety as the primary concern.

### Persona Guarantees

The honeypot persona (Priya) is constrained by explicit rules:

| Guarantee | Implementation |
|-----------|----------------|
| Never sends money | Prompt explicitly forbids agreeing to payments |
| Never shares real personal data | Uses only fictional background details |
| Never clicks links | Responds with confusion, never acknowledges links |
| Never escalates urgency | Always delays with "let me check with my husband" |
| Never reveals AI identity | Prompt strictly forbids disclosure |

### Why This Is Safe

1. **Engages scammers, not victims**: The classifier runs first. Only messages classified as scams trigger honeypot engagement. Benign messages receive no response.

2. **Extraction happens post-conversation**: Intelligence is only extracted after the conversation ends. This prevents mid-conversation data leakage and ensures complete transcripts.

3. **Regex-first prevents hallucination**: The extractor uses deterministic regex patterns as the primary method. LLM is only used for enhancement, and its output is validated against the schema. Any LLM failure falls back to regex-only results.

4. **Bounded loops**: LangGraph enforces a hard limit of 6 turns. No infinite engagement is possible.

5. **Fail-safe defaults**: All agents default to safe behavior on errors. Classification errors are treated as scams (to prevent missed threats). Engagement errors produce neutral responses.

---

## Threat Model

| Threat | Mitigation |
|--------|------------|
| **Prompt injection** | User input is sanitized before LLM calls. System prompts explicitly instruct models to ignore embedded commands. Input is never treated as instructions. |
| **Persona drift** | The honeypot persona is defined in a separate prompt file. No user input can modify the persona mid-conversation. Temperature is controlled (0.4) for consistency. |
| **Infinite loops** | MAX_TURNS=6 is enforced at the orchestration layer. Empty input ends the conversation immediately. |
| **Data exfiltration** | The persona never shares real data. All "personal details" are fictional placeholders defined in the prompt. |
| **Hallucinated intelligence** | Regex-first extraction. LLM output must match schema exactly or is discarded. No inference or guessing allowed. |
| **Accidental scam participation** | Persona explicitly cannot: send money, click links, share OTPs, or confirm actions. All responses express confusion or delay. |

---

## Demo Instructions

### Prerequisites

```bash
# Clone and install
cd honey
pip install -r requirements.txt

# Set API key
export GROQ_API_KEY="your-groq-api-key"
```

### Start the Server

```bash
uvicorn app.main:app --reload
```

Server runs at `http://127.0.0.1:8000`

### Test with a Scam Message

```bash
curl -X POST http://127.0.0.1:8000/api/v1/message \
  -H "Content-Type: application/json" \
  -d '{
    "session_id": "demo-session-1",
    "message": "Congratulations! You won Rs 50 lakh in our lucky draw! Send Rs 5000 to claim your prize. UPI: winner@okaxis"
  }'
```

### Expected Response

```json
{
  "classification": {
    "is_scam": true,
    "confidence": 0.95,
    "reason": "Prize scam with payment request and UPI ID"
  },
  "agent_reply": "Oh really? But why do I need to send money to receive a prize? Can you explain how this works?",
  "extracted_intel": {
    "bank_accounts": [],
    "upi_ids": ["winner@okaxis"],
    "phishing_links": [],
    "other_indicators": []
  }
}
```

### Test with a Benign Message

```bash
curl -X POST http://127.0.0.1:8000/api/v1/message \
  -H "Content-Type: application/json" \
  -d '{
    "session_id": "demo-session-2",
    "message": "Hey, are we still meeting for coffee tomorrow at 4pm?"
  }'
```

### Expected Response

```json
{
  "classification": {
    "is_scam": false,
    "confidence": 0.92,
    "reason": "Normal social message, no scam indicators"
  },
  "agent_reply": null,
  "extracted_intel": null
}
```

### What Judges Should Observe

1. **Scam messages** trigger classification (is_scam: true), engagement (agent_reply), and intelligence extraction (extracted_intel with UPI/URLs found)
2. **Benign messages** are classified correctly (is_scam: false) with no engagement
3. **Honeypot responses** are believable, ask questions, and never commit to action
4. **Extracted intelligence** only contains data that actually appears in the conversation

---

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/v1/message` | Process a message through the pipeline |
| POST | `/api/v1/session/{id}/end` | Force-end a session and trigger extraction |
| GET | `/health` | Health check |
| GET | `/config` | View non-sensitive configuration |

---

## Running Tests

```bash
# Run all tests (some skip without API key)
PYTHONPATH=. pytest tests/ -v

# Run only unit tests (no API key needed)
PYTHONPATH=. pytest tests/test_schemas.py tests/test_extractor.py -v
```

Test coverage:
- 35+ unit tests for schemas, routing, state, and extraction
- Integration tests for full pipeline (require API key)

---

## Limitations and Future Work

### Current Limitations

- **Mock environment**: Tested against simulated scam messages, not live scammer feeds
- **Text-only**: Does not handle voice calls, images, or videos
- **Single language**: Optimized for English with Indian context; no Hindi/regional language support yet
- **In-memory state**: Session state is not persisted across server restarts

### Future Enhancements

- Voice scam detection using speech-to-text
- Multilingual support (Hindi, Tamil, Telugu)
- Real-time integration with telecom/messaging APIs
- Persistent storage for conversation history and extracted intelligence
- Dashboard for visualizing scam patterns and extracted data
- Integration with law enforcement reporting systems

---

## Project Structure

```
honey/
├── app/
│   ├── agents/
│   │   ├── scam_classifier.py    # Scam detection
│   │   ├── honeypot_agent.py     # Victim persona
│   │   └── intel_extractor.py    # Intelligence extraction
│   ├── api/
│   │   ├── routes.py             # HTTP endpoints
│   │   └── schemas.py            # Pydantic models
│   ├── core/
│   │   └── config.py             # Configuration
│   ├── orchestration/
│   │   ├── graph.py              # LangGraph flow
│   │   └── state.py              # Conversation state
│   ├── prompts/
│   │   ├── scam_classifier.md    # Classification prompt
│   │   ├── honeypot_persona.md   # Persona definition
│   │   └── intel_extractor.md    # Extraction prompt
│   └── main.py                   # FastAPI app
├── tests/
│   ├── test_classifier.py
│   ├── test_honeypot.py
│   ├── test_extractor.py
│   ├── test_graph.py
│   └── test_schemas.py
├── requirements.txt
└── README.md
```

---

## License

MIT License
