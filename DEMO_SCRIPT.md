# 90-Second Judge Demo Script

## Setup (Before Demo)

```bash
# Terminal 1: Start server
cd honey
export GROQ_API_KEY="your-key"
uvicorn app.main:app --reload
```

---

## Demo Flow (90 seconds)

### Part 1: Introduction (15 sec)

**Say**: "Honey is an AI honeypot that detects scam messages, safely engages scammers to waste their time, and extracts intelligence like UPI IDs and phishing links."

---

### Part 2: Show Scam Detection (20 sec)

**Say**: "When a scam message arrives, we first classify it."

**Run**:
```bash
curl -s -X POST http://127.0.0.1:8000/api/v1/message \
  -H "Content-Type: application/json" \
  -d '{"session_id": "judge-demo", "message": "Congratulations! You won Rs 50 lakh! Send Rs 5000 processing fee to UPI: lottery@okaxis"}' | python -m json.tool
```

**Point out**: 
- `is_scam: true` with high confidence
- The agent reply sounds like a confused person asking questions

---

### Part 3: Simulate Multi-Turn (25 sec)

**Say**: "The scammer responds. Our honeypot continues engaging."

**Run**:
```bash
curl -s -X POST http://127.0.0.1:8000/api/v1/message \
  -H "Content-Type: application/json" \
  -d '{"session_id": "judge-demo", "message": "Yes madam, you must pay processing fee immediately or prize expires. Send to bank account 123456789012345 IFSC SBIN0001234"}' | python -m json.tool
```

**Point out**:
- Agent continues asking questions, delaying
- Never agrees to send money

---

### Part 4: End Session & Extract Intel (20 sec)

**Say**: "When we end the conversation, we extract all scam indicators."

**Run**:
```bash
curl -s -X POST http://127.0.0.1:8000/api/v1/session/judge-demo/end | python -m json.tool
```

**Point out**:
- `extracted_intel` now populated with:
  - UPI ID: `lottery@okaxis`
  - Bank account: `123456789012345`
  - IFSC: `SBIN0001234`

---

### Part 5: Safety Highlight (10 sec)

**Say**: "Key safety features:
- Never sends money
- Never clicks links
- Hard limit of 6 turns
- Extraction uses regex first - no hallucination"

---

## Backup: Benign Message Test

If asked "what about false positives?":

```bash
curl -s -X POST http://127.0.0.1:8000/api/v1/message \
  -H "Content-Type: application/json" \
  -d '{"session_id": "benign-test", "message": "Hey, are we meeting for coffee tomorrow at 4pm?"}' | python -m json.tool
```

**Point out**: `is_scam: false`, no engagement, no intel extraction.

---

## Key Talking Points

1. **Why it matters**: India loses Rs 1.25 lakh crore annually to digital fraud
2. **How it's different**: Active defense - wastes scammer time, extracts intel
3. **Safety first**: Persona never compromises, bounded loops, no hallucination
4. **Actionable output**: UPI IDs and bank accounts can be reported to authorities
