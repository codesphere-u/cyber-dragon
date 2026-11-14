# Getting Started with Cyber Dragon (`v1.1.0`)

Cyber Dragon is an explainable, SSRF-free defensive cybersecurity platform for phishing links, IDN homograph attacks, and East African Mobile Money & USSD social engineering.

## 1. Web Security Workbench & Developer CLI

```bash
cd apps/web
npm install
npm test
npm run benchmark
npm run dev
```

Run the CLI directly:

```bash
node --experimental-strip-types bin/cyber-dragon.mjs scan "URGENT: Dial *21*0772112233# to prevent SIM deactivation"
```

## 2. FastAPI Microservice (`services/threat-api`)

```bash
cd services/threat-api
pytest -q
uvicorn app.main:app --host 127.0.0.1 --port 8000
```
