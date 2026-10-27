# 🐉 Cyber Dragon

**Open-source community cyber defense.** Detect suspicious URLs and scam messages, explain risks, and help people make safer decisions.

> **Status:** early MVP. Heuristic results are advisory, not proof that content is malicious or safe. No external reputation lookups are performed.

## Quick start

Requires Python 3.11+.

```bash
cd services/threat-api
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload
```

Open `http://127.0.0.1:8000/docs` for the interactive API. Run tests with `pytest`.

Example:
```bash
curl -X POST http://127.0.0.1:8000/api/v1/analyze -H 'Content-Type: application/json' -d '{"text":"Congratulations! You won a prize. Send your mobile money PIN to claim."}'
```

## MVP safeguards
- No fetching submitted URLs (avoids SSRF and unexpected disclosure)
- No database, tracking, or storage of submissions
- Request size limits and bounded inputs
- Explainable, deterministic indicators
- No automated public accusations or threat publication

## Roadmap
See [docs/IMPLEMENTATION_PLAN.md](docs/IMPLEMENTATION_PLAN.md).

## Community
See [CONTRIBUTING.md](CONTRIBUTING.md), [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md), and [SECURITY.md](SECURITY.md).

Licensed under Apache-2.0. Contributions welcome.
