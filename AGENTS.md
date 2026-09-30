# AGENTS.md — vercel-edge-agent-cap-token

**Company:** Vercel
**Domain:** Cloud AI Platform Engineering

## Quick Rules
- **Test command:** `PYTHONPATH=src pytest tests/ -v`
- **Lint:** `ruff check src/ tests/`
- **No drive-by edits** — load the skill first.

## Architecture
- `src/vercel_edge_agent_cap_token/core.py` — Domain logic (Cloud AI Platform Engineering)
- `tests/` — Verified test suite
- `.github/workflows/ci.yml` — Enforced CI pipeline
