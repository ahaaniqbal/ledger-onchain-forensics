# Ledger — Autonomous On-Chain Forensics Agent

An AI agent that investigates any Ethereum ERC-20 and decides whether it's a
**scam / rug pull** — then unmasks the operator behind it. Built for the
Emergence × Nebius Enterprise Agents Hackathon (Crypto track).

- **Brain:** Nebius Token Factory (`nvidia/nemotron-3-super-120b-a12b`)
- **Hands:** Emergence CRAFT semantic layer over 25M real Ethereum transactions (via MCP)
- **Surface:** a live-streaming on-chain forensics UI

## What it does

Point it at a token address and the agent autonomously:
1. Reasons through a forensic methodology and **writes its own SQL via CRAFT**.
2. Measures scam signals: holder concentration, deployer dominance, lifecycle
   collapse, wash-trading.
3. Runs a **bytecode clone-family check** (`craft_clone_check`) — finds other
   tokens deployed from *identical* contract code. Several identical-bytecode
   tokens deployed together = a **serial rugger / scam factory**.
4. Returns a **verdict** (RUG / SUSPICIOUS / LEGIT), a **risk score**, evidence,
   and a **parameterized detection rule**.

The UI streams the whole investigation live, then shows the verdict, a
**fund-flow graph** (nodes role-labelled; known mixers / exchanges / DEX / mint
flagged via `labels.py`), and a **serial-deployer panel**.

## Run

```bash
cd detector
cp .env.template .env          # add your NEBIUS_API_KEY
uv sync

# Web UI (the demo surface):
uv run uvicorn server:app --port 8000   # open http://localhost:8000

# Or the CLI:
uv run agent.py 0xTOKENADDRESS          # investigate a token
uv run agent.py --check                 # verify CRAFT wiring
uv run batch.py                         # triage a shortlist of tokens
uv run sql.py "a question"              # manual CRAFT query (dev helper)
```

## Files
| File | Role |
|------|------|
| `agent.py` | Nebius LLM + tool-calling loop + 6 CRAFT tools + investigation log |
| `craft.py` | CRAFT MCP client (OAuth 2.1 + PKCE, persistent session, query helper) |
| `prompts.py` | Investigator system prompt (methodology, units, output format) |
| `labels.py` | Known-address intelligence (mixers, exchanges, DEX routers, mint/burn) |
| `server.py` | FastAPI + SSE backend (`/api/investigate`, `/api/graph`, `/api/siblings`) |
| `web/index.html` | The forensics UI (console + verdict + graph + clone-family panel) |
| `batch.py` · `sql.py` | Triage mode · dev query helper |

## Honest limitations
- The dataset is a ~1–3% block **sample** ending mid-2024, so we detect *clear*
  cases and use sampling-robust, address-level signals — no fabricated multi-hop
  mixer tracing.
- `TOKEN_TRANSFERS.value` is in each token's own (unknown) decimals — we use
  ratios/counts, not raw amounts.
- Detection signals are grounded in AML research (FlowScope AAAI'20, DenseFlow WWW'24).

MIT License.
