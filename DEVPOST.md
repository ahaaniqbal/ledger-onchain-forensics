# Ledger — Autonomous On-Chain Forensics Agent

**Track:** Crypto / Blockchain — wallet & scam-token pattern detection

## Inspiration
Crypto lost **$17B+ to scams and $3.4B to hacks in 2025.** Spotting a rug pull
today takes an analyst hours of manual on-chain digging. We asked: what if an
agent could do the on-chain half of a ZachXBT investigation in minutes — and not
just flag one bad token, but unmask the operator behind a whole ring?

## What it does
**Ledger** is an autonomous on-chain investigator. You give it an Ethereum ERC-20
address and it:

1. **Reasons** through a forensic methodology (a Nebius-hosted LLM).
2. **Writes its own SQL** through Emergence CRAFT and queries **25M real Ethereum
   transactions** (Spider 2.0 dataset) — no hand-written SQL.
3. Measures the scam signals that matter: **holder concentration, deployer
   dominance, lifecycle collapse, wash-trading, and — the key move — a bytecode
   clone-family check** that finds other tokens deployed from identical contract
   code.
4. Returns a **verdict** (RUG / SUSPICIOUS / LEGIT), a **0–100 risk score**,
   evidence, and a **parameterized detection rule a compliance team can ship.**

### The discovery that sets it apart
On our demo token, Ledger didn't just flag a rug — it fingerprinted the bytecode
and found the token is **1 of 3 identical-code ERC-20s all deployed on the same
day (2023-10-19), all dead within a day.** That's a **serial rugger / scam
factory**, surfaced autonomously. Detection → discovery.

## How we built it
- **Brain:** Nebius Token Factory (`nvidia/nemotron-3-super-120b-a12b`, OpenAI-compatible).
- **Hands:** Emergence CRAFT semantic layer over Snowflake, via MCP (OAuth 2.1 + PKCE).
- **Agent loop:** a transparent tool-calling loop (OpenAI SDK) with six CRAFT
  tools, including a purpose-built `craft_clone_check` for the bytecode pivot.
- **UI:** a FastAPI + SSE backend streaming the live investigation into a custom
  "on-chain forensics" frontend — reasoning console, verdict card, a
  **fund-flow graph** (nodes role-labelled; known mixers/exchanges/DEX/mint
  flagged), and a **serial-deployer panel.**

## Rubric fit
- **CRAFT depth:** multi-step, multi-table investigation (CONTRACTS ↔ TOKEN_TRANSFERS),
  bytecode self-join fingerprinting — not one raw query.
- **Insight:** an actionable, non-obvious finding (a scam *ring*) + a shippable rule.
- **Agent architecture:** planning, self-correction, and a token→operator pivot.
- **Story:** every reasoning step streams live; the verdict and the ring are visible.

## Honest limitations (we state these on stage)
- The dataset is a ~1–3% block **sample** ending mid-2024, so we detect *clear*
  cases and lean on sampling-robust, address-level signals — no fake multi-hop
  mixer tracing.
- `TOKEN_TRANSFERS.value` uses per-token decimals, so we use ratios/counts, not
  raw amounts.
- Detection signals are grounded in AML research (FlowScope AAAI'20, DenseFlow WWW'24).

## What's next
A watchlist mode that triages a portfolio and a live pre-transaction risk oracle —
the on-chain immune system crypto is missing.

## Try it
```
cd detector && cp .env.template .env   # add NEBIUS_API_KEY
uv sync
uv run uvicorn server:app --port 8000  # open http://localhost:8000
```
