# Demo script — Predictive Scam-Token Detector

**The pitch (say this first, 20 sec):**
> "Rug pulls and scam tokens drained billions in 2025. Spotting one today takes an
> analyst hours of manual on-chain digging. We built an autonomous agent — an AI
> ZachXBT — that investigates any Ethereum token in minutes: it reasons, writes its
> own SQL through Emergence CRAFT, digs through 25 million real transactions, and
> returns a verdict plus a detection rule a compliance team can ship. The brain is
> Nebius Token Factory; the hands are CRAFT."

## The 3-minute flow

**1. Show the architecture (15s)** — Nebius (reasoning) → CRAFT (semantic text-to-SQL)
→ 25M-row Ethereum dataset. One hand-written loop, fully visible reasoning.

**2. Cleared case — the agent doesn't cry wolf (45s)**
Replay `reports/…_0x47a16e51.md`.
- Token `0x47a16e51…`: agent finds **1 sender → 5,204 receivers, 1 unit each, one day**.
- Reasons: low concentration (top holder 0.02%), one-time distribution → **airdrop**.
- **VERDICT: LIKELY LEGITIMATE (15/100).** Point: it reasons, it doesn't just flag everything.

**3. Flagged case — the rug (60s)**
Replay `reports/…_0x0008a519.md`.
- Token `0x0008a519…`: agent finds it was **minted 1,000,000,000 units straight to a
  single address**, ~**99.9% concentration**, **4 holders**, dead in **< 1 day**.
- Reasons: extreme insider concentration + no distribution + instant death → rug.
- **VERDICT: LIKELY RUG.** Same agent, opposite call — that's real discrimination.

**4. Triage at scale (30s)**
Show `reports/…_triage.md` — the agent triaged several tokens and ranked them
riskiest-first. "Point it at a watchlist, it surfaces the dangerous ones."

**5. The shippable output (20s)**
Highlight the DETECTION RULE the agent emits, e.g.:
> Flag an ERC-20 if top-1 holder > 20% of transferred supply AND active lifespan
> < 2 days AND unique holders < 50.
"Not just an answer — a rule they deploy tomorrow."

## Why it scores (map to the rubric)
- **CRAFT depth (30%)** — every step routes through generate_sql → execute_query;
  schema exploration, multi-query investigation, not one raw query.
- **Insight quality (30%)** — a concrete, actionable finding (this token is a rug,
  here's the evidence and the rule).
- **Agent architecture (20%)** — multi-step reasoning, self-correction, tool use.
- **Story clarity (20%)** — the visible investigation log shows the agent thinking.

## Honest caveats to volunteer (rigor scores points)
- Data is a ~1–3% block **sample** ending mid-2024 → we detect clear cases; we say so.
- `TOKEN_TRANSFERS.value` uses per-token decimals → we use ratios/counts, not raw amounts.
- Detection features are grounded in AML research (FlowScope, DenseFlow, ICC 2023).

## Run live (backup only — prefer replaying recordings)
```
cd detector
uv run agent.py 0x0008a519b43d1dd0d81e08b4d569c769524e0593   # the rug
uv run agent.py 0x47a16e51bcc89c0015622fe83eb482a4522f6c5c   # the airdrop
uv run batch.py                                               # triage shortlist
```
