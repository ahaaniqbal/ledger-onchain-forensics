"""Batch triage: investigate several tokens and rank them by risk.

Demo line: "the agent triaged N tokens and flagged the riskiest."

    uv run batch.py                       # runs the built-in candidate shortlist
    uv run batch.py 0xAAA 0xBBB 0xCCC     # your own list
    uv run batch.py --max-steps 12
"""

from __future__ import annotations

import argparse
import asyncio
from datetime import datetime, timezone
from pathlib import Path

from agent import NEBIUS_MODEL, investigate, parse_verdict

# Scouted candidates (see demo_tokens.md). Mix of scam-shaped + a legit control.
DEFAULT_TOKENS = [
    "0x47a16e51bcc89c0015622fe83eb482a4522f6c5c",  # airdrop (legit control)
    "0x53b27466c3fa132f7e81d6399a776c55f21ad480",  # concentration
    "0x483b2942b24681c258bc5b63cd0921e6c5ea997a",  # concentration
    "0x111111f7e9b1fe072ade438f77e1ce861c7ee4e3",  # 1inch Chi (legit control)
]

_ORDER = {"LIKELY RUG": 0, "SUSPICIOUS": 1, "INSUFFICIENT DATA": 2, "LIKELY LEGITIMATE": 3}


async def run_batch(tokens: list[str], model: str, max_steps: int) -> None:
    results: list[dict] = []
    for i, tok in enumerate(tokens, 1):
        print(f"\n\n########## [{i}/{len(tokens)}] {tok} ##########")
        try:
            text = await investigate(tok, model, max_steps)
            v = parse_verdict(text)
        except Exception as exc:  # keep triaging the rest
            v = {"verdict": f"ERROR: {type(exc).__name__}", "risk_score": None}
        results.append({"token": tok, **v})

    # Rank: riskiest first (by verdict class, then score desc).
    results.sort(
        key=lambda r: (
            _ORDER.get(r.get("verdict") or "", 9),
            -(r.get("risk_score") or 0),
        )
    )

    lines = ["", "=" * 70, "  TRIAGE SUMMARY (riskiest first)", "=" * 70,
             f"{'RISK':>4}  {'VERDICT':<20}  TOKEN"]
    for r in results:
        score = r.get("risk_score")
        lines.append(
            f"{(score if score is not None else '?'):>4}  "
            f"{(r.get('verdict') or 'UNKNOWN'):<20}  {r['token']}"
        )
    summary = "\n".join(lines)
    print(summary)

    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    out = Path("reports")
    out.mkdir(exist_ok=True)
    path = out / f"{ts}_triage.md"
    path.write_text(summary + "\n")
    print(f"\n[saved triage -> {path}]")


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("tokens", nargs="*", help="token addresses (default: shortlist)")
    ap.add_argument("--model", default=NEBIUS_MODEL)
    ap.add_argument("--max-steps", type=int, default=12)
    args = ap.parse_args()
    tokens = args.tokens or DEFAULT_TOKENS
    asyncio.run(run_batch(tokens, args.model, args.max_steps))


if __name__ == "__main__":
    main()
