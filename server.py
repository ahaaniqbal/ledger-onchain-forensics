"""FastAPI backend for the on-chain forensics UI.

Serves the designed frontend and streams a live investigation over SSE.

    cd detector
    uv run uvicorn server:app --port 8000
    # then open http://localhost:8000
"""

from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path

from dotenv import load_dotenv
from fastapi import FastAPI
from fastapi.responses import HTMLResponse, StreamingResponse

from agent import NEBIUS_MODEL, investigate, parse_verdict
from craft import Craft
from labels import label_address
from prompts import CONNECTION

load_dotenv()

app = FastAPI(title="On-Chain Forensics")
WEB = Path(__file__).parent / "web"


_OVERVIEW_CACHE: dict | None = None


@app.get("/api/overview")
async def api_overview() -> dict:
    """Command-center: chain-wide threat stats + a ranked board of flagged tokens.

    Cached after first build (the board query aggregates 18M transfers).
    """
    global _OVERVIEW_CACHE
    if _OVERVIEW_CACHE is not None:
        return _OVERVIEW_CACHE

    board_sql = """
    SELECT tt."token_address" AS token,
      COUNT(*) AS transfers,
      COUNT(DISTINCT tt."to_address") AS holders,
      ROUND((MAX(tt."block_timestamp")-MIN(tt."block_timestamp"))/(1000000.0*86400),2) AS lifespan,
      ROUND(MAX(TRY_TO_DOUBLE(tt."value"))/NULLIF(SUM(TRY_TO_DOUBLE(tt."value")),0)*100,1) AS concentration
    FROM "CRYPTO"."CRYPTO_ETHEREUM"."TOKEN_TRANSFERS" tt
    JOIN "CRYPTO"."CRYPTO_ETHEREUM"."CONTRACTS" c
      ON tt."token_address"=c."address" AND c."is_erc20"=TRUE
    GROUP BY tt."token_address"
    HAVING COUNT(*) >= 200
      AND ROUND(MAX(TRY_TO_DOUBLE(tt."value"))/NULLIF(SUM(TRY_TO_DOUBLE(tt."value")),0)*100,1) > 70
      AND (MAX(tt."block_timestamp")-MIN(tt."block_timestamp"))/(1000000.0*86400) < 3
    ORDER BY concentration DESC, transfers DESC
    LIMIT 12
    """
    async with Craft() as craft:
        res = await craft.execute_query(CONNECTION, board_sql, max_rows=20)
    cols = [c.lower() for c in (res.get("columns") or [])]
    idx = {c: i for i, c in enumerate(cols)}
    board = []
    for r in res.get("rows") or []:
        conc = float(r[idx["concentration"]] or 0)
        life = float(r[idx["lifespan"]] or 0)
        holders = int(r[idx["holders"]] or 0)
        # deterministic threat score from the visible signals
        score = min(98, round(conc * 0.9 + (12 if life < 1 else 6 if life < 2 else 0)
                              + (6 if holders < 25 else 0)))
        addr = r[idx["token"]]
        board.append(
            {
                "token": addr,
                "short": addr[:6] + "…" + addr[-4:],
                "transfers": int(r[idx["transfers"]] or 0),
                "holders": holders,
                "lifespan": life,
                "concentration": conc,
                "score": score,
            }
        )

    _OVERVIEW_CACHE = {
        "stats": {
            "transactions": 24881700,
            "contracts": 20793354,
            "tokens": 65639,
            "flagged": None,  # filled by a lightweight count if available
        },
        "board": board,
    }
    return _OVERVIEW_CACHE


@app.get("/api/siblings")
async def api_siblings(token: str) -> dict:
    """Clone-family / serial-deployer detection: other ERC-20s with IDENTICAL
    bytecode, with each sibling's transfer/holder/lifespan stats. Pure CRAFT.

    A cluster of identical-bytecode tokens (esp. deployed together) is strong
    evidence of a scam factory — one actor mass-producing rugs.
    """
    tok = token.strip().lower()
    sql = f"""
    WITH fam AS (
      SELECT c2."address" AS addr, c2."block_timestamp" AS ts
      FROM "CRYPTO"."CRYPTO_ETHEREUM"."CONTRACTS" c1
      JOIN "CRYPTO"."CRYPTO_ETHEREUM"."CONTRACTS" c2 ON c1."bytecode" = c2."bytecode"
      WHERE LOWER(c1."address") = '{tok}' AND c2."is_erc20" = TRUE
    )
    SELECT LOWER(fam.addr) AS token,
      TO_VARCHAR(TO_TIMESTAMP(fam.ts/1000000),'YYYY-MM-DD') AS deployed,
      COUNT(t."token_address") AS transfers,
      COUNT(DISTINCT t."to_address") AS holders,
      ROUND((MAX(t."block_timestamp")-MIN(t."block_timestamp"))/(1000000.0*86400),2) AS lifespan_days
    FROM fam
    LEFT JOIN "CRYPTO"."CRYPTO_ETHEREUM"."TOKEN_TRANSFERS" t
      ON LOWER(t."token_address") = LOWER(fam.addr)
    GROUP BY fam.addr, fam.ts
    ORDER BY deployed
    """
    async with Craft() as craft:
        res = await craft.execute_query(CONNECTION, sql, max_rows=200)
    cols = [c.lower() for c in (res.get("columns") or [])]
    rows = res.get("rows") or []
    idx = {c: i for i, c in enumerate(cols)}
    fam = []
    days = set()
    for r in rows:
        addr = r[idx["token"]]
        dep = r[idx["deployed"]]
        days.add(dep)
        fam.append(
            {
                "token": addr,
                "short": addr[:6] + "…" + addr[-4:],
                "deployed": dep,
                "transfers": r[idx["transfers"]],
                "holders": r[idx["holders"]],
                "lifespan_days": r[idx["lifespan_days"]],
                "is_target": addr == tok,
            }
        )
    return {
        "token": tok,
        "family_size": len(fam),
        "same_day": len(days) == 1 and len(fam) > 1,
        "deploy_days": sorted(days),
        "siblings": fam,
    }


@app.get("/api/graph")
async def api_graph(token: str, limit: int = 60) -> dict:
    """Token transfer network: nodes (addresses, role-labelled) + edges (transfers).

    Pure CRAFT query, no LLM — the honest "trail we can see" for one token, with
    known mixer/exchange/DEX/mint counterparties flagged.
    """
    tok = token.strip().lower()
    sql = f"""
    SELECT LOWER("from_address") AS src, LOWER("to_address") AS dst,
           COUNT(*) AS n, SUM(TRY_TO_DOUBLE("value")) AS val
    FROM "CRYPTO"."CRYPTO_ETHEREUM"."TOKEN_TRANSFERS"
    WHERE LOWER("token_address") = '{tok}'
    GROUP BY src, dst
    ORDER BY val DESC NULLS LAST
    LIMIT {int(limit)}
    """
    async with Craft() as craft:
        res = await craft.execute_query(CONNECTION, sql, max_rows=limit)
    cols = res.get("columns") or []
    rows = res.get("rows") or []
    idx = {c.lower(): i for i, c in enumerate(cols)}

    def g(row, key):
        i = idx.get(key)
        return row[i] if i is not None and i < len(row) else None

    nodes: dict[str, dict] = {}
    edges: list[dict] = []
    for row in rows:
        s, d = g(row, "src"), g(row, "dst")
        val = float(g(row, "val") or 0)
        n = int(g(row, "n") or 0)
        if not s or not d:
            continue
        edges.append({"s": s, "t": d, "val": val, "n": n})
        for a in (s, d):
            nodes.setdefault(a, {"id": a, "in": 0.0, "out": 0.0, "deg": 0})
        nodes[s]["out"] += val
        nodes[d]["in"] += val
        nodes[s]["deg"] += 1
        nodes[d]["deg"] += 1

    top_receiver = max(nodes.values(), key=lambda x: x["in"], default=None)
    flags: list[dict] = []
    out_nodes = []
    for a, nd in nodes.items():
        known = label_address(a)
        kind = "wallet"
        label = None
        if known:
            kind, label = known
            flags.append({"address": a, "kind": kind, "label": label})
        elif top_receiver and a == top_receiver["id"] and nd["in"] > 0:
            kind, label = "whale", "Top holder (concentration)"
        out_nodes.append(
            {
                "id": a,
                "short": a[:6] + "…" + a[-4:],
                "kind": kind,
                "label": label,
                "in": nd["in"],
                "out": nd["out"],
                "deg": nd["deg"],
            }
        )
    return {"token": tok, "nodes": out_nodes, "edges": edges, "flags": flags}


@app.get("/")
async def index() -> HTMLResponse:
    return HTMLResponse((WEB / "index.html").read_text())


@app.get("/api/investigate")
async def api_investigate(token: str, max_steps: int = 12) -> StreamingResponse:
    q: asyncio.Queue = asyncio.Queue()

    def emit(line: str) -> None:
        try:
            q.put_nowait({"type": "log", "line": line})
        except Exception:
            pass

    async def run() -> None:
        try:
            result = await investigate(token, NEBIUS_MODEL, max_steps, emit=emit)
            v = parse_verdict(result)
            q.put_nowait(
                {
                    "type": "verdict",
                    "text": result,
                    "verdict": v.get("verdict"),
                    "score": v.get("risk_score"),
                }
            )
        except Exception as e:  # surface errors to the UI instead of hanging
            q.put_nowait({"type": "error", "message": f"{type(e).__name__}: {e}"})
        finally:
            q.put_nowait({"type": "done"})

    asyncio.create_task(run())

    async def gen():
        while True:
            evt = await q.get()
            yield f"data: {json.dumps(evt)}\n\n"
            if evt.get("type") == "done":
                break

    return StreamingResponse(
        gen(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )
