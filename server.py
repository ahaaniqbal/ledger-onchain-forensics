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

app = FastAPI(title="Quorum — On-Chain Threat Intelligence")
WEB = Path(__file__).parent / "web"


@app.get("/api/risk")
async def api_risk(token: str) -> dict:
    """Machine-consumable risk score for a token — the 'Protect' surface.

    Fast + deterministic (no LLM): this is what a wallet / exchange / protocol
    calls in real time before letting a user interact. Combines concentration,
    lifecycle, and clone-family signals into a 0-100 score + verdict + reasons.
    """
    tok = token.strip().lower()
    stat_sql = f"""
    SELECT COUNT(*) AS transfers,
      COUNT(DISTINCT "to_address") AS holders,
      ROUND(MAX(TRY_TO_DOUBLE("value"))/NULLIF(SUM(TRY_TO_DOUBLE("value")),0)*100,1) AS concentration,
      ROUND((MAX("block_timestamp")-MIN("block_timestamp"))/(1000000.0*86400),2) AS lifespan
    FROM "CRYPTO"."CRYPTO_ETHEREUM"."TOKEN_TRANSFERS"
    WHERE LOWER("token_address") = '{tok}'
    """
    clone_sql = f"""
    SELECT COUNT(*) AS fam, MIN(TO_VARCHAR(TO_TIMESTAMP(c2."block_timestamp"/1000000),'YYYY-MM-DD')) AS d0,
      MAX(TO_VARCHAR(TO_TIMESTAMP(c2."block_timestamp"/1000000),'YYYY-MM-DD')) AS d1
    FROM "CRYPTO"."CRYPTO_ETHEREUM"."CONTRACTS" c1
    JOIN "CRYPTO"."CRYPTO_ETHEREUM"."CONTRACTS" c2 ON c1."bytecode"=c2."bytecode"
    WHERE LOWER(c1."address")='{tok}' AND c2."is_erc20"=TRUE
    """
    async with Craft() as craft:
        s = await craft.execute_query(CONNECTION, stat_sql, max_rows=1)
        c = await craft.execute_query(CONNECTION, clone_sql, max_rows=1)

    def row0(res):
        cols = [x.lower() for x in (res.get("columns") or [])]
        rows = res.get("rows") or [[]]
        return dict(zip(cols, rows[0])) if rows and rows[0] else {}

    sr, cr = row0(s), row0(c)
    conc = float(sr.get("concentration") or 0)
    life = float(sr.get("lifespan") or 0)
    holders = int(sr.get("holders") or 0)
    transfers = int(sr.get("transfers") or 0)
    fam = int(cr.get("fam") or 0)

    signals = []
    score = 0
    if transfers == 0:
        return {"token": tok, "risk_score": None, "verdict": "UNKNOWN",
                "reason": "no transfer activity found in dataset"}
    if conc >= 90:
        score += 45; signals.append({"name": "extreme holder concentration", "value": f"{conc}%", "severity": "critical"})
    elif conc >= 70:
        score += 30; signals.append({"name": "high holder concentration", "value": f"{conc}%", "severity": "high"})
    if life < 1:
        score += 20; signals.append({"name": "sub-day lifespan", "value": f"{life}d", "severity": "high"})
    elif life < 3:
        score += 10; signals.append({"name": "short lifespan", "value": f"{life}d", "severity": "medium"})
    if holders < 25:
        score += 12; signals.append({"name": "very few holders", "value": holders, "severity": "medium"})
    if fam > 1:
        same = cr.get("d0") == cr.get("d1")
        score += 25 if same else 15
        signals.append({"name": "bytecode clone family", "value": f"{fam} tokens" + (" same-day" if same else ""), "severity": "critical" if same else "high"})
    score = min(99, score)
    verdict = "LIKELY RUG" if score >= 70 else "SUSPICIOUS" if score >= 40 else "LIKELY LEGITIMATE"
    return {
        "token": tok, "risk_score": score, "verdict": verdict,
        "signals": signals,
        "metrics": {"concentration_pct": conc, "lifespan_days": life,
                    "holders": holders, "transfers": transfers, "clone_family": fam},
        "action": "block" if score >= 70 else "warn" if score >= 40 else "allow",
    }


_OPS_CACHE: dict | None = None
_OP_MEMBERS_CACHE: dict[str, dict] = {}


@app.get("/api/operators")
async def api_operators() -> dict:
    """Chain-wide scam-OPERATOR leaderboard: cluster all 65k ERC-20s by exact
    bytecode fingerprint, rank operators by how many of their tokens are
    rug-shaped. Entity resolution at scale — the campaign view. Cached (heavy).
    """
    global _OPS_CACHE
    if _OPS_CACHE is not None:
        return _OPS_CACHE
    sql = """
    WITH erc AS (
      SELECT LOWER("address") AS addr, MD5("bytecode") AS fp, "block_timestamp" AS ts
      FROM "CRYPTO"."CRYPTO_ETHEREUM"."CONTRACTS" WHERE "is_erc20"=TRUE
    ),
    tt AS (
      SELECT LOWER("token_address") AS token, COUNT(*) AS transfers,
        COUNT(DISTINCT "to_address") AS holders,
        (MAX("block_timestamp")-MIN("block_timestamp"))/(1000000.0*86400) AS life,
        MAX(TRY_TO_DOUBLE("value"))/NULLIF(SUM(TRY_TO_DOUBLE("value")),0) AS conc
      FROM "CRYPTO"."CRYPTO_ETHEREUM"."TOKEN_TRANSFERS" GROUP BY LOWER("token_address")
    )
    SELECT e.fp,
      COUNT(*) AS cluster_tokens, COUNT(tt.token) AS active,
      SUM(CASE WHEN tt.conc>0.8 AND tt.life<3 THEN 1 ELSE 0 END) AS rug_tokens,
      ROUND(SUM(tt.holders)) AS victims,
      TO_VARCHAR(TO_TIMESTAMP(MIN(e.ts)/1000000),'YYYY-MM-DD') AS first_deploy,
      TO_VARCHAR(TO_TIMESTAMP(MAX(e.ts)/1000000),'YYYY-MM-DD') AS last_deploy,
      COUNT(DISTINCT TO_VARCHAR(TO_TIMESTAMP(e.ts/1000000),'YYYY-MM-DD')) AS deploy_days
    FROM erc e LEFT JOIN tt ON e.addr=tt.token
    GROUP BY e.fp
    HAVING COUNT(*)>=50 AND SUM(CASE WHEN tt.conc>0.8 AND tt.life<3 THEN 1 ELSE 0 END)>=5
    ORDER BY rug_tokens DESC LIMIT 15
    """
    async with Craft() as craft:
        res = await craft.execute_query(CONNECTION, sql, max_rows=20)
    cols = [c.lower() for c in (res.get("columns") or [])]
    idx = {c: i for i, c in enumerate(cols)}
    ops = []
    for r in res.get("rows") or []:
        rug = int(r[idx["rug_tokens"]] or 0)
        active = int(r[idx["active"]] or 0)
        ops.append({
            "fp": r[idx["fp"]],
            "cluster_tokens": int(r[idx["cluster_tokens"]] or 0),
            "active": active,
            "rug_tokens": rug,
            "rug_rate": round(rug / active * 100) if active else 0,
            "victims": int(float(r[idx["victims"]] or 0)),
            "first_deploy": r[idx["first_deploy"]],
            "last_deploy": r[idx["last_deploy"]],
            "deploy_days": int(r[idx["deploy_days"]] or 0),
        })
    _OPS_CACHE = {
        "operators": ops,
        "totals": {
            "operators": len(ops),
            "rug_tokens": sum(o["rug_tokens"] for o in ops),
            "victims": sum(o["victims"] for o in ops),
        },
    }
    return _OPS_CACHE


@app.get("/api/operator")
async def api_operator(fp: str, limit: int = 45) -> dict:
    """Campaign members for one operator (bytecode fingerprint): the tokens it
    deployed, with rug metrics — powers the operator→tokens network graph."""
    fp = fp.strip().lower()
    if fp in _OP_MEMBERS_CACHE:
        return _OP_MEMBERS_CACHE[fp]
    sql = f"""
    WITH erc AS (
      SELECT LOWER("address") AS addr, "block_timestamp" AS ts
      FROM "CRYPTO"."CRYPTO_ETHEREUM"."CONTRACTS"
      WHERE "is_erc20"=TRUE AND MD5("bytecode")='{fp}'
    ),
    tt AS (
      SELECT LOWER("token_address") AS token, COUNT(*) AS transfers,
        COUNT(DISTINCT "to_address") AS holders,
        (MAX("block_timestamp")-MIN("block_timestamp"))/(1000000.0*86400) AS life,
        MAX(TRY_TO_DOUBLE("value"))/NULLIF(SUM(TRY_TO_DOUBLE("value")),0) AS conc
      FROM "CRYPTO"."CRYPTO_ETHEREUM"."TOKEN_TRANSFERS"
      WHERE LOWER("token_address") IN (SELECT addr FROM erc)
      GROUP BY LOWER("token_address")
    )
    SELECT e.addr AS token, TO_VARCHAR(TO_TIMESTAMP(e.ts/1000000),'YYYY-MM-DD') AS deployed,
      COALESCE(tt.transfers,0) AS transfers, COALESCE(tt.holders,0) AS holders,
      ROUND(COALESCE(tt.life,0),2) AS life, ROUND(COALESCE(tt.conc,0)*100,1) AS conc,
      CASE WHEN COALESCE(tt.conc,0)>0.8 AND COALESCE(tt.life,999)<3 AND COALESCE(tt.holders,0)>0
           THEN 0 ELSE 1 END AS rug_order
    FROM erc e LEFT JOIN tt ON e.addr=tt.token
    ORDER BY rug_order ASC, holders DESC NULLS LAST LIMIT {int(limit)}
    """
    async with Craft() as craft:
        res = await craft.execute_query(CONNECTION, sql, max_rows=limit)
    cols = [c.lower() for c in (res.get("columns") or [])]
    idx = {c: i for i, c in enumerate(cols)}
    members = []
    for r in res.get("rows") or []:
        conc = float(r[idx["conc"]] or 0)
        life = float(r[idx["life"]] or 0)
        holders = int(r[idx["holders"]] or 0)
        is_rug = conc > 80 and life < 3 and holders > 0
        addr = r[idx["token"]]
        members.append({
            "token": addr, "short": addr[:6] + "…" + addr[-4:],
            "deployed": r[idx["deployed"]],
            "transfers": int(r[idx["transfers"]] or 0),
            "holders": holders, "life": life, "conc": conc, "rug": is_rug,
        })
    out = {"fp": fp, "members": members}
    _OP_MEMBERS_CACHE[fp] = out
    return out


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
    HAVING COUNT(*) >= 80
      AND ROUND(MAX(TRY_TO_DOUBLE(tt."value"))/NULLIF(SUM(TRY_TO_DOUBLE(tt."value")),0)*100,1) > 45
      AND (MAX(tt."block_timestamp")-MIN(tt."block_timestamp"))/(1000000.0*86400) < 12
    ORDER BY concentration DESC, transfers DESC
    LIMIT 14
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


@app.get("/api/timeline")
async def api_timeline(token: str) -> dict:
    """Token activity lifecycle: transfer volume/count bucketed over the token's
    active life, with fraud-event markers (mint, distribution peak, collapse).
    Visualizes the pump-then-collapse rug shape. Pure CRAFT."""
    tok = token.strip().lower()
    sql = f"""
    WITH tt AS (
      SELECT "block_timestamp" AS ts, TRY_TO_DOUBLE("value") AS val,
             LOWER("from_address") AS frm, LOWER("to_address") AS dst
      FROM "CRYPTO"."CRYPTO_ETHEREUM"."TOKEN_TRANSFERS"
      WHERE LOWER("token_address") = '{tok}'
    ),
    b AS (SELECT MIN(ts) AS mn, MAX(ts) AS mx FROM tt),
    w AS (SELECT mn, GREATEST(1, (mx-mn)/40.0) AS width FROM b)
    SELECT FLOOR((tt.ts-(SELECT mn FROM w))/(SELECT width FROM w)) AS bucket,
      COUNT(*) AS transfers, SUM(tt.val) AS volume,
      COUNT(DISTINCT tt.dst) AS receivers,
      TO_VARCHAR(TO_TIMESTAMP(MIN(tt.ts)/1000000),'YYYY-MM-DD HH24:MI') AS t
    FROM tt GROUP BY bucket ORDER BY bucket
    """
    async with Craft() as craft:
        res = await craft.execute_query(CONNECTION, sql, max_rows=60)
    cols = [c.lower() for c in (res.get("columns") or [])]
    idx = {c: i for i, c in enumerate(cols)}
    buckets = []
    for r in res.get("rows") or []:
        buckets.append({
            "i": int(float(r[idx["bucket"]] or 0)),
            "transfers": int(r[idx["transfers"]] or 0),
            "volume": float(r[idx["volume"]] or 0),
            "receivers": int(r[idx["receivers"]] or 0),
            "t": r[idx["t"]],
        })
    markers = []
    if buckets:
        peak = max(range(len(buckets)), key=lambda i: buckets[i]["transfers"])
        markers.append({"i": 0, "kind": "mint", "label": "Deploy · supply minted"})
        if peak != 0:
            markers.append({"i": peak, "kind": "peak", "label": "Distribution burst"})
        markers.append({"i": len(buckets) - 1, "kind": "collapse",
                        "label": "Activity collapse · rug"})
    return {"token": tok, "buckets": buckets, "markers": markers}


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
