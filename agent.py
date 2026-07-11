"""Predictive Scam-Token Detector — autonomous on-chain investigator.

LLM  = Nebius Token Factory (OpenAI-compatible)   -> the reasoning/planning brain
Tools = Emergence CRAFT (semantic text-to-SQL)    -> the data hands
Loop  = hand-written tool-calling loop            -> a fully visible investigation log

Usage:
    uv run agent.py --check                       # verify CRAFT wiring (no LLM)
    uv run agent.py 0xTOKENADDRESS                # investigate a token
    uv run agent.py 0x... --max-steps 16 --model nvidia/nemotron-3-super-120b-a12b
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys

from dotenv import load_dotenv
from openai import AsyncOpenAI

from craft import Craft, _deep_find
from prompts import CONNECTION, SCHEMA_FQN, SCHEMA_NAME, INVESTIGATOR_SYSTEM

load_dotenv()

NEBIUS_BASE_URL = os.environ.get(
    "NEBIUS_BASE_URL", "https://api.tokenfactory.nebius.com/v1/"
)
NEBIUS_MODEL = os.environ.get("NEBIUS_MODEL", "nvidia/nemotron-3-super-120b-a12b")
TOOL_RESULT_CAP = 7000  # chars of a tool result fed back to the model

# ---------------------------------------------------------------------------
# Tools exposed to the LLM (connection + schema are injected server-side so the
# model only supplies the interesting argument — fewer ways to get it wrong).
# ---------------------------------------------------------------------------
TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "craft_generate_sql",
            "description": (
                "Turn a natural-language question into SQL against the Ethereum "
                "crypto connection. Returns generated SQL + explanation + "
                "assumptions. Use this before executing a query for any new question."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "question": {
                        "type": "string",
                        "description": "The analytical question in plain English.",
                    }
                },
                "required": ["question"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "craft_execute_query",
            "description": (
                "Run a read-only SELECT and return rows (first page inline). "
                "Pass SQL from craft_generate_sql, optionally lightly edited. "
                'Tables are quoted 3-part: "CRYPTO"."CRYPTO_ETHEREUM"."TABLE".'
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "sql": {"type": "string", "description": "A SELECT statement."}
                },
                "required": ["sql"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "craft_search_schema",
            "description": "Full-text search the catalog metadata (find tables/columns).",
            "parameters": {
                "type": "object",
                "properties": {"query": {"type": "string"}},
                "required": ["query"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "craft_get_schema",
            "description": (
                "Get metadata/columns for an entity by 4-part FQN "
                "(e.g. crypto-f9780007.CRYPTO.CRYPTO_ETHEREUM.TOKEN_TRANSFERS)."
            ),
            "parameters": {
                "type": "object",
                "properties": {"fqn": {"type": "string"}},
                "required": ["fqn"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "craft_clone_check",
            "description": (
                "Serial-deployer / scam-factory check: finds other ERC-20 tokens "
                "that share this token's EXACT contract bytecode, with each "
                "sibling's deploy date, holder count, transfer count and lifespan. "
                "Several identical-bytecode tokens (esp. same-day, all short-lived) "
                "= a scam factory. Call this before concluding."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "token": {"type": "string", "description": "The token address (0x…)."}
                },
                "required": ["token"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "craft_operator_scan",
            "description": (
                "Campaign-scale escalation: given a token, resolve its ENTIRE "
                "bytecode-fingerprint cluster chain-wide (the 'rug-kit' operator) "
                "and return how many tokens share that exact code, how many are "
                "rug-shaped, and total wallets hit. Reveals whether a token is one "
                "of a whole fleet. Call this after the clone check for the big picture."
            ),
            "parameters": {
                "type": "object",
                "properties": {"token": {"type": "string", "description": "token address (0x…)"}},
                "required": ["token"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "craft_sample_data",
            "description": (
                "Preview rows of a table. table_fqn is 3-part WITHOUT the slug: "
                "CRYPTO.CRYPTO_ETHEREUM.TABLE"
            ),
            "parameters": {
                "type": "object",
                "properties": {"table_fqn": {"type": "string"}},
                "required": ["table_fqn"],
            },
        },
    },
]


# ---------------------------------------------------------------------------
# Tool dispatch -> CRAFT
# ---------------------------------------------------------------------------
# Reasoning models sometimes drop the `craft_` prefix or invent a near-name.
# Normalize so a reasonable call still lands instead of erroring + burning a step.
_TOOL_ALIASES = {
    "generate_sql": "craft_generate_sql",
    "gen_sql": "craft_generate_sql",
    "generatesql": "craft_generate_sql",
    "execute_query": "craft_execute_query",
    "run_query": "craft_execute_query",
    "runquery": "craft_execute_query",
    "executequery": "craft_execute_query",
    "execute": "craft_execute_query",
    "exec": "craft_execute_query",
    "run": "craft_execute_query",
    "query": "craft_execute_query",
    "sql": "craft_execute_query",
    "search_schema": "craft_search_schema",
    "get_schema": "craft_get_schema",
    "getschema": "craft_get_schema",
    "sample_data": "craft_sample_data",
    "sampledata": "craft_sample_data",
}


async def dispatch(craft: Craft, name: str, args: dict) -> dict:
    name = _TOOL_ALIASES.get(name.strip(), name.strip())
    if name == "craft_generate_sql":
        out = await craft.call(
            "generate_sql",
            {
                "question": args["question"],
                "connection": CONNECTION,
                "schema": {"schema_name": SCHEMA_NAME, "schema_fqn": SCHEMA_FQN},
            },
        )
        gen = _deep_find(out, "generate_sql") or {}
        return {
            "sql": gen.get("sql"),
            "explanation": gen.get("explanation"),
            "assumptions": gen.get("assumptions"),
        }
    if name == "craft_execute_query":
        return await craft.execute_query(CONNECTION, args["sql"])
    if name == "craft_clone_check":
        tok = str(args.get("token", "")).strip().lower()
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
        GROUP BY fam.addr, fam.ts ORDER BY deployed
        """
        return await craft.execute_query(CONNECTION, sql)
    if name == "craft_operator_scan":
        tok = str(args.get("token", "")).strip().lower()
        sql = f"""
        WITH t AS (SELECT MD5("bytecode") AS fp FROM "CRYPTO"."CRYPTO_ETHEREUM"."CONTRACTS"
                   WHERE LOWER("address")='{tok}' AND "is_erc20"=TRUE),
        erc AS (SELECT LOWER("address") AS addr FROM "CRYPTO"."CRYPTO_ETHEREUM"."CONTRACTS"
                WHERE "is_erc20"=TRUE AND MD5("bytecode")=(SELECT fp FROM t)),
        tt AS (SELECT LOWER("token_address") AS token, COUNT(DISTINCT "to_address") AS holders,
                 (MAX("block_timestamp")-MIN("block_timestamp"))/(1000000.0*86400) AS life,
                 MAX(TRY_TO_DOUBLE("value"))/NULLIF(SUM(TRY_TO_DOUBLE("value")),0) AS conc
               FROM "CRYPTO"."CRYPTO_ETHEREUM"."TOKEN_TRANSFERS"
               WHERE LOWER("token_address") IN (SELECT addr FROM erc) GROUP BY LOWER("token_address"))
        SELECT (SELECT COUNT(*) FROM erc) AS cluster_tokens,
          COUNT(tt.token) AS active_tokens,
          SUM(CASE WHEN tt.conc>0.8 AND tt.life<3 THEN 1 ELSE 0 END) AS rug_tokens,
          ROUND(SUM(tt.holders)) AS wallets_hit
        FROM tt
        """
        return await craft.execute_query(CONNECTION, sql)
    if name == "craft_search_schema":
        return await craft.call(
            "search_schema",
            {"connection": CONNECTION, "query": args["query"], "limit": 30},
        )
    if name == "craft_get_schema":
        return await craft.call(
            "get_schema", {"connection": CONNECTION, "fqn": args["fqn"]}
        )
    if name == "craft_sample_data":
        return await craft.call(
            "sample_data",
            {"connection": CONNECTION, "table_fqn": args["table_fqn"], "limit": 8},
        )
    return {"ok": False, "error": f"unknown tool {name}"}


# ---------------------------------------------------------------------------
# Investigation-log printing
# ---------------------------------------------------------------------------
RUNLOG: list[str] = []
_EMIT = None  # optional callback(line: str) for streaming into a UI


def _p(line: str = "") -> None:
    RUNLOG.append(line)
    print(line, flush=True)
    if _EMIT is not None:
        try:
            _EMIT(line)
        except Exception:
            pass


def parse_verdict(text: str) -> dict:
    """Pull VERDICT + RISK SCORE out of the final answer for ranking/triage."""
    import re

    verdict = None
    score = None
    m = re.search(
        r"VERDICT[:*\s]+(LIKELY RUG|SUSPICIOUS|LIKELY LEGITIMATE|INSUFFICIENT DATA)",
        text or "",
        re.IGNORECASE,
    )
    if m:
        verdict = m.group(1).upper()
    m = re.search(r"RISK SCORE[:*\s]+(\d{1,3})", text or "", re.IGNORECASE)
    if m:
        score = int(m.group(1))
    return {"verdict": verdict, "risk_score": score}


def _save_report(token: str) -> str:
    from datetime import datetime, timezone
    from pathlib import Path

    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    out = Path("reports")
    out.mkdir(exist_ok=True)
    path = out / f"{ts}_{token[:12]}.md"
    path.write_text("\n".join(RUNLOG))
    return str(path)


def _brief(result: dict) -> str:
    """One-line summary of a tool result for the log."""
    if not isinstance(result, dict):
        return str(result)[:200]
    if "rows" in result and result.get("rows") is not None:
        rc = result.get("row_count")
        cols = result.get("columns")
        return f"{rc} row(s); columns={cols}; first={ (result['rows'] or [])[:2] }"
    if "sql" in result:
        return f"SQL drafted: {str(result.get('sql'))[:160]}..."
    return json.dumps(result, default=str)[:220]


# ---------------------------------------------------------------------------
# Agent loop
# ---------------------------------------------------------------------------
async def investigate(token: str, model: str, max_steps: int, emit=None) -> str:
    global _EMIT
    _EMIT = emit
    api_key = os.environ.get("NEBIUS_API_KEY")
    if not api_key:
        sys.exit("ERROR: set NEBIUS_API_KEY (see .env.template).")

    client = AsyncOpenAI(base_url=NEBIUS_BASE_URL, api_key=api_key)
    task = (
        f"Investigate ERC-20 token {token} on Ethereum. Determine whether it is a "
        f"scam / rug pull. Follow the METHOD, show your reasoning at each step, and "
        f"end with the VERDICT card."
    )
    messages: list[dict] = [
        {"role": "system", "content": INVESTIGATOR_SYSTEM},
        {"role": "user", "content": task},
    ]

    RUNLOG.clear()
    _p(f"\n{'='*70}\n  INVESTIGATION: {token}\n  model: {model}\n{'='*70}")

    async with Craft() as craft:
        for step in range(1, max_steps + 1):
            resp = await client.chat.completions.create(
                model=model,
                messages=messages,
                tools=TOOLS,
                tool_choice="auto",
                max_tokens=4000,  # reasoning model: leave room for thinking + answer
            )
            msg = resp.choices[0].message

            # nemotron is a reasoning model: it exposes chain-of-thought separately.
            reasoning = getattr(msg, "reasoning_content", None)
            if reasoning:
                _p(f"\n[step {step}] thinking: {reasoning.strip()[:600]}")

            assistant: dict = {"role": "assistant", "content": msg.content or ""}
            if msg.tool_calls:
                assistant["tool_calls"] = [
                    {
                        "id": tc.id,
                        "type": "function",
                        "function": {
                            "name": tc.function.name,
                            "arguments": tc.function.arguments,
                        },
                    }
                    for tc in msg.tool_calls
                ]
            messages.append(assistant)

            if msg.content and msg.content.strip():
                _p(f"\n[step {step}] {msg.content.strip()}")

            if not msg.tool_calls:
                _p(f"\n{'='*70}\n  DONE ({step} steps)\n{'='*70}")
                _p(f"[saved report -> {_save_report(token)}]")
                return msg.content or ""

            for tc in msg.tool_calls:
                try:
                    args = json.loads(tc.function.arguments or "{}")
                except json.JSONDecodeError:
                    args = {}
                _p(f"\n  -> {tc.function.name}({json.dumps(args, default=str)[:200]})")
                try:
                    result = await dispatch(craft, tc.function.name, args)
                except Exception as exc:  # keep the loop alive; let the model react
                    result = {"ok": False, "error": f"{type(exc).__name__}: {exc}"}
                _p(f"     {_brief(result)}")
                messages.append(
                    {
                        "role": "tool",
                        "tool_call_id": tc.id,
                        "content": json.dumps(result, default=str)[:TOOL_RESULT_CAP],
                    }
                )

        # Budget exhausted without the model concluding on its own. Force a verdict
        # by making ONE final call with NO tools available — it must synthesize from
        # the evidence gathered above. (nemotron ignores tool_choice="none", so we
        # remove tools entirely, which it cannot ignore.)
        _p("\n[budget reached — forcing final synthesis]")
        messages.append(
            {
                "role": "user",
                "content": (
                    "Stop investigating. Based ONLY on the evidence gathered above, "
                    "output the final VERDICT card now: VERDICT, RISK SCORE, KEY "
                    "EVIDENCE, DETECTION RULE, CAVEATS."
                ),
            }
        )
        final = await client.chat.completions.create(
            model=model, messages=messages, max_tokens=4000
        )
        verdict = final.choices[0].message.content or ""
        _p(f"\n{verdict}")
    _p(f"\n{'='*70}\n  DONE (synthesized)\n{'='*70}")
    _p(f"[saved report -> {_save_report(token)}]")
    return verdict


async def check() -> None:
    _p("Checking CRAFT wiring...")
    async with Craft() as craft:
        hello = await craft.call("hello_world")
        _p(f"hello_world -> {json.dumps(hello, default=str)}")
        conns = await craft.call("list_data_connections")
        slugs = [c.get("slug") for c in (_deep_find(conns, "connections") or [])]
        _p(f"connections -> {slugs}")
        _p("OK — CRAFT reachable and authenticated." if slugs else "No connections?")


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("token", nargs="?", help="ERC-20 token address (0x...)")
    ap.add_argument("--check", action="store_true", help="verify CRAFT wiring, no LLM")
    ap.add_argument("--model", default=NEBIUS_MODEL)
    ap.add_argument("--max-steps", type=int, default=22)
    args = ap.parse_args()

    if args.check:
        asyncio.run(check())
        return
    if not args.token:
        ap.error("provide a token address, or use --check")
    asyncio.run(investigate(args.token, args.model, args.max_steps))


if __name__ == "__main__":
    main()
