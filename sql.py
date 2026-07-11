"""Dev helper: run a natural-language question through CRAFT (generate_sql ->
execute_query) and print the rows. Handy for manual data exploration.

    uv run sql.py "how many ERC20 tokens are there?"
    uv run sql.py --raw 'SELECT COUNT(*) FROM "CRYPTO"."CRYPTO_ETHEREUM"."CONTRACTS"'
"""

from __future__ import annotations

import argparse
import asyncio
import json

from craft import Craft, _deep_find
from prompts import CONNECTION, SCHEMA_FQN, SCHEMA_NAME


async def run(question: str | None, raw_sql: str | None) -> None:
    async with Craft() as craft:
        sql = raw_sql
        if sql is None:
            gen = await craft.call(
                "generate_sql",
                {
                    "question": question,
                    "connection": CONNECTION,
                    "schema": {"schema_name": SCHEMA_NAME, "schema_fqn": SCHEMA_FQN},
                },
            )
            payload = _deep_find(gen, "generate_sql") or {}
            sql = payload.get("sql")
            print("--- generated SQL ---")
            print(sql)
            if payload.get("explanation"):
                print("\n--- explanation ---")
                print(payload["explanation"])
            print()
        if not sql:
            print("no SQL produced")
            return
        result = await craft.execute_query(CONNECTION, sql, max_rows=200)
        print("--- result ---")
        print("row_count:", result.get("row_count"))
        print("columns:", result.get("columns"))
        for row in (result.get("rows") or [])[:50]:
            print(row)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("question", nargs="?", help="natural-language question")
    ap.add_argument("--raw", help="run raw SQL instead of generate_sql")
    args = ap.parse_args()
    if not args.question and not args.raw:
        ap.error("provide a question or --raw SQL")
    asyncio.run(run(args.question, args.raw))


if __name__ == "__main__":
    main()
