# Candidate demo tokens (scouted from TOKEN_TRANSFERS, all present in the sample)

Short-lived, high-activity ERC-20s (≥500 transfers, active lifespan < 5 days) —
strong scam/airdrop/rug candidates for the first live investigation.

| token_address | transfers | holders | lifespan (days) | shape |
|---|---|---|---|---|
| `0x47a16e51bcc89c0015622fe83eb482a4522f6c5c` | 5204 | 5204 | 1.0 | 1 transfer/holder → classic **scam airdrop / dust lure** |
| `0xb334c7e5cf74197f5da676cbeaf3a1c1e54a6a94` | 520 | 520 | **0.003** (~4 min) | 520 sends in 4 min → **bot airdrop blast** |
| `0x53b27466c3fa132f7e81d6399a776c55f21ad480` | 663 | 81 | 1.0 | transfers ≫ holders → **recirculation among few** |
| `0x483b2942b24681c258bc5b63cd0921e6c5ea997a` | 515 | 54 | 1.0 | concentrated into ~54 receivers |
| `0x111111f7e9b1fe072ade438f77e1ce861c7ee4e3` | 1328 | 303 | 1.0 | ⚠️ 1inch Chi Gastoken vanity prefix — likely LEGIT, good negative control |

**Suggested first run:** `0x47a16e51bcc89c0015622fe83eb482a4522f6c5c` (clean airdrop-scam
story) or `0x53b27466c3fa132f7e81d6399a776c55f21ad480` (concentration story).
Use `0x111111f7…` as a **legit control** to show the agent doesn't just cry wolf.

## High-concentration rug candidates (top-1 receiver holds >99% of transferred value)

Scouted from TOKEN_TRANSFERS (ERC-20, 200–5000 transfers). Extreme single-address
concentration = classic rug / insider-controlled supply.

| token_address | transfers | holders | lifespan (days) | top-1 share |
|---|---|---|---|---|
| `0x0008a519b43d1dd0d81e08b4d569c769524e0593` | 267 | **4** | 0.4 | 99.9% |
| `0x9193265983f21bf2d787e7de2c6f72c12a86f2d1` | 383 | **1** | 0.34 | 100% |
| `0xa88fc5e2b9aa4e3bb40d67fa553517a1569c8e72` | 518 | **3** | 30.3 | 99.76% |
| `0xdb967cceb5ce4adb1524dad8f1fad6007fd7e86e` | 218 | 5 | 0.6 | 98.64% |
| `0xda3cd7eeed7dc8a0bc76968a9ae67d318d1634b8` | 277 | 61 | 244 | 100% |

**Headline demo token:** `0x0008a519b43d1dd0d81e08b4d569c769524e0593` — 4 holders,
0.4-day life, 99.9% concentration. Expect a LIKELY RUG verdict.

⚠️ Verify per token: some ~100% single-holder tokens could be a staking/vesting
lock, not a rug — the agent should tease that apart (that nuance is a feature).
