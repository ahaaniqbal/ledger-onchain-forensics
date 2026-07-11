"""Known-address intelligence: label counterparties that matter for forensics.

This is the honest "cybersecurity" layer — if a token's funds touch a known
mixer, DEX router, exchange hot wallet, or the mint/burn address, we flag it.
All addresses are real Ethereum mainnet, lowercased for matching.
"""

from __future__ import annotations

# label -> (kind, display) ; kind drives node color/severity in the UI
KNOWN_ADDRESSES: dict[str, tuple[str, str]] = {
    # mint / burn
    "0x0000000000000000000000000000000000000000": ("mint", "Mint / 0x0"),
    "0x000000000000000000000000000000000000dead": ("burn", "Burn address"),
    # Tornado Cash (mixer) — router + fixed-denomination pools
    "0x722122df12d4e14e13ac3b6895a86e84145b6967": ("mixer", "Tornado Cash Router"),
    "0x12d66f87a04a9e220743712ce6d9bb1b5616b8fc": ("mixer", "Tornado Cash 0.1 ETH"),
    "0x47ce0c6ed5b0ce3d3a51fdb1c52dc66a7c3c2936": ("mixer", "Tornado Cash 1 ETH"),
    "0x910cbd523d972eb0a6f4cae4618ad62622b39dbf": ("mixer", "Tornado Cash 10 ETH"),
    "0xa160cdab225685da1d56aa342ad8841c3b53f291": ("mixer", "Tornado Cash 100 ETH"),
    "0xd90e2f925da726b50c4ed8d0fb90ad053324f31b": ("mixer", "Tornado Cash 1 ETH"),
    # DEX routers
    "0x7a250d5630b4cf539739df2c5dacb4c659f2488d": ("dex", "Uniswap V2 Router"),
    "0xe592427a0aece92de3edee1f18e0157c05861564": ("dex", "Uniswap V3 Router"),
    "0x68b3465833fb72a70ecdf485e0e4c7bd8665fc45": ("dex", "Uniswap Universal Router"),
    "0xd9e1ce17f2641f24ae83637ab66a2cca9c378b9f": ("dex", "SushiSwap Router"),
    # major exchange hot wallets
    "0x28c6c06298d514db089934071355e5743bf21d60": ("exchange", "Binance 14"),
    "0x21a31ee1afc51d94c2efccaa2092ad1028285549": ("exchange", "Binance 15"),
    "0xdfd5293d8e347dfe59e90efd55b2956a1343963d": ("exchange", "Binance 16"),
    "0x56eddb7aa87536c09ccc2793473599fd21a8b17f": ("exchange", "Binance 17"),
    "0x71660c4005ba85c37ccec55d0c4493e66fe775d3": ("exchange", "Coinbase 1"),
    "0x503828976d22510aad0201ac7ec88293211d23da": ("exchange", "Coinbase 2"),
    "0x267be1c1d684f78cb4f6a176c4911b741e4ffdc0": ("exchange", "Kraken 4"),
}


def label_address(addr: str) -> tuple[str, str] | None:
    """Return (kind, display) if the address is known, else None."""
    if not addr:
        return None
    return KNOWN_ADDRESSES.get(addr.strip().lower())
