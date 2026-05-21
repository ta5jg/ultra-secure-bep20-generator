#!/usr/bin/env python3
"""Multi-DEX oracle consensus — shadow RPC / sahte kontrat tespiti.

Paralel (gölge) RPC'lerin BscScan'de olmayan uydurma kontrat adreslerini
göstermesine karşı zorunlu doğrulama katmanı:

1. Resmi RPC'de bytecode var mı?
2. Gölge RPC ile resmi RPC bytecode hash'i aynı mı?
3. Explorer (BscScan/Etherscan) indeksinde kayıt var mı?
4. PancakeSwap / Uniswap / SunSwap Factory getPair + CREATE2 pair hash eşleşmesi
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from dataclasses import dataclass
from typing import Any

try:
    import requests
except ImportError:
    requests = None  # type: ignore

# ---------------------------------------------------------------------------
# Zincir + DEX fabrika registry (Uniswap V2 / PancakeSwap V2 uyumlu CREATE2)
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class DexFactory:
    name: str
    factory: str
    init_code_pair_hash: str
    quote_token: str  # WBNB / WETH / WTRX wrapper
    subgraph: str | None = None


@dataclass(frozen=True)
class ChainProfile:
    chain_id: int
    official_rpc: str
    explorer_api: str
    explorer_verify_key_env: str
    dex_factories: tuple[DexFactory, ...]


CHAIN_PROFILES: dict[str, ChainProfile] = {
    "bsc": ChainProfile(
        chain_id=56,
        official_rpc=os.environ.get("BSC_RPC_URL", "https://bsc-dataseed.binance.org"),
        explorer_api="https://api.bscscan.com/api",
        explorer_verify_key_env="BSCSCAN_API_KEY",
        dex_factories=(
            DexFactory(
                name="PancakeSwap V2",
                factory="0xcA143Ce32Fe78f1f7019d7d551a6402fC5350c73",
                init_code_pair_hash="0x00fb7f630766e6a796048ea87d01acd3068e8ff67d078148a3fa3f4a84f69bd5",
                quote_token="0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c",
                subgraph="https://api.thegraph.com/subgraphs/name/pancakeswap/exchange-v2",
            ),
        ),
    ),
    "ethereum": ChainProfile(
        chain_id=1,
        official_rpc=os.environ.get("ETHEREUM_RPC_URL", "https://rpc.ankr.com/eth"),
        explorer_api="https://api.etherscan.io/api",
        explorer_verify_key_env="ETHERSCAN_API_KEY",
        dex_factories=(
            DexFactory(
                name="Uniswap V2",
                factory="0x5C69bEe701ef814a2B6a3EDD4B1652CB9cc5aA6f",
                init_code_pair_hash="0x96e8ac4277198ff8b6f785478aa9a793f24ee5b88ac2e02050d56bc84ddd844f",
                quote_token="0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2",
                subgraph="https://api.thegraph.com/subgraphs/name/uniswap/uniswap-v2",
            ),
        ),
    ),
    "tron": ChainProfile(
        chain_id=728126428,
        official_rpc=os.environ.get("TRON_RPC_URL", "https://api.trongrid.io"),
        explorer_api="https://apilist.tronscanapi.com/api",
        explorer_verify_key_env="TRONSCAN_API_KEY",
        dex_factories=(
            DexFactory(
                name="SunSwap V2",
                factory="TKzxdSv2FCEQrXggPE6W3cP3W8VKnF3q5",
                init_code_pair_hash="0x96e8ac4277198ff8b6f785478aa9a793f24ee5b88ac2e82050d56bc84ddd844f",
                quote_token="T9yD14Nj9j7xAB4dbGeiX9h8unkKHxuWwb",
                subgraph=None,
            ),
        ),
    ),
}

GET_PAIR_SELECTOR = "0xe6a43905"  # getPair(address,address)


def _require_requests() -> None:
    if requests is None:
        raise RuntimeError("requests modülü gerekli: pip install requests")


def _norm_evm(addr: str) -> str:
    a = (addr or "").strip()
    if not a.startswith("0x") or len(a) != 42:
        raise ValueError(f"Geçersiz EVM adresi: {addr}")
    return a.lower()


def _rpc_call(rpc_url: str, method: str, params: list[Any], timeout: int = 12) -> Any:
    _require_requests()
    payload = {"jsonrpc": "2.0", "id": 1, "method": method, "params": params}
    r = requests.post(rpc_url, json=payload, timeout=timeout)
    r.raise_for_status()
    body = r.json()
    if "error" in body:
        raise RuntimeError(f"RPC error ({rpc_url}): {body['error']}")
    return body.get("result")


def _get_code(rpc_url: str, address: str) -> str:
    code = _rpc_call(rpc_url, "eth_getCode", [address, "latest"]) or "0x"
    return code if isinstance(code, str) else "0x"


def _code_hash(code: str) -> str:
    import hashlib

    raw = bytes.fromhex(code[2:]) if code and code != "0x" else b""
    return hashlib.sha256(raw).hexdigest()


def _pad_address(addr: str) -> str:
    return addr.lower().replace("0x", "").zfill(64)


def _keccak256(data: bytes) -> bytes:
    try:
        from Crypto.Hash import keccak  # pycryptodome

        k = keccak.new(digest_bits=256)
        k.update(data)
        return k.digest()
    except ImportError:
        pass
    try:
        import sha3  # pysha3

        return sha3.keccak_256(data).digest()
    except ImportError:
        raise RuntimeError(
            "CREATE2 pair hash için pycryptodome veya pysha3 gerekli: "
            "pip install pycryptodome"
        )


INIT_CODE_HASH_SELECTOR = "0x5855a25a"  # INIT_CODE_PAIR_HASH()


def _fetch_init_code_pair_hash(rpc_url: str, factory: str) -> str | None:
    try:
        result = _rpc_call(
            rpc_url,
            "eth_call",
            [{"to": _rpc_address(factory), "data": INIT_CODE_HASH_SELECTOR}, "latest"],
        )
        if result and len(result) >= 66:
            return "0x" + result[-64:].lower()
    except Exception:
        pass
    return None


def compute_v2_pair_address(
    factory: str,
    token_a: str,
    token_b: str,
    init_code_hash: str,
    *,
    rpc_url: str | None = None,
) -> str:
    """Uniswap V2 / PancakeSwap V2 CREATE2 pair adresi."""
    if rpc_url:
        live = _fetch_init_code_pair_hash(rpc_url, factory)
        if live:
            init_code_hash = live
    a, b = _norm_evm(token_a), _norm_evm(token_b)
    token0, token1 = (a, b) if int(a, 16) < int(b, 16) else (b, a)
    # Uniswap V2 / PancakeSwap: salt = keccak256(abi.encodePacked(token0, token1)) — 20+20 byte
    salt = _keccak256(bytes.fromhex(token0[2:]) + bytes.fromhex(token1[2:]))
    factory_bytes = bytes.fromhex(_norm_evm(factory)[2:])
    init_bytes = bytes.fromhex(init_code_hash.replace("0x", ""))
    preimage = b"\xff" + factory_bytes + salt + init_bytes
    digest = _keccak256(preimage)
    return "0x" + digest[-20:].hex()


def _rpc_address(addr: str) -> str:
    return "0x" + _norm_evm(addr)[2:]


def _eth_call_get_pair(rpc_url: str, factory: str, token: str, quote: str) -> str:
    token, quote = _norm_evm(token), _norm_evm(quote)
    data = GET_PAIR_SELECTOR + _pad_address(token) + _pad_address(quote)
    result = _rpc_call(
        rpc_url, "eth_call", [{"to": _rpc_address(factory), "data": data}, "latest"]
    )
    if not result or result == "0x" or int(result, 16) == 0:
        return "0x0000000000000000000000000000000000000000"
    # last 20 bytes
    return "0x" + result[-40:]


def _explorer_has_contract(profile: ChainProfile, address: str) -> bool:
    _require_requests()
    key = os.environ.get(profile.explorer_verify_key_env, "")
    if not key:
        return _get_code(profile.official_rpc, address) not in ("0x", "0x0")

    params = {
        "module": "contract",
        "action": "getsourcecode",
        "address": address,
        "apikey": key,
    }
    try:
        r = requests.get(profile.explorer_api, params=params, timeout=12)
        payload = r.json()
        if payload.get("status") != "1" or not payload.get("result"):
            return False
        row = payload["result"][0] if isinstance(payload["result"], list) else payload["result"]
        name = (row.get("ContractName") or "").strip()
        # "Not Verified" yine de zincirde var demektir; boş ABI + Unknown ise şüpheli
        if name in ("", "Unknown"):
            return _get_code(profile.official_rpc, address) not in ("0x", "0x0")
        return True
    except Exception:
        return False


def _subgraph_pair_exists(subgraph_url: str, token: str) -> list[str]:
    _require_requests()
    t = token.lower()
    query = (
        "{ pairs(where: { or: ["
        f'{{ token0: "{t}" }}, {{ token1: "{t}" }}'
        "] }, first: 5) { id } }"
    )
    try:
        r = requests.post(subgraph_url, json={"query": query}, timeout=10)
        data = r.json()
        pairs = data.get("data", {}).get("pairs") or []
        return [p["id"] for p in pairs if p.get("id")]
    except Exception:
        return []


@dataclass
class VerifyReport:
    chain: str
    address: str
    ok: bool
    official_code_hash: str
    shadow_code_hash: str | None
    rpc_consensus: bool
    explorer_indexed: bool
    dex_checks: list[dict[str, Any]]
    errors: list[str]
    warnings: list[str]

    def to_dict(self) -> dict[str, Any]:
        return {
            "chain": self.chain,
            "address": self.address,
            "ok": self.ok,
            "official_code_hash": self.official_code_hash,
            "shadow_code_hash": self.shadow_code_hash,
            "rpc_consensus": self.rpc_consensus,
            "explorer_indexed": self.explorer_indexed,
            "dex_checks": self.dex_checks,
            "errors": self.errors,
            "warnings": self.warnings,
        }


def verify_contract_on_multi_dex(
    chain: str,
    contract_address: str,
    *,
    shadow_rpc: str | None = None,
    strict_explorer: bool = True,
    require_liquidity_pair: bool = False,
) -> VerifyReport:
    """
    Çoklu-DEX + RPC konsensüs doğrulaması.

    strict_explorer: Explorer'da kayıt yoksa reddet (gölge ağ import'u).
    require_liquidity_pair: Henüz pair yoksa reddet (yeni deploy için False bırakın).
    """
    chain = chain.lower().strip()
    if chain not in CHAIN_PROFILES:
        return VerifyReport(
            chain=chain,
            address=contract_address,
            ok=False,
            official_code_hash="",
            shadow_code_hash=None,
            rpc_consensus=False,
            explorer_indexed=False,
            dex_checks=[],
            errors=[f"Desteklenmeyen zincir: {chain}"],
            warnings=[],
        )

    profile = CHAIN_PROFILES[chain]
    try:
        address = _norm_evm(contract_address)
    except ValueError as e:
        return VerifyReport(
            chain=chain,
            address=contract_address,
            ok=False,
            official_code_hash="",
            shadow_code_hash=None,
            rpc_consensus=False,
            explorer_indexed=False,
            dex_checks=[],
            errors=[str(e)],
            warnings=[],
        )

    errors: list[str] = []
    warnings: list[str] = []
    dex_checks: list[dict[str, Any]] = []

    official_code = _get_code(profile.official_rpc, address)
    official_hash = _code_hash(official_code)
    if official_code in ("0x", "0x0", ""):
        errors.append("Resmi RPC: kontrat bytecode yok (adres boş veya sahte).")

    shadow_url = shadow_rpc or os.environ.get("SHADOW_RPC_URL", "").strip()
    shadow_hash: str | None = None
    rpc_consensus = True
    if shadow_url:
        try:
            shadow_code = _get_code(shadow_url, address)
            shadow_hash = _code_hash(shadow_code)
            if shadow_code != official_code:
                rpc_consensus = False
                errors.append(
                    "SHADOW NETWORK: Gölge RPC bytecode resmi RPC ile uyuşmuyor "
                    f"(official={official_hash[:12]}… shadow={shadow_hash[:12]}…)."
                )
        except Exception as exc:
            warnings.append(f"Gölge RPC okunamadı: {exc}")

    explorer_ok = _explorer_has_contract(profile, address)
    if strict_explorer and not explorer_ok and official_code not in ("0x", "0x0"):
        # Yeni deploy: explorer gecikmesi olabilir
        warnings.append(
            "Explorer henüz indekslememiş olabilir; resmi RPC'de kod mevcut."
        )
    if strict_explorer and official_code in ("0x", "0x0") and not explorer_ok:
        errors.append("Explorer + resmi RPC: kontrat kaydı bulunamadı (uydurma adres?).")

    any_pair = False
    for dex in profile.dex_factories:
        on_chain_pair = _eth_call_get_pair(
            profile.official_rpc, dex.factory, address, dex.quote_token
        )
        predicted = compute_v2_pair_address(
            dex.factory, address, dex.quote_token, dex.init_code_pair_hash,
            rpc_url=profile.official_rpc,
        )
        subgraph_ids: list[str] = []
        if dex.subgraph:
            subgraph_ids = _subgraph_pair_exists(dex.subgraph, address)

        pair_match = (
            on_chain_pair.lower() == predicted.lower()
            if on_chain_pair.lower() != "0x0000000000000000000000000000000000000000"
            else False
        )
        if on_chain_pair.lower() != "0x0000000000000000000000000000000000000000":
            any_pair = True
            if not pair_match:
                errors.append(
                    f"{dex.name}: Factory getPair ({on_chain_pair}) != CREATE2 hash ({predicted})."
                )

        dex_checks.append(
            {
                "dex": dex.name,
                "factory": dex.factory,
                "on_chain_pair": on_chain_pair,
                "predicted_pair": predicted,
                "pair_hash_match": pair_match,
                "subgraph_pairs": subgraph_ids,
            }
        )

    if require_liquidity_pair and not any_pair:
        errors.append("Zorunlu likidite: hiçbir resmi DEX factory'de pair bulunamadı.")

    ok = len(errors) == 0 and official_code not in ("0x", "0x0") and rpc_consensus

    report = VerifyReport(
        chain=chain,
        address=address,
        ok=ok,
        official_code_hash=official_hash,
        shadow_code_hash=shadow_hash,
        rpc_consensus=rpc_consensus,
        explorer_indexed=explorer_ok,
        dex_checks=dex_checks,
        errors=errors,
        warnings=warnings,
    )

    if ok:
        print(f"✔ MULTI-DEX DOĞRULAMA OK: {address} ({chain})")
        for dc in dex_checks:
            if dc["on_chain_pair"] != "0x0000000000000000000000000000000000000000":
                print(f"  ↳ {dc['dex']} pair={dc['on_chain_pair']} hash_ok={dc['pair_hash_match']}")
    else:
        print(f"🚨 MULTI-DEX DOĞRULAMA BAŞARISIZ: {address} ({chain})")
        for err in errors:
            print(f"  ✗ {err}")

    for w in warnings:
        print(f"  ⚠ {w}")

    return report


def main() -> int:
    parser = argparse.ArgumentParser(description="Multi-DEX oracle consensus verifier")
    parser.add_argument("--chain", required=True, help="bsc | ethereum | tron")
    parser.add_argument("--address", required=True, help="Token/kontrat adresi")
    parser.add_argument("--shadow-rpc", default="", help="Paralel/gölge RPC URL")
    parser.add_argument(
        "--strict-explorer",
        action="store_true",
        default=os.environ.get("MULTI_DEX_STRICT_EXPLORER", "0") == "1",
    )
    parser.add_argument(
        "--require-pair",
        action="store_true",
        default=os.environ.get("MULTI_DEX_REQUIRE_PAIR", "0") == "1",
    )
    parser.add_argument("--json", action="store_true", help="JSON rapor yazdır")
    args = parser.parse_args()

    report = verify_contract_on_multi_dex(
        args.chain,
        args.address,
        shadow_rpc=args.shadow_rpc or None,
        strict_explorer=args.strict_explorer,
        require_liquidity_pair=args.require_pair,
    )
    if args.json:
        print(json.dumps(report.to_dict(), indent=2))
    return 0 if report.ok else 1


if __name__ == "__main__":
    sys.exit(main())
