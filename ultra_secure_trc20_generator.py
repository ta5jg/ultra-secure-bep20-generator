#!/usr/bin/env python3
"""Tron ağında TRC20 ultra güvenli token paketi üretir.

Aynı ``collect_config`` motorunu ``ultra_secure_bep20_generator`` ile paylaşır (ağ Tron’a sabittir).

Profil seçenekleri (BEP20 script ile aynı):
- Stablecoin vs volatil, serbest decimals, varsayılan 10 M initial supply
- Varsayılan mint tavanı: ``min(initial × 10, 1_000_000_000)`` token (``uint256.max`` yok)

Varsayılan ad/sembol soruları: Tether USD Bridged ZED20 (USDT.z).

Çalıştırma::
    python3 ultra_secure_trc20_generator.py
"""

from ultra_secure_bep20_generator import collect_config, create_ultra_secure_token_package


def main() -> None:
    create_ultra_secure_token_package(collect_config(chain_preset="tron"))


if __name__ == "__main__":
    main()
