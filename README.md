# Ultra Secure BEP20 / TRC20 Token Generator

Python ile interaktif **ultra güvenli token paketi** üretir (Solidity kontrat, Hardhat/TronBox, test, audit iskeleti, metadata).

## Scriptler

| Dosya | Ağ |
|--------|-----|
| `ultra_secure_bep20_generator.py` | BSC / EVM (BEP20 varsayılan; çoklu zincir menüsü) |
| `ultra_secure_trc20_generator.py` | Tron TRC20 (Mainnet + Shasta sabit) |

## Varsayılan profil

- **Ad / sembol:** Tether USD Bridged ZED20 / USDT.z
- **Initial supply:** 10.000.000 token
- **Mint tavanı:** pratikte sınırsız (`ERC20Capped(type(uint256).max)`)
- **Varlık sınıfı:** stablecoin veya volatil (decimals serbest, öneri 6 / 18)

## Kurulum & çalıştırma

```bash
python3 ultra_secure_bep20_generator.py   # BEP20 / EVM
python3 ultra_secure_trc20_generator.py   # TRC20 / Tron
```

Üretilen klasörde: `bash setup.sh` → `npx hardhat test` → deploy scriptleri.

## Lisans

MIT — üretilen token kontratları için interaktif soruda lisans seçilebilir.
