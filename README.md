# Ultra Secure BEP20 / TRC20 Token Generator

Python ile interaktif **ultra güvenli token paketi** üretir (Solidity kontrat, Hardhat/TronBox, test, audit iskeleti, metadata, multi-DEX doğrulama).

## Scriptler

| Dosya | Amaç |
|--------|------|
| `ultra_secure_bep20_generator.py` | BSC / EVM (BEP20 varsayılan; çoklu zincir menüsü) |
| `ultra_secure_trc20_generator.py` | Tron TRC20 (Mainnet + Shasta sabit) |
| `verify_contract_on_multi_dex.py` | Shadow-RPC + explorer + DEX CREATE2 oracle doğrulaması (BSC / ETH / Tron) |

## Varsayılan profil

- **Ad / sembol:** Tether USD Bridged ZED20 / USDT.z
- **Initial supply:** 10.000.000 token
- **Mint tavanı:** `min(initial × 10, 1_000_000_000)` token — `uint256.max` **yok** (tarayıcı/cüzdan rug-pull uyarısı önlenir)
- **Varlık sınıfı:** stablecoin veya volatil (decimals serbest, öneri 6 / 18)

## Kurulum & çalıştırma

```bash
python3 ultra_secure_bep20_generator.py   # BEP20 / EVM
python3 ultra_secure_trc20_generator.py   # TRC20 / Tron
```

Üretilen klasörde: `bash setup.sh` → `npx hardhat test` → deploy scriptleri.

Multi-DEX doğrulama (tek başına):

```bash
python3 verify_contract_on_multi_dex.py --chain bsc --address 0x...
```

## Lisans

MIT — üretilen token kontratları için interaktif soruda lisans seçilebilir.
