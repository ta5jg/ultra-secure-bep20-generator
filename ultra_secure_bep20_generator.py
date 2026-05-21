"""Ultra Secure BEP20 / TRC20 Token Generator.

Varsayılan üretim profili: BNB Smart Chain (BEP20) — ``Tether USD Bridged ZED20`` (``USDT.z``).
[1/7] adımında **stablecoin / volatil** seçilir; **decimals** 0–30 arası seçilebilir (öneriler: 6 / 18).
**Initial supply** varsayılan ``10_000_000``; **mint tavanı** ``min(initial × 10, 1_000_000_000)`` token
(``uint256.max`` yok — tarayıcı/cüzdan rug-pull uyarısı önlenir).
İnteraktif sorularda Enter ile bu politikalar seçilebilir; Tron için ``ultra_secure_trc20_generator.py``.

Desteklenen zincirler: BSC, Ethereum, Polygon, Arbitrum, Base, Tron, Multi-chain.

Özellikler:
- ERC20 + ERC20Capped (sabit üst sınır: min(initial×çarpan, 1B token); mintable) + Burnable + Pausable + AccessControl + Ownable2Step
- Stablecoin / volatil profil seçimi (decimals & fiyat metadata önerileri)
- Initial supply varsayılan 10 milyon; decimals serbest seçim (0–30)
- Anti-bot launch-window (configurable, exempt mapping)
- Fee-on-transfer (capped, exempt mapping)
- Burn-on-transfer fee (opsiyonel, capped)
- Trading-enabled flag (manuel açma)
- Whitelist (presale + bypass)
- Max-tx / max-wallet limits (whale önleme)
- ERC20Permit (EIP-2612, opsiyonel)
- ERC20Snapshot (opsiyonel)
- UUPS upgradeable (opsiyonel; Tron'da kapalı)
- SafeERC20 + ReentrancyGuard ile rescueTokens / rescueETH
- Custom errors (gas optimize)
- Tron için pragma 0.8.18 + TronBox config + migrations
- Diğer EVM zincirler için pragma 0.8.28 + Hardhat çoklu network
- Auto-verify (BscScan/Etherscan/Polygonscan/...)
- Zorunlu Multi-DEX oracle consensus (PancakeSwap/Uniswap/SunSwap Factory pair hash + gölge RPC)
"""

import os
import re
import shutil
import sys
import json


# -------------------------- Helpers --------------------------

def sanitize_solidity_identifier(s: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9_]", "", s or "")
    if not cleaned:
        cleaned = "Token"
    if cleaned[0].isdigit():
        cleaned = "T" + cleaned
    return cleaned


def sanitize_folder_name(s: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9_\-]", "_", s or "")
    return cleaned or "Token"


def yes_no(prompt: str, default: bool = False) -> bool:
    suffix = " [yes/no" + (", default=yes]: " if default else ", default=no]: ")
    raw = input(prompt + suffix).strip().lower()
    if not raw:
        return default
    return raw in ("yes", "y", "evet", "e", "1", "true")


def parse_int(value, default: int = 0, min_v=None, max_v=None) -> int:
    try:
        v = int(str(value).strip().replace("_", "").replace(",", ""))
    except Exception:
        v = default
    if min_v is not None and v < min_v:
        v = min_v
    if max_v is not None and v > max_v:
        v = max_v
    return v


def write_file(path: str, content: str, executable: bool = False) -> None:
    parent = os.path.dirname(path)
    if parent:
        os.makedirs(parent, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)
    if executable:
        os.chmod(path, 0o755)


def is_valid_eth_address(addr: str) -> bool:
    if not addr:
        return False
    return bool(re.fullmatch(r"0x[a-fA-F0-9]{40}", addr.strip()))


# -------------------------- Chain Configurations --------------------------

CHAINS = {
    "bsc": {
        "label": "BSC (BNB Chain) Mainnet",
        "chain_id": 56,
        "rpc": "https://bsc-dataseed.binance.org",
        "explorer": "https://bscscan.com",
        "verify_key": "BSCSCAN_API_KEY",
        "verify_network": "bsc",
        "currency": "BNB",
        "evm": True,
    },
    "bscTestnet": {
        "label": "BSC Testnet",
        "chain_id": 97,
        "rpc": "https://data-seed-prebsc-1-s1.binance.org:8545",
        "explorer": "https://testnet.bscscan.com",
        "verify_key": "BSCSCAN_API_KEY",
        "verify_network": "bscTestnet",
        "currency": "tBNB",
        "evm": True,
    },
    "ethereum": {
        "label": "Ethereum Mainnet",
        "chain_id": 1,
        "rpc": "https://rpc.ankr.com/eth",
        "explorer": "https://etherscan.io",
        "verify_key": "ETHERSCAN_API_KEY",
        "verify_network": "mainnet",
        "currency": "ETH",
        "evm": True,
    },
    "sepolia": {
        "label": "Ethereum Sepolia Testnet",
        "chain_id": 11155111,
        "rpc": "https://rpc.sepolia.org",
        "explorer": "https://sepolia.etherscan.io",
        "verify_key": "ETHERSCAN_API_KEY",
        "verify_network": "sepolia",
        "currency": "sETH",
        "evm": True,
    },
    "polygon": {
        "label": "Polygon Mainnet",
        "chain_id": 137,
        "rpc": "https://polygon-rpc.com",
        "explorer": "https://polygonscan.com",
        "verify_key": "POLYGONSCAN_API_KEY",
        "verify_network": "polygon",
        "currency": "MATIC",
        "evm": True,
    },
    "arbitrum": {
        "label": "Arbitrum One",
        "chain_id": 42161,
        "rpc": "https://arb1.arbitrum.io/rpc",
        "explorer": "https://arbiscan.io",
        "verify_key": "ARBISCAN_API_KEY",
        "verify_network": "arbitrumOne",
        "currency": "ETH",
        "evm": True,
    },
    "base": {
        "label": "Base Mainnet",
        "chain_id": 8453,
        "rpc": "https://mainnet.base.org",
        "explorer": "https://basescan.org",
        "verify_key": "BASESCAN_API_KEY",
        "verify_network": "base",
        "currency": "ETH",
        "evm": True,
    },
    "tron": {
        "label": "Tron Mainnet",
        "chain_id": "0x2b6653dc",
        "rpc": "https://api.trongrid.io",
        "explorer": "https://tronscan.org",
        "verify_key": "TRONSCAN_API_KEY",
        "verify_network": "tron",
        "currency": "TRX",
        "evm": False,
    },
    "tronShasta": {
        "label": "Tron Shasta Testnet",
        "chain_id": "0x94a9059e",
        "rpc": "https://api.shasta.trongrid.io",
        "explorer": "https://shasta.tronscan.org",
        "verify_key": "TRONSCAN_API_KEY",
        "verify_network": "tronShasta",
        "currency": "tTRX",
        "evm": False,
    },
}

NETWORK_PRESETS = {
    "bsc": ["bsc", "bscTestnet"],
    "ethereum": ["ethereum", "sepolia"],
    "polygon": ["polygon"],
    "arbitrum": ["arbitrum"],
    "base": ["base"],
    "tron": ["tron", "tronShasta"],
    "multi": ["bsc", "bscTestnet", "ethereum", "sepolia", "polygon", "arbitrum", "base"],
}

NETWORK_LABELS = [
    ("bsc",      "BSC (BNB Chain)        — pragma 0.8.28, Hardhat"),
    ("ethereum", "Ethereum               — pragma 0.8.28, Hardhat"),
    ("polygon",  "Polygon                — pragma 0.8.28, Hardhat"),
    ("arbitrum", "Arbitrum One           — pragma 0.8.28, Hardhat"),
    ("base",     "Base                   — pragma 0.8.28, Hardhat"),
    ("tron",     "Tron (TRC20)           — pragma 0.8.18, TronBox"),
    ("multi",    "Multi-chain (BSC+ETH+Polygon+Arb+Base) — pragma 0.8.28"),
]

# BNB Smart Chain (BEP20) — USDT.z: üreticinin varsayılan token metadata'sı
DEFAULT_BEP20_TOKEN_NAME = "Tether USD Bridged ZED20"
DEFAULT_BEP20_TOKEN_SYMBOL = "USDT.z"
# Varsayılan arz/limit politikası (her iki generator script’te kullanılır)
DEFAULT_INITIAL_SUPPLY_UNITS = 10_000_000  # 10 milyon token (decimals öncesi)
DEFAULT_CAP_MULTIPLIER = 10               # cap = initial × 10 (varsayılan)
MAX_CAP_SUPPLY_UNITS = 1_000_000_000      # mutlak tavan: 1 milyar token (uint256.max yerine)
DEFAULT_DECIMALS_STABLECOIN = 6
DEFAULT_DECIMALS_VOLATILE = 18


def compute_cap_supply(total_supply: int, cap_multiplier: int) -> int:
    """Mint tavanı (tam token adedi): min(initial × çarpan, MAX_CAP_SUPPLY_UNITS)."""
    mult = max(1, int(cap_multiplier))
    return min(int(total_supply) * mult, MAX_CAP_SUPPLY_UNITS)


def cap_solidity_constructor_arg(cfg: dict) -> str:
    """ERC20Capped yapıcı argümanı — her zaman somut cap; uint256.max kullanılmaz."""
    decimals = cfg["decimals"]
    cap_supply = cfg["cap_supply"]
    return f"{cap_supply} * 10 ** {decimals}"


def describe_cap_human(cfg: dict) -> str:
    mult = cfg["cap_multiplier"]
    cap = cfg["cap_supply"]
    initial = cfg["total_supply"]
    if cap < initial * mult:
        return (
            f"cap {cap:,} token = min({mult}× initial {initial:,}, "
            f"tavan {MAX_CAP_SUPPLY_UNITS:,}); MINTER mint cap'e kadar"
        )
    return f"cap {cap:,} token ({mult}× initial); MINTER mint cap'e kadar"


# -------------------------- Solidity Templates --------------------------

def _common_state_block(uups: bool) -> str:
    upgrader_line = (
        '    bytes32 public constant UPGRADER_ROLE   = keccak256("UPGRADER_ROLE");'
        if uups else
        '    // (UPGRADER_ROLE not present — non-upgradeable variant)'
    )
    decimals_line = (
        "    uint8   public _customDecimals;"
        if uups else
        "    uint8   private immutable _customDecimals;"
    )
    supply_line = (
        "    uint256 public INITIAL_SUPPLY;"
        if uups else
        "    uint256 public immutable INITIAL_SUPPLY;"
    )
    gap_line = "    uint256[40] private __gap;" if uups else ""
    return f"""    bytes32 public constant MINTER_ROLE     = keccak256("MINTER_ROLE");
    bytes32 public constant PAUSER_ROLE     = keccak256("PAUSER_ROLE");
    bytes32 public constant BLACKLIST_ROLE  = keccak256("BLACKLIST_ROLE");
    bytes32 public constant FEE_ROLE        = keccak256("FEE_ROLE");
    bytes32 public constant LIMIT_ROLE      = keccak256("LIMIT_ROLE");
{upgrader_line}

    uint256 public constant FEE_DENOMINATOR    = 10_000;
    uint256 public constant MAX_FEE_BPS        = 500;     // %5
    uint256 public constant MAX_BURN_FEE_BPS   = 500;     // %5
    uint256 public constant MAX_ANTIBOT_DELAY  = 1 hours;

{decimals_line}
{supply_line}

    mapping(address => bool)    public blacklisted;
    mapping(address => bool)    public feeExempt;
    mapping(address => bool)    public antibotExempt;
    mapping(address => bool)    public whitelisted;
    mapping(address => bool)    public limitExempt;
    mapping(address => uint256) private _lastTransferAt;

    uint256 public feePercent;
    address public feeRecipient;
    uint256 public burnFeeBps;

    bool    public antibotEnabled;
    uint256 public antibotMinDelay;

    bool    public tradingEnabled;
    uint256 public maxTxAmount;
    uint256 public maxWalletAmount;

    // -------------------- Metadata & Price (informational on-chain) --------------------
    // NOT: Cüzdanlar (MetaMask, Trust Wallet) bu alanları DOĞRUDAN okumaz.
    // Wallet'ta "$1" görünmesi için CoinGecko/CMC listing veya DEX likidite havuzu gerekir.
    // tokenURI: IPFS/HTTPS metadata JSON linki (logo, açıklama, sosyal linkler)
    // priceUSD: 8 decimals (Chainlink-uyumlu) → 100000000 = $1.00
    string  public tokenURI;
    uint256 public priceUSD;

{gap_line}
"""


def _common_events_errors() -> str:
    return """    event Blacklisted(address indexed account, bool value);
    event FeeUpdated(uint256 newFeePercent, address indexed newFeeRecipient);
    event BurnFeeUpdated(uint256 newBps);
    event FeeExemptionUpdated(address indexed account, bool exempt);
    event AntibotExemptionUpdated(address indexed account, bool exempt);
    event AntibotConfigUpdated(bool enabled, uint256 minDelay);
    event WhitelistedUpdated(address indexed account, bool value);
    event LimitExemptionUpdated(address indexed account, bool exempt);
    event MaxLimitsUpdated(uint256 maxTx, uint256 maxWallet);
    event TradingEnabled();
    event TokensRescued(address indexed token, address indexed to, uint256 amount);
    event ETHRescued(address indexed to, uint256 amount);
    event TokenURIUpdated(string newURI);
    event PriceUSDUpdated(uint256 newPriceE8);

    error FeeTooHigh(uint256 fee);
    error InvalidAddress();
    error BlacklistedAccount(address account);
    error TransferTooFast();
    error CannotRescueSelfToken();
    error AntibotDelayTooLong();
    error ETHTransferFailed();
    error TradingNotEnabled();
    error MaxTxExceeded();
    error MaxWalletExceeded();
"""


def _common_admin_functions(uups: bool) -> str:
    return f"""    // -------------------- Pausable --------------------
    function pause()   external onlyRole(PAUSER_ROLE) {{ _pause(); }}
    function unpause() external onlyRole(PAUSER_ROLE) {{ _unpause(); }}

    // -------------------- Blacklist --------------------
    function blacklist(address account, bool value) external onlyRole(BLACKLIST_ROLE) {{
        if (account == address(0)) revert InvalidAddress();
        blacklisted[account] = value;
        emit Blacklisted(account, value);
    }}

    function blacklistBatch(address[] calldata accounts, bool value) external onlyRole(BLACKLIST_ROLE) {{
        for (uint256 i = 0; i < accounts.length; i++) {{
            if (accounts[i] == address(0)) revert InvalidAddress();
            blacklisted[accounts[i]] = value;
            emit Blacklisted(accounts[i], value);
        }}
    }}

    // -------------------- Fee --------------------
    function setFee(uint256 _feePercent, address _feeRecipient) external onlyRole(FEE_ROLE) {{
        if (_feePercent > MAX_FEE_BPS) revert FeeTooHigh(_feePercent);
        if (_feeRecipient == address(0)) revert InvalidAddress();
        feePercent   = _feePercent;
        feeRecipient = _feeRecipient;
        feeExempt[_feeRecipient]     = true;
        antibotExempt[_feeRecipient] = true;
        limitExempt[_feeRecipient]   = true;
        emit FeeUpdated(_feePercent, _feeRecipient);
    }}

    function setBurnFee(uint256 _bps) external onlyRole(FEE_ROLE) {{
        if (_bps > MAX_BURN_FEE_BPS) revert FeeTooHigh(_bps);
        burnFeeBps = _bps;
        emit BurnFeeUpdated(_bps);
    }}

    function setFeeExempt(address account, bool exempt) external onlyRole(FEE_ROLE) {{
        feeExempt[account] = exempt;
        emit FeeExemptionUpdated(account, exempt);
    }}

    // -------------------- Anti-bot --------------------
    function setAntibotExempt(address account, bool exempt) external onlyOwner {{
        antibotExempt[account] = exempt;
        emit AntibotExemptionUpdated(account, exempt);
    }}

    function setAntibotConfig(bool enabled, uint256 minDelay) external onlyOwner {{
        if (minDelay > MAX_ANTIBOT_DELAY) revert AntibotDelayTooLong();
        antibotEnabled  = enabled;
        antibotMinDelay = minDelay;
        emit AntibotConfigUpdated(enabled, minDelay);
    }}

    // -------------------- Whitelist --------------------
    function setWhitelist(address account, bool value) external onlyOwner {{
        if (account == address(0)) revert InvalidAddress();
        whitelisted[account] = value;
        emit WhitelistedUpdated(account, value);
    }}

    function setWhitelistBatch(address[] calldata accounts, bool value) external onlyOwner {{
        for (uint256 i = 0; i < accounts.length; i++) {{
            if (accounts[i] == address(0)) revert InvalidAddress();
            whitelisted[accounts[i]] = value;
            emit WhitelistedUpdated(accounts[i], value);
        }}
    }}

    // -------------------- Limits --------------------
    function setMaxLimits(uint256 _maxTx, uint256 _maxWallet) external onlyRole(LIMIT_ROLE) {{
        maxTxAmount     = _maxTx;
        maxWalletAmount = _maxWallet;
        emit MaxLimitsUpdated(_maxTx, _maxWallet);
    }}

    function setLimitExempt(address account, bool exempt) external onlyRole(LIMIT_ROLE) {{
        limitExempt[account] = exempt;
        emit LimitExemptionUpdated(account, exempt);
    }}

    // -------------------- Trading --------------------
    function enableTrading() external onlyOwner {{
        tradingEnabled = true;
        emit TradingEnabled();
    }}

    // -------------------- Mint (cap-aware) --------------------
    function mint(address to, uint256 amount) external onlyRole(MINTER_ROLE) {{
        _mint(to, amount);
    }}

    // -------------------- Metadata & Price (admin updatable) --------------------
    /// @notice IPFS / HTTPS metadata linki. JSON formatı önerisi:
    ///         {{ "name", "symbol", "description", "image" (logo), "decimals" }}
    function setTokenURI(string calldata _uri) external onlyOwner {{
        tokenURI = _uri;
        emit TokenURIUpdated(_uri);
    }}

    /// @notice 8 decimals fiyat (100000000 = $1.00). Chainlink AggregatorV3 ile uyumlu format.
    function setPriceUSD(uint256 _priceE8) external onlyOwner {{
        priceUSD = _priceE8;
        emit PriceUSDUpdated(_priceE8);
    }}
"""


def _common_internal_hooks(snapshot_before: str, ierc20_name: str) -> str:
    return f"""    /// @dev Pause + blacklist: every transfer/mint/burn path.
    function _beforeTokenTransfer(address from, address to, uint256 amount)
        internal
        override({snapshot_before})
        whenNotPaused
    {{
        super._beforeTokenTransfer(from, to, amount);
        if (blacklisted[from]) revert BlacklistedAccount(from);
        if (blacklisted[to])   revert BlacklistedAccount(to);
    }}

    /// @dev Trading gate, limits, anti-bot, fees — only on user-facing transfers (not mint/burn).
    function _transfer(address from, address to, uint256 amount) internal override {{
        // Mint/burn paths don't pass through here; safe to assume from!=0 && to!=0.
        // Trading gate
        if (!tradingEnabled) {{
            if (
                from != owner() && to != owner()
                && !whitelisted[from] && !whitelisted[to]
            ) revert TradingNotEnabled();
        }}

        // Max-tx / max-wallet (EOA alıcılar için). DEX likidite çoğunlukla contract (pair) adresine.
        if (!limitExempt[from] && !limitExempt[to] && from != owner() && to != owner()) {{
            if (maxTxAmount > 0 && amount > maxTxAmount) {{
                if (to.code.length == 0) revert MaxTxExceeded();
            }}
            if (
                maxWalletAmount > 0
                && to.code.length == 0
                && balanceOf(to) + amount > maxWalletAmount
            ) {{
                revert MaxWalletExceeded();
            }}
        }}

        // Anti-bot delay (top-level only, not on internal legs)
        if (
            antibotEnabled
            && !antibotExempt[from]
            && !antibotExempt[to]
        ) {{
            unchecked {{
                if (block.timestamp - _lastTransferAt[from] < antibotMinDelay) {{
                    revert TransferTooFast();
                }}
            }}
            _lastTransferAt[from] = block.timestamp;
        }}

        // Burn-on-transfer fee
        if (
            burnFeeBps > 0
            && !feeExempt[from]
            && !feeExempt[to]
        ) {{
            uint256 burnAmt = (amount * burnFeeBps) / FEE_DENOMINATOR;
            if (burnAmt > 0) {{
                _burn(from, burnAmt);
                amount -= burnAmt;
            }}
        }}

        // Fee-on-transfer
        if (
            feePercent > 0
            && !feeExempt[from]
            && !feeExempt[to]
        ) {{
            uint256 fee = (amount * feePercent) / FEE_DENOMINATOR;
            uint256 sendAmount = amount - fee;
            if (fee > 0) super._transfer(from, feeRecipient, fee);
            super._transfer(from, to, sendAmount);
        }} else {{
            super._transfer(from, to, amount);
        }}
    }}
"""


def build_non_upgradeable_contract(cfg: dict) -> str:
    contract_id = cfg["contract_id"]
    name = cfg["name"]
    symbol = cfg["symbol"]
    decimals = cfg["decimals"]
    initial_supply = cfg["total_supply"]
    cap_expr = cap_solidity_constructor_arg(cfg)
    pragma_v = cfg["pragma_version"]
    license_id = cfg["license"]
    permit_v = cfg["permit_version"]
    init_fee_bps = cfg["init_fee_bps"]
    init_burn_bps = cfg["init_burn_fee_bps"]
    antibot_enabled = cfg["antibot_enabled"]
    antibot_delay = cfg["antibot_delay"]
    init_max_tx = cfg["max_tx"]
    init_max_wallet = cfg["max_wallet"]
    trading_flag = cfg["trading_flag"]

    imports = [
        '@openzeppelin/contracts/token/ERC20/ERC20.sol',
        '@openzeppelin/contracts/token/ERC20/extensions/ERC20Capped.sol',
        '@openzeppelin/contracts/token/ERC20/extensions/ERC20Burnable.sol',
        '@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol',
        '@openzeppelin/contracts/security/Pausable.sol',
        '@openzeppelin/contracts/security/ReentrancyGuard.sol',
        '@openzeppelin/contracts/access/Ownable2Step.sol',
        '@openzeppelin/contracts/access/AccessControl.sol',
    ]
    inherits = ["ERC20Capped", "ERC20Burnable", "Pausable", "Ownable2Step", "AccessControl", "ReentrancyGuard"]

    if cfg["include_permit"]:
        imports.append('@openzeppelin/contracts/token/ERC20/extensions/ERC20Permit.sol')
        inherits.insert(2, "ERC20Permit")
    if cfg["include_snapshot"]:
        imports.append('@openzeppelin/contracts/token/ERC20/extensions/ERC20Snapshot.sol')
        inherits.insert(2, "ERC20Snapshot")

    imports_str = "\n".join(f'import "{p}";' for p in imports)
    inherits_str = ",\n    ".join(inherits)

    permit_init = f'\n        ERC20Permit("{name}")' if cfg["include_permit"] else ""

    snapshot_role = ""
    snapshot_grant = ""
    snapshot_func = ""
    snapshot_before = "ERC20"
    if cfg["include_snapshot"]:
        snapshot_role = '    bytes32 public constant SNAPSHOT_ROLE = keccak256("SNAPSHOT_ROLE");\n'
        snapshot_grant = "        _grantRole(SNAPSHOT_ROLE, admin);\n"
        snapshot_func = """
    function snapshot() external onlyRole(SNAPSHOT_ROLE) returns (uint256) {
        return _snapshot();
    }
"""
        snapshot_before = "ERC20, ERC20Snapshot"

    state_block = _common_state_block(uups=False)
    events_errors = _common_events_errors()
    admin_funcs = _common_admin_functions(uups=False)
    hooks = _common_internal_hooks(snapshot_before, "IERC20")

    initial_supply_expr = f"{initial_supply} * 10 ** {decimals}"
    init_trading = "false" if trading_flag else "true"

    return f"""// SPDX-License-Identifier: {license_id}
pragma solidity {pragma_v};

{imports_str}

/**
 * @title {contract_id}
 * @notice {name} ({symbol}) — Ultra-Secure ERC20 token (non-upgradeable variant).
 * @dev Generated by ultra_secure_bep20_generator.py. OpenZeppelin v4.9.6.
 */
contract {contract_id} is
    {inherits_str}
{{
    using SafeERC20 for IERC20;

{state_block}{snapshot_role}
{events_errors}

    /// @param admin  DEFAULT_ADMIN_ROLE + Ownable owner (multisig önerilir).
    /// @param mintTo Initial supply'ın gönderileceği cüzdan (treasury / vesting / admin).
    /// @param initialDexExempt Deploy anında fee+antibot+limit muaf (DEX router, pair, V3 pool adresleri).
    constructor(address admin, address mintTo, address[] memory initialDexExempt)
        ERC20("{name}", "{symbol}")
        ERC20Capped({cap_expr}){permit_init}
    {{
        if (admin  == address(0)) revert InvalidAddress();
        if (mintTo == address(0)) revert InvalidAddress();

        _customDecimals = {decimals};
        INITIAL_SUPPLY  = {initial_supply_expr};

        feeRecipient    = admin;
        feePercent      = {init_fee_bps};
        burnFeeBps      = {init_burn_bps};

        antibotEnabled  = {("true" if antibot_enabled else "false")};
        antibotMinDelay = {antibot_delay};

        tradingEnabled  = {init_trading};
        maxTxAmount     = {init_max_tx};
        maxWalletAmount = {init_max_wallet};

        // Metadata & price (constructor'da hardcoded; admin sonradan setterlarla değiştirebilir)
        tokenURI = "{cfg["token_uri"]}";
        priceUSD = {cfg["price_usd_e8"]};

        feeExempt[admin]     = true;
        antibotExempt[admin] = true;
        limitExempt[admin]   = true;
        if (mintTo != admin) {{
            feeExempt[mintTo]     = true;
            antibotExempt[mintTo] = true;
            limitExempt[mintTo]   = true;
        }}

        uint256 _nDex = initialDexExempt.length;
        for (uint256 _iDex; _iDex < _nDex; ++_iDex) {{
            address _aDex = initialDexExempt[_iDex];
            if (_aDex == address(0)) continue;
            feeExempt[_aDex]     = true;
            antibotExempt[_aDex] = true;
            limitExempt[_aDex]   = true;
        }}

        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(MINTER_ROLE,    admin);
        _grantRole(PAUSER_ROLE,    admin);
        _grantRole(BLACKLIST_ROLE, admin);
        _grantRole(FEE_ROLE,       admin);
        _grantRole(LIMIT_ROLE,     admin);
{snapshot_grant}
        if (admin != _msgSender()) {{
            _transferOwnership(admin);
        }}

        _mint(mintTo, INITIAL_SUPPLY);
    }}

    function decimals() public view virtual override returns (uint8) {{
        return _customDecimals;
    }}

{admin_funcs}
    // -------------------- Rescue --------------------
    function rescueTokens(address tokenAddress, address to, uint256 amount)
        external
        onlyOwner
        nonReentrant
    {{
        if (tokenAddress == address(this)) revert CannotRescueSelfToken();
        if (to == address(0)) revert InvalidAddress();
        IERC20(tokenAddress).safeTransfer(to, amount);
        emit TokensRescued(tokenAddress, to, amount);
    }}

    function rescueETH(address payable to, uint256 amount) external onlyOwner nonReentrant {{
        if (to == address(0)) revert InvalidAddress();
        (bool ok, ) = to.call{{value: amount}}("");
        if (!ok) revert ETHTransferFailed();
        emit ETHRescued(to, amount);
    }}

    receive() external payable {{}}
{snapshot_func}
{hooks}
    function _mint(address account, uint256 amount)
        internal
        override(ERC20, ERC20Capped)
    {{
        super._mint(account, amount);
    }}
}}
"""


def build_upgradeable_contract(cfg: dict) -> str:
    contract_id = cfg["contract_id"]
    name = cfg["name"]
    symbol = cfg["symbol"]
    decimals = cfg["decimals"]
    initial_supply = cfg["total_supply"]
    cap_expr = cap_solidity_constructor_arg(cfg)
    pragma_v = cfg["pragma_version"]
    license_id = cfg["license"]
    init_fee_bps = cfg["init_fee_bps"]
    init_burn_bps = cfg["init_burn_fee_bps"]
    antibot_enabled = cfg["antibot_enabled"]
    antibot_delay = cfg["antibot_delay"]
    init_max_tx = cfg["max_tx"]
    init_max_wallet = cfg["max_wallet"]
    trading_flag = cfg["trading_flag"]

    imports = [
        '@openzeppelin/contracts-upgradeable/token/ERC20/ERC20Upgradeable.sol',
        '@openzeppelin/contracts-upgradeable/token/ERC20/extensions/ERC20CappedUpgradeable.sol',
        '@openzeppelin/contracts-upgradeable/token/ERC20/extensions/ERC20BurnableUpgradeable.sol',
        '@openzeppelin/contracts-upgradeable/token/ERC20/utils/SafeERC20Upgradeable.sol',
        '@openzeppelin/contracts-upgradeable/security/PausableUpgradeable.sol',
        '@openzeppelin/contracts-upgradeable/security/ReentrancyGuardUpgradeable.sol',
        '@openzeppelin/contracts-upgradeable/access/Ownable2StepUpgradeable.sol',
        '@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol',
        '@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol',
        '@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol',
        '@openzeppelin/contracts-upgradeable/interfaces/IERC20Upgradeable.sol',
    ]
    inherits = [
        "Initializable",
        "ERC20Upgradeable",
        "ERC20CappedUpgradeable",
        "ERC20BurnableUpgradeable",
        "PausableUpgradeable",
        "Ownable2StepUpgradeable",
        "AccessControlUpgradeable",
        "ReentrancyGuardUpgradeable",
        "UUPSUpgradeable",
    ]

    permit_init = ""
    if cfg["include_permit"]:
        imports.append('@openzeppelin/contracts-upgradeable/token/ERC20/extensions/ERC20PermitUpgradeable.sol')
        inherits.insert(4, "ERC20PermitUpgradeable")
        permit_init = f'        __ERC20Permit_init("{name}");\n'

    snapshot_role = ""
    snapshot_grant = ""
    snapshot_func = ""
    snapshot_before = "ERC20Upgradeable"
    snapshot_init = ""
    if cfg["include_snapshot"]:
        imports.append('@openzeppelin/contracts-upgradeable/token/ERC20/extensions/ERC20SnapshotUpgradeable.sol')
        inherits.insert(4, "ERC20SnapshotUpgradeable")
        snapshot_role = '    bytes32 public constant SNAPSHOT_ROLE = keccak256("SNAPSHOT_ROLE");\n'
        snapshot_grant = "        _grantRole(SNAPSHOT_ROLE, admin);\n"
        snapshot_init = "        __ERC20Snapshot_init();\n"
        snapshot_func = """
    function snapshot() external onlyRole(SNAPSHOT_ROLE) returns (uint256) {
        return _snapshot();
    }
"""
        snapshot_before = "ERC20Upgradeable, ERC20SnapshotUpgradeable"

    imports_str = "\n".join(f'import "{p}";' for p in imports)
    inherits_str = ",\n    ".join(inherits)

    state_block = _common_state_block(uups=True)
    events_errors = _common_events_errors()
    admin_funcs = _common_admin_functions(uups=True)
    hooks = _common_internal_hooks(snapshot_before, "IERC20Upgradeable")

    initial_supply_expr = f"{initial_supply} * 10 ** {decimals}"
    init_trading = "false" if trading_flag else "true"

    return f"""// SPDX-License-Identifier: {license_id}
pragma solidity {pragma_v};

{imports_str}

/**
 * @title {contract_id}
 * @notice {name} ({symbol}) — Ultra-Secure ERC20 token (UUPS upgradeable variant).
 */
contract {contract_id} is
    {inherits_str}
{{
    using SafeERC20Upgradeable for IERC20Upgradeable;

{state_block}{snapshot_role}
{events_errors}

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {{
        _disableInitializers();
    }}

    function initialize(address admin, address mintTo, address[] calldata initialDexExempt) public initializer {{
        if (admin  == address(0)) revert InvalidAddress();
        if (mintTo == address(0)) revert InvalidAddress();

        __ERC20_init("{name}", "{symbol}");
        __ERC20Capped_init({cap_expr});
        __ERC20Burnable_init();
{snapshot_init}{permit_init}        __Pausable_init();
        __Ownable2Step_init();
        __AccessControl_init();
        __ReentrancyGuard_init();
        __UUPSUpgradeable_init();

        _customDecimals = {decimals};
        INITIAL_SUPPLY  = {initial_supply_expr};

        feeRecipient    = admin;
        feePercent      = {init_fee_bps};
        burnFeeBps      = {init_burn_bps};

        antibotEnabled  = {("true" if antibot_enabled else "false")};
        antibotMinDelay = {antibot_delay};

        tradingEnabled  = {init_trading};
        maxTxAmount     = {init_max_tx};
        maxWalletAmount = {init_max_wallet};

        // Metadata & price
        tokenURI = "{cfg["token_uri"]}";
        priceUSD = {cfg["price_usd_e8"]};

        feeExempt[admin]     = true;
        antibotExempt[admin] = true;
        limitExempt[admin]   = true;
        if (mintTo != admin) {{
            feeExempt[mintTo]     = true;
            antibotExempt[mintTo] = true;
            limitExempt[mintTo]   = true;
        }}

        uint256 _nDex = initialDexExempt.length;
        for (uint256 _iDex; _iDex < _nDex; ++_iDex) {{
            address _aDex = initialDexExempt[_iDex];
            if (_aDex == address(0)) continue;
            feeExempt[_aDex]     = true;
            antibotExempt[_aDex] = true;
            limitExempt[_aDex]   = true;
        }}

        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(MINTER_ROLE,    admin);
        _grantRole(PAUSER_ROLE,    admin);
        _grantRole(BLACKLIST_ROLE, admin);
        _grantRole(FEE_ROLE,       admin);
        _grantRole(LIMIT_ROLE,     admin);
        _grantRole(UPGRADER_ROLE,  admin);
{snapshot_grant}
        _transferOwnership(admin);
        _mint(mintTo, INITIAL_SUPPLY);
    }}

    function decimals() public view virtual override returns (uint8) {{
        return _customDecimals;
    }}

    function _authorizeUpgrade(address newImplementation)
        internal
        override
        onlyRole(UPGRADER_ROLE)
    {{}}

{admin_funcs}
    // -------------------- Rescue --------------------
    function rescueTokens(address tokenAddress, address to, uint256 amount)
        external
        onlyOwner
        nonReentrant
    {{
        if (tokenAddress == address(this)) revert CannotRescueSelfToken();
        if (to == address(0)) revert InvalidAddress();
        IERC20Upgradeable(tokenAddress).safeTransfer(to, amount);
        emit TokensRescued(tokenAddress, to, amount);
    }}

    function rescueETH(address payable to, uint256 amount) external onlyOwner nonReentrant {{
        if (to == address(0)) revert InvalidAddress();
        (bool ok, ) = to.call{{value: amount}}("");
        if (!ok) revert ETHTransferFailed();
        emit ETHRescued(to, amount);
    }}

    receive() external payable {{}}
{snapshot_func}
{hooks}
    function _mint(address account, uint256 amount)
        internal
        override(ERC20Upgradeable, ERC20CappedUpgradeable)
    {{
        super._mint(account, amount);
    }}
}}
"""


# -------------------------- Hardhat / Tooling Templates --------------------------

def build_setup_sh(cfg: dict) -> str:
    is_tron = cfg["is_tron"]
    extra_tron = """
# TronBox (Tron deploy için)
echo "🟥 TronBox kuruluyor..."
npm install -g tronbox || true
""" if is_tron else ""
    return f"""#!/bin/bash
set -e
echo "🔧 Başlangıç kurulumu başlıyor..."

if [ -f .venv/bin/activate ]; then
  echo "📦 .venv ortamı etkinleştiriliyor..."
  source .venv/bin/activate
fi

echo "📦 Node.js modülleri yükleniyor..."
if [ ! -f package.json ]; then npm init -y >/dev/null; fi
npm install --save-dev \\
  hardhat@^2.22.0 \\
  @nomicfoundation/hardhat-toolbox@^4.0.0 \\
  @nomicfoundation/hardhat-verify@^2.0.0 \\
  @openzeppelin/hardhat-upgrades@^3.0.0 \\
  dotenv@^16.4.0
npm install \\
  @openzeppelin/contracts@4.9.6 \\
  @openzeppelin/contracts-upgradeable@4.9.6
{extra_tron}
echo "🐍 Python audit araçları (opsiyonel)..."
pip3 install --upgrade pip setuptools wheel || true
pip3 install slither-analyzer mythril || true
pip3 install markdown pdfkit matplotlib || true
pip3 install -r backend/requirements.txt 2>/dev/null || pip3 install requests flask pycryptodome || true

if ! command -v forge >/dev/null 2>&1; then
  echo "🔨 Foundry kuruluyor..."
  curl -L https://foundry.paradigm.xyz | bash || true
  export PATH="$HOME/.foundry/bin:$PATH"
  foundryup || true
fi

npm install -g @eth-scribble/scribble || true

echo "✅ Kurulum tamamlandı."
"""


def build_hardhat_config(cfg: dict) -> str:
    networks = cfg["networks_evm"]
    pragma_v = cfg["pragma_version"]
    use_uups = cfg["include_uups"]

    network_blocks = []
    for nid in networks:
        meta = CHAINS[nid]
        if not meta["evm"]:
            continue
        network_blocks.append(f"""    {nid}: {{
      url: process.env.{nid.upper()}_RPC || "{meta['rpc']}",
      chainId: {meta['chain_id']},
      accounts: ACCOUNTS
    }}""")

    upgrades_require = "require(\"@openzeppelin/hardhat-upgrades\");" if use_uups else ""

    return f"""require("@nomicfoundation/hardhat-toolbox");
require("@nomicfoundation/hardhat-verify");
{upgrades_require}
require("dotenv").config();

const PRIVATE_KEY = process.env.PRIVATE_KEY || "0x" + "0".repeat(64);
const PRIVATE_KEY_VALID = /^0x[0-9a-fA-F]{{64}}$/.test(PRIVATE_KEY) && PRIVATE_KEY !== "0x" + "0".repeat(64);
const ACCOUNTS = PRIVATE_KEY_VALID ? [PRIVATE_KEY] : [];

module.exports = {{
  solidity: {{
    version: "{pragma_v}",
    settings: {{
      optimizer: {{ enabled: true, runs: 200 }},
      viaIR: true
    }}
  }},
  paths: {{
    sources:   "./contracts",
    tests:     "./test",
    cache:     "./cache",
    artifacts: "./artifacts"
  }},
  networks: {{
    hardhat: {{ chainId: 31337 }},
{",".join(network_blocks)}
  }},
  // V2 Unified Etherscan API: tek key (etherscan.io'dan al) BSC + ETH + Polygon + Arb + Base + ... hepsinde çalışır.
  // https://docs.etherscan.io/etherscan-v2
  etherscan: {{
    apiKey: process.env.ETHERSCAN_API_KEY || ""
  }},
  sourcify: {{
    enabled: false
  }}
}};
"""


def build_create2_factory(cfg: dict) -> str:
    """Reusable CREATE2 factory contract."""
    return f"""// SPDX-License-Identifier: {cfg["license"]}
pragma solidity {cfg["pragma_version"]};

/**
 * @title Create2Factory
 * @notice Aynı bytecode + aynı salt + aynı factory ile EVM'de deterministik adres üretir.
 *         Cross-chain (BSC, ETH, Polygon, Arbitrum, Base) aynı factory deploy edilirse,
 *         aynı (salt, initCode) ile aynı kontrat adresine deploy edilir.
 */
contract Create2Factory {{
    event Deployed(address indexed addr, bytes32 indexed salt);

    /// @notice initCode (bytecode + ABI-encoded constructor args) ve salt ile deploy.
    function deploy(bytes32 salt, bytes memory initCode) external payable returns (address addr) {{
        require(initCode.length != 0, "initCode empty");
        assembly {{
            addr := create2(callvalue(), add(initCode, 0x20), mload(initCode), salt)
            if iszero(extcodesize(addr)) {{ revert(0, 0) }}
        }}
        emit Deployed(addr, salt);
    }}

    /// @notice Deploy etmeden önce hangi adrese ineceğini hesaplar.
    function computeAddress(bytes32 salt, bytes32 initCodeHash) external view returns (address) {{
        return address(uint160(uint256(keccak256(abi.encodePacked(
            bytes1(0xff), address(this), salt, initCodeHash
        )))));
    }}
}}
"""


def build_create2_deploy_script(cfg: dict) -> str:
    contract_id = cfg["contract_id"]
    is_uups = cfg["include_uups"]
    constructor_args = "" if is_uups else "admin, mintTo, initialDexExempt"
    dex_parse = (
        ""
        if is_uups
        else """  const initialDexExempt = (process.env.INITIAL_DEX_EXEMPT || "").split(/[,\\n]+/).map(s => s.trim()).filter(s => /^0x[0-9a-fA-F]{40}$/i.test(s)).map(s => ethers.getAddress(s));
"""
    )
    constructor_note = (
        "  // UUPS implementation constructor parametre almaz (sadece _disableInitializers)\n"
        "  // initialize() proxy üzerinden çağrılacak; aşağıda örnek var.\n"
        if is_uups else
        "  // Constructor: admin, mintTo, initialDexExempt (INITIAL_DEX_EXEMPT env, virgülle adresler)\n"
    )
    # Canonical Deterministic Deployment Proxy (BSC, ETH, Polygon, Arb, Base, Avalanche, Optimism vb.)
    # https://github.com/Arachnid/deterministic-deployment-proxy
    return f"""const {{ ethers }} = require("hardhat");
const fs = require("fs");
const path = require("path");

/**
 * CREATE2 deterministic deploy.
 *
 * .env değişkenleri:
 *   FACTORY_ADDRESS  → Create2Factory'nin deploy edilmiş adresi (yoksa otomatik deploy edilir)
 *   CREATE2_SALT     → 32-byte hex (0x prefix'li). Boşsa rastgele üretilir.
 *   ADMIN_ADDRESS    → Token admin (boşsa deployer)
 *   MINT_TO_ADDRESS  → Initial supply alıcısı (boşsa admin)
 */
async function main() {{
  const [deployer] = await ethers.getSigners();
  const adminEnv = process.env.ADMIN_ADDRESS;
  const mintToEnv = process.env.MINT_TO_ADDRESS;
  const admin = adminEnv && adminEnv.startsWith("0x") ? adminEnv : deployer.address;
  const mintTo = mintToEnv && mintToEnv.startsWith("0x") ? mintToEnv : admin;
{dex_parse}
  console.log("👤 Deployer:", deployer.address);
  console.log("🔑 Admin:   ", admin);
  console.log("💰 Mint to: ", mintTo);

  // 1) Factory: canonical Deterministic Deployment Proxy (varsayılan) veya custom.
  //    BSC + ETH + Polygon + Arbitrum + Base + Avalanche + Optimism + ... hepsinde aynı adres.
  const CANONICAL_FACTORY = "0x4e59b44847b379578588920cA78FbF26c0B4956C";
  const factoryAddr = process.env.FACTORY_ADDRESS || CANONICAL_FACTORY;
  console.log("🏭 Factory:", factoryAddr, factoryAddr === CANONICAL_FACTORY ? "(canonical)" : "(custom)");

  // 2) initCode + salt
{constructor_note}  const Token = await ethers.getContractFactory("{contract_id}");
  const deployTx = await Token.getDeployTransaction({constructor_args});
  const initCode = deployTx.data;

  const salt = process.env.CREATE2_SALT
    ? process.env.CREATE2_SALT
    : "0x" + require("crypto").randomBytes(32).toString("hex");
  console.log("🧂 Salt:", salt);

  // 3) Adresi önceden hesapla
  const initCodeHash = ethers.keccak256(initCode);
  const predicted = ethers.getCreate2Address(factoryAddr, salt, initCodeHash);
  console.log("📍 Predicted address:", predicted);

  // 4) Deploy: canonical factory raw transaction (data = salt || initCode)
  const callData = ethers.concat([salt, initCode]);
  const tx = await deployer.sendTransaction({{
    to: factoryAddr,
    data: callData,
  }});
  const receipt = await tx.wait();
  console.log("✅ {contract_id} deployed to:", predicted);
  console.log("   tx hash:", receipt.hash);

  const code = await ethers.provider.getCode(predicted);
  if (code === "0x") {{
    console.error("❌ Beklenen adreste kod bulunamadı! Salt/factory/initCode hash'ini kontrol et.");
    process.exit(1);
  }}

  const net = await ethers.provider.getNetwork();
  fs.mkdirSync(path.join(__dirname, "..", "deployments"), {{ recursive: true }});
  fs.writeFileSync(
    path.join(__dirname, "..", "deployments", `${{Number(net.chainId)}}-create2.json`),
    JSON.stringify({{
      network: net.name,
      chainId: Number(net.chainId),
      factory: factoryAddr,
      salt,
      address: predicted,
      txHash: receipt.hash,
      admin, mintTo,
      deployer: deployer.address,
      timestamp: new Date().toISOString()
    }}, null, 2)
  );
}}

main().catch((err) => {{ console.error(err); process.exitCode = 1; }});
"""


def build_predict_address_script(cfg: dict) -> str:
    contract_id = cfg["contract_id"]
    is_uups = cfg["include_uups"]
    constructor_args = "" if is_uups else "admin, mintTo, initialDexExempt"
    dex_parse = (
        ""
        if is_uups
        else """
  const initialDexExempt = (process.env.INITIAL_DEX_EXEMPT || "").split(/[,\\n]+/).map(s => s.trim()).filter(s => /^0x[0-9a-fA-F]{40}$/i.test(s)).map(s => ethers.getAddress(s));"""
    )
    return f"""const {{ ethers }} = require("hardhat");

/**
 * Deploy ETMEDEN, hangi adrese düşeceğini hesaplar.
 *
 * Modlar:
 *   1) CREATE     → deployer + nonce'a göre
 *   2) CREATE2    → factory + salt + initCode'a göre
 *
 * .env:
 *   PREDICT_MODE      = "create" | "create2"  (default: create)
 *   DEPLOYER_ADDRESS  → CREATE için
 *   DEPLOYER_NONCE    → CREATE için (default: cüzdanın güncel nonce'u)
 *   FACTORY_ADDRESS   → CREATE2 için
 *   CREATE2_SALT      → CREATE2 için
 *   ADMIN_ADDRESS / MINT_TO_ADDRESS → constructor parametreleri
 *   INITIAL_DEX_EXEMPT → virgülle DEX muaf adresleri (CREATE2 initCode için)
 */
async function main() {{
  const mode = (process.env.PREDICT_MODE || "create").toLowerCase();
  const [signer] = await ethers.getSigners();

  const admin  = process.env.ADMIN_ADDRESS  || signer.address;
  const mintTo = process.env.MINT_TO_ADDRESS || admin;{dex_parse}

  if (mode === "create") {{
    const deployerAddr = process.env.DEPLOYER_ADDRESS || signer.address;
    const nonce = process.env.DEPLOYER_NONCE
      ? Number(process.env.DEPLOYER_NONCE)
      : await ethers.provider.getTransactionCount(deployerAddr);
    const predicted = ethers.getCreateAddress({{ from: deployerAddr, nonce }});
    console.log("📐 CREATE prediction");
    console.log("  Deployer:", deployerAddr);
    console.log("  Nonce:   ", nonce);
    console.log("  Address: ", predicted);
    return;
  }}

  // CREATE2
  const CANONICAL_FACTORY = "0x4e59b44847b379578588920cA78FbF26c0B4956C";
  const factoryAddr = process.env.FACTORY_ADDRESS || CANONICAL_FACTORY;
  const salt = process.env.CREATE2_SALT;
  if (!salt) throw new Error("CREATE2_SALT gerekli");

  const Token = await ethers.getContractFactory("{contract_id}");
  const deployTx = await Token.getDeployTransaction({constructor_args});
  const initCodeHash = ethers.keccak256(deployTx.data);

  const predicted = ethers.getCreate2Address(factoryAddr, salt, initCodeHash);
  console.log("📐 CREATE2 prediction");
  console.log("  Factory:      ", factoryAddr);
  console.log("  Salt:         ", salt);
  console.log("  initCodeHash: ", initCodeHash);
  console.log("  Address:      ", predicted);
}}

main().catch((err) => {{ console.error(err); process.exitCode = 1; }});
"""


def build_vanity_miner_script(cfg: dict) -> str:
    contract_id = cfg["contract_id"]
    is_uups = cfg["include_uups"]
    constructor_args = "" if is_uups else "admin, mintTo, initialDexExempt"
    dex_parse = (
        ""
        if is_uups
        else """

  const initialDexExempt = (process.env.INITIAL_DEX_EXEMPT || "").split(/[,\\n]+/).map(s => s.trim()).filter(s => /^0x[0-9a-fA-F]{40}$/i.test(s)).map(s => ethers.getAddress(s));"""
    )
    return f"""const {{ ethers }} = require("hardhat");
const crypto = require("crypto");

/**
 * Vanity address miner — CREATE2 salt'ını brute-force ederek
 * istenen prefix/suffix'e uyan adresi bulur.
 *
 * Kullanım:
 *   FACTORY_ADDRESS=0x... VANITY_PREFIX=c0ffee VANITY_SUFFIX=dead \\
 *     npx hardhat run scripts/vanity_miner.js --network hardhat
 *
 * Notlar:
 *   - Prefix/suffix lowercase hex; "0x" yazma.
 *   - 4-5 karakter prefix saniye-dakika; 6-7 karakter dakika-saat;
 *     8+ saat-gün sürer. Tam adres eşleşmesi (40 karakter) imkansız.
 */
async function main() {{
  const [signer] = await ethers.getSigners();
  // Canonical Deterministic Deployment Proxy (BSC, ETH, Polygon, Arb, Base, Avalanche, ...)
  const CANONICAL_FACTORY = "0x4e59b44847b379578588920cA78FbF26c0B4956C";
  const factoryAddr = process.env.FACTORY_ADDRESS || CANONICAL_FACTORY;

  const prefix = (process.env.VANITY_PREFIX || "").toLowerCase();
  const suffix = (process.env.VANITY_SUFFIX || "").toLowerCase();
  if (!prefix && !suffix) throw new Error("VANITY_PREFIX veya VANITY_SUFFIX şart");
  if (!/^[0-9a-f]*$/.test(prefix)) throw new Error("Prefix hex olmalı");
  if (!/^[0-9a-f]*$/.test(suffix)) throw new Error("Suffix hex olmalı");

  const admin  = process.env.ADMIN_ADDRESS  || signer.address;
  const mintTo = process.env.MINT_TO_ADDRESS || admin;{dex_parse}

  const Token = await ethers.getContractFactory("{contract_id}");
  const deployTx = await Token.getDeployTransaction({constructor_args});
  const initCodeHash = ethers.keccak256(deployTx.data);

  console.log("⛏️  Vanity mining...");
  console.log("  Factory:    ", factoryAddr, factoryAddr === CANONICAL_FACTORY ? "(canonical)" : "(custom)");
  console.log("  Prefix:     ", prefix || "(any)");
  console.log("  Suffix:     ", suffix || "(any)");
  console.log("  initCodeHash:", initCodeHash);

  let attempts = 0;
  const start = Date.now();
  while (true) {{
    const salt = "0x" + crypto.randomBytes(32).toString("hex");
    const addr = ethers.getCreate2Address(factoryAddr, salt, initCodeHash).toLowerCase();
    const body = addr.slice(2);
    attempts++;
    if (
      (!prefix || body.startsWith(prefix))
      && (!suffix || body.endsWith(suffix))
    ) {{
      const elapsed = ((Date.now() - start) / 1000).toFixed(1);
      console.log(`\\n🎯 Bulundu! (${{attempts}} deneme, ${{elapsed}}s)`);
      console.log("  Salt:    ", salt);
      console.log("  Address: ", ethers.getAddress(addr));
      console.log("\\nDeploy için:");
      console.log(`  FACTORY_ADDRESS=${{factoryAddr}} CREATE2_SALT=${{salt}} \\\\`);
      console.log(`    npx hardhat run scripts/deploy-create2.js --network <NET>`);
      return;
    }}
    if (attempts % 50000 === 0) {{
      const rate = Math.round(attempts / ((Date.now() - start) / 1000));
      console.log(`  ${{attempts}} deneme (${{rate}}/s)...`);
    }}
  }}
}}

main().catch((err) => {{ console.error(err); process.exitCode = 1; }});
"""


def build_tronbox_config(cfg: dict) -> str:
    pragma_v = cfg["pragma_version"]
    return f"""module.exports = {{
  networks: {{
    mainnet: {{
      privateKey: process.env.PRIVATE_KEY_MAINNET,
      userFeePercentage: 100,
      feeLimit: 1_000_000_000,
      fullHost: 'https://api.trongrid.io',
      network_id: '1'
    }},
    shasta: {{
      privateKey: process.env.PRIVATE_KEY_SHASTA,
      userFeePercentage: 50,
      feeLimit: 1_000_000_000,
      fullHost: 'https://api.shasta.trongrid.io',
      network_id: '2'
    }},
    nile: {{
      privateKey: process.env.PRIVATE_KEY_NILE,
      userFeePercentage: 100,
      feeLimit: 1_000_000_000,
      fullHost: 'https://nile.trongrid.io',
      network_id: '3'
    }}
  }},
  compilers: {{
    solc: {{
      version: '{pragma_v}',
      optimizer: {{ enabled: true, runs: 200 }}
    }}
  }}
}};
"""


def build_tron_migrations(cfg: dict, folder: str) -> None:
    contract_id = cfg["contract_id"]
    pragma_v = cfg["pragma_version"]
    license_id = cfg["license"]

    write_file(os.path.join(folder, "contracts", "Migrations.sol"), f"""// SPDX-License-Identifier: {license_id}
pragma solidity {pragma_v};

contract Migrations {{
    address public owner;
    uint256 public last_completed_migration;

    modifier restricted() {{
        require(msg.sender == owner, "restricted");
        _;
    }}

    constructor() {{
        owner = msg.sender;
    }}

    function setCompleted(uint256 completed) external restricted {{
        last_completed_migration = completed;
    }}
}}
""")

    write_file(os.path.join(folder, "migrations", "1_initial_migration.js"), """const Migrations = artifacts.require("Migrations");

module.exports = function (deployer) {
  deployer.deploy(Migrations);
};
""")

    write_file(os.path.join(folder, "migrations", "2_deploy_token.js"), f"""const Token = artifacts.require("{contract_id}");

module.exports = async function (deployer, network, accounts) {{
  // ADMIN_ADDRESS / MINT_TO_ADDRESS env'den; yoksa deployer
  const admin  = process.env.ADMIN_ADDRESS  || accounts[0];
  const mintTo = process.env.MINT_TO_ADDRESS || admin;

  console.log("👤 Deployer:", accounts[0]);
  console.log("🔑 Admin:   ", admin);
  console.log("💰 Mint to: ", mintTo);

  await deployer.deploy(Token, admin, mintTo, []);
  const token = await Token.deployed();
  console.log("✅ {contract_id} deployed to:", token.address);
}};
""")


def build_deploy_script(cfg: dict) -> str:
    contract_id = cfg["contract_id"]
    auto_verify = cfg["auto_verify"]
    is_uups = cfg["include_uups"]
    multi_dex_gate = _multi_dex_deploy_gate_js()

    admin_arg = '''const adminEnv = process.env.ADMIN_ADDRESS;
  const admin = adminEnv && adminEnv.startsWith("0x") ? adminEnv : deployer.address;
  const mintToEnv = process.env.MINT_TO_ADDRESS;
  const mintTo = mintToEnv && mintToEnv.startsWith("0x") ? mintToEnv : admin;
  const initialDexExempt = (process.env.INITIAL_DEX_EXEMPT || "").split(/[,\\n]+/).map(s => s.trim()).filter(s => /^0x[0-9a-fA-F]{40}$/i.test(s)).map(s => ethers.getAddress(s));'''

    if auto_verify:
        if is_uups:
            verify_block = """
  if (process.env.AUTO_VERIFY === "true") {
    console.log("⏳ Verify... (60s bekleyip kontrol edilecek)");
    await new Promise(r => setTimeout(r, 60_000));
    try {
      // UUPS: implementation'ın constructor'ı parametresizdir
      await hre.run("verify:verify", { address: implAddress, constructorArguments: [] });
      console.log("✅ Verify tamamlandı.");
    } catch (e) { console.warn("⚠️ Verify hatası:", e.message || e); }
  }"""
        else:
            verify_block = """
  if (process.env.AUTO_VERIFY === "true") {
    console.log("⏳ Verify... (60s bekleyip kontrol edilecek)");
    await new Promise(r => setTimeout(r, 60_000));
    try {
      await hre.run("verify:verify", { address, constructorArguments: [admin, mintTo, initialDexExempt] });
      console.log("✅ Verify tamamlandı.");
    } catch (e) { console.warn("⚠️ Verify hatası:", e.message || e); }
  }"""
    else:
        verify_block = ""

    if is_uups:
        return f"""const {{ ethers, upgrades }} = require("hardhat");
const hre = require("hardhat");
const fs = require("fs");
const path = require("path");

async function main() {{
  const [deployer] = await ethers.getSigners();
  console.log("👤 Deployer:", deployer.address);

  {admin_arg}
  console.log("🔑 Admin:   ", admin);
  console.log("💰 Mint to: ", mintTo);

  const Factory = await ethers.getContractFactory("{contract_id}");
  console.log("🚀 UUPS proxy deploy ediliyor...");
  const proxy = await upgrades.deployProxy(
    Factory,
    [admin, mintTo, initialDexExempt],
    {{ kind: "uups", initializer: "initialize" }}
  );
  await proxy.waitForDeployment();

  const proxyAddress = await proxy.getAddress();
  const implAddress  = await upgrades.erc1967.getImplementationAddress(proxyAddress);
  const address = proxyAddress;

  console.log("✅ Proxy:         ", proxyAddress);
  console.log("✅ Implementation:", implAddress);

  const net = await ethers.provider.getNetwork();
  fs.mkdirSync(path.join(__dirname, "..", "deployments"), {{ recursive: true }});
  fs.writeFileSync(
    path.join(__dirname, "..", "deployments", `${{Number(net.chainId)}}.json`),
    JSON.stringify({{
      network: net.name,
      chainId: Number(net.chainId),
      proxy: proxyAddress,
      implementation: implAddress,
      admin, mintTo,
      initialDexExempt,
      deployer: deployer.address,
      timestamp: new Date().toISOString()
    }}, null, 2)
  );
{verify_block}
{multi_dex_gate}
}}

main().catch((err) => {{ console.error(err); process.exitCode = 1; }});
"""
    return f"""const {{ ethers }} = require("hardhat");
const hre = require("hardhat");
const fs = require("fs");
const path = require("path");

async function main() {{
  const [deployer] = await ethers.getSigners();
  console.log("👤 Deployer:", deployer.address);

  {admin_arg}
  console.log("🔑 Admin:   ", admin);
  console.log("💰 Mint to: ", mintTo);

  const Factory = await ethers.getContractFactory("{contract_id}");
  const token = await Factory.deploy(admin, mintTo, initialDexExempt);
  await token.waitForDeployment();
  const address = await token.getAddress();
  let implAddress;

  console.log("✅ {contract_id} deployed to:", address);

  const net = await ethers.provider.getNetwork();
  fs.mkdirSync(path.join(__dirname, "..", "deployments"), {{ recursive: true }});
  fs.writeFileSync(
    path.join(__dirname, "..", "deployments", `${{Number(net.chainId)}}.json`),
    JSON.stringify({{
      network: net.name,
      chainId: Number(net.chainId),
      address,
      admin, mintTo,
      initialDexExempt,
      deployer: deployer.address,
      timestamp: new Date().toISOString()
    }}, null, 2)
  );
{verify_block}
{multi_dex_gate}
}}

main().catch((err) => {{ console.error(err); process.exitCode = 1; }});
"""


# -------------------------- Test Templates --------------------------

def _deploy_block(cfg: dict, signers_decl: str) -> str:
    contract_id = cfg["contract_id"]
    if cfg["include_uups"]:
        return f"""    const Factory = await ethers.getContractFactory("{contract_id}");
    {signers_decl}
    const {{ upgrades }} = require("hardhat");
    token = await upgrades.deployProxy(Factory, [owner.address, owner.address, []], {{ kind: "uups", initializer: "initialize" }});
    await token.waitForDeployment();"""
    return f"""    const Factory = await ethers.getContractFactory("{contract_id}");
    {signers_decl}
    token = await Factory.deploy(owner.address, owner.address, []);
    await token.waitForDeployment();"""


def build_main_test(cfg: dict) -> str:
    contract_id = cfg["contract_id"]
    name = cfg["name"]
    symbol = cfg["symbol"]
    decimals = cfg["decimals"]
    initial_supply = cfg["total_supply"]
    cap_supply = cfg["cap_supply"]
    trading_flag = cfg["trading_flag"]
    deploy = _deploy_block(cfg, "[owner, alice, bob, carol] = await ethers.getSigners();")

    enable_trading = "    if (!(await token.tradingEnabled())) await token.enableTrading();" if trading_flag else ""
    initial_supply_num = cfg["total_supply"]

    if cap_supply == initial_supply_num:
        cap_test = f"""  it("cap dolu, mint revert eder (fixed supply davranışı)", async function () {{
    const MINTER_ROLE = await token.MINTER_ROLE();
    expect(await token.hasRole(MINTER_ROLE, owner.address)).to.equal(true);
    await expect(token.mint(owner.address, 1)).to.be.reverted;
  }});

  it("burn sonrası mint çalışır", async function () {{
    const amount = ethers.parseUnits("1000", {decimals});
    await token.burn(amount);
    await token.mint(alice.address, amount);
    expect(await token.balanceOf(alice.address)).to.equal(amount);
  }});"""
    else:
        cap_test = f"""  it("cap > initial; mint cap'e kadar çalışır (uint256.max yok)", async function () {{
    const cap = await token.cap();
    const supply = await token.totalSupply();
    expect(cap).to.be.lt(ethers.MaxUint256);
    const headroom = cap - supply;
    if (headroom > 0n) {{
      await token.mint(alice.address, headroom);
    }}
    await expect(token.mint(alice.address, 1)).to.be.reverted;
  }});"""

    return f"""const {{ expect }} = require("chai");
const {{ ethers }} = require("hardhat");

describe("{contract_id} - core", function () {{
  let token, owner, alice, bob, carol;

  beforeEach(async function () {{
{deploy}
    await token.connect(owner).setAntibotConfig(false, 0);
{enable_trading}
  }});

  it("metadata doğru", async function () {{
    expect(await token.name()).to.equal("{name}");
    expect(await token.symbol()).to.equal("{symbol}");
    expect(await token.decimals()).to.equal({decimals});
    const expectedSupply = ethers.parseUnits("{initial_supply}", {decimals});
    expect(await token.totalSupply()).to.equal(expectedSupply);
    expect(await token.balanceOf(owner.address)).to.equal(expectedSupply);
  }});

  it("transfer çalışır", async function () {{
    const amount = ethers.parseUnits("100", {decimals});
    await token.transfer(alice.address, amount);
    expect(await token.balanceOf(alice.address)).to.equal(amount);
  }});

  it("pause transferleri durdurur", async function () {{
    await token.pause();
    await expect(token.transfer(alice.address, 1)).to.be.reverted;
    await token.unpause();
    await token.transfer(alice.address, 1);
  }});

  it("blacklist transferi engeller", async function () {{
    await token.blacklist(alice.address, true);
    await expect(token.transfer(alice.address, 1)).to.be.reverted;
    await token.blacklist(alice.address, false);
    await token.transfer(alice.address, 1);
  }});

{cap_test}
}});
"""


def build_fee_test(cfg: dict) -> str:
    contract_id = cfg["contract_id"]
    decimals = cfg["decimals"]
    trading_flag = cfg["trading_flag"]
    deploy = _deploy_block(cfg, "[owner, alice, bob, feeWallet] = await ethers.getSigners();")
    enable_trading = "    if (!(await token.tradingEnabled())) await token.enableTrading();" if trading_flag else ""

    return f"""const {{ expect }} = require("chai");
const {{ ethers }} = require("hardhat");

describe("{contract_id} - fee & rescue & burn-fee", function () {{
  let token, owner, alice, bob, feeWallet;

  beforeEach(async function () {{
{deploy}
    await token.connect(owner).setAntibotConfig(false, 0);
    // Init'te fee/burn-fee 0 olmayabilir; testlerin temiz başlaması için reset
    await token.connect(owner).setFee(0, owner.address);
    await token.connect(owner).setBurnFee(0);
{enable_trading}
  }});

  it("fee max %5 ile sınırlı", async function () {{
    await expect(token.setFee(501, owner.address)).to.be.reverted;
    await token.setFee(500, owner.address);
  }});

  it("fee transferden kesilir, doğru hedefe gider", async function () {{
    const amount = ethers.parseUnits("10000", {decimals});
    await token.setFee(100, feeWallet.address); // %1
    await token.setFeeExempt(owner.address, false);

    await token.transfer(alice.address, amount);
    const fee = (amount * 100n) / 10000n;
    expect(await token.balanceOf(alice.address)).to.equal(amount - fee);
    expect(await token.balanceOf(feeWallet.address)).to.equal(fee);
  }});

  it("burn fee miktarı supply'dan düşer", async function () {{
    const amount = ethers.parseUnits("10000", {decimals});
    await token.setBurnFee(50); // %0.5
    await token.setFeeExempt(owner.address, false);

    const supplyBefore = await token.totalSupply();
    await token.transfer(alice.address, amount);
    const supplyAfter = await token.totalSupply();

    const burnAmount = (amount * 50n) / 10000n;
    expect(supplyBefore - supplyAfter).to.equal(burnAmount);
    expect(await token.balanceOf(alice.address)).to.equal(amount - burnAmount);
  }});

  it("rescueTokens kontratın kendi tokenini rescue edemez", async function () {{
    const tokenAddr = await token.getAddress();
    await expect(token.rescueTokens(tokenAddr, owner.address, 1)).to.be.reverted;
  }});
}});
"""


def build_antibot_test(cfg: dict) -> str:
    contract_id = cfg["contract_id"]
    decimals = cfg["decimals"]
    trading_flag = cfg["trading_flag"]
    deploy = _deploy_block(cfg, "[owner, alice, bob] = await ethers.getSigners();")
    enable_trading = "    if (!(await token.tradingEnabled())) await token.enableTrading();" if trading_flag else ""

    return f"""const {{ expect }} = require("chai");
const {{ ethers }} = require("hardhat");

describe("{contract_id} - antibot", function () {{
  let token, owner, alice, bob;

  beforeEach(async function () {{
{deploy}
    // Init'te fee/burn-fee 0 olmayabilir; antibot delay matematiğini bozmamak için reset
    await token.connect(owner).setFee(0, owner.address);
    await token.connect(owner).setBurnFee(0);
{enable_trading}
  }});

  it("anti-bot delay devrede; exempt olmayan iki transfer arka arkaya patlar", async function () {{
    const amount = ethers.parseUnits("100", {decimals});
    await token.transfer(alice.address, amount * 2n);
    await token.connect(alice).transfer(bob.address, amount);
    await expect(
      token.connect(alice).transfer(bob.address, 1)
    ).to.be.reverted;
  }});

  it("admin antibot'u kapatabilir", async function () {{
    await token.setAntibotConfig(false, 0);
    const amount = ethers.parseUnits("10", {decimals});
    await token.transfer(alice.address, amount * 2n);
    await token.connect(alice).transfer(bob.address, amount);
    await token.connect(alice).transfer(bob.address, 1);
  }});
}});
"""


def build_advanced_test(cfg: dict) -> str:
    contract_id = cfg["contract_id"]
    decimals = cfg["decimals"]
    deploy = _deploy_block(cfg, "[owner, alice, bob] = await ethers.getSigners();")

    return f"""const {{ expect }} = require("chai");
const {{ ethers }} = require("hardhat");

describe("{contract_id} - trading flag & limits & whitelist", function () {{
  let token, owner, alice, bob;

  beforeEach(async function () {{
{deploy}
    await token.connect(owner).setAntibotConfig(false, 0);
    // Init'te fee/burn-fee 0 olmayabilir; testlerin temiz başlaması için reset
    await token.connect(owner).setFee(0, owner.address);
    await token.connect(owner).setBurnFee(0);
  }});

  it("trading kapalıyken whitelisted dışında transfer revert eder", async function () {{
    const amount = ethers.parseUnits("100", {decimals});
    await token.transfer(alice.address, amount); // owner->alice OK (owner exempt)

    if (!(await token.tradingEnabled())) {{
      // alice -> bob başarısız (alice owner değil, whitelisted değil)
      await expect(token.connect(alice).transfer(bob.address, 1)).to.be.reverted;

      await token.setWhitelist(alice.address, true);
      await token.connect(alice).transfer(bob.address, 1); // şimdi geçer

      await token.enableTrading();
    }} else {{
      await token.connect(alice).transfer(bob.address, 1);
    }}
  }});

  it("max-tx limit aşılırsa revert eder (alice -> bob)", async function () {{
    if ((await token.tradingEnabled()) === false) await token.enableTrading();
    const limit = ethers.parseUnits("10", {decimals});
    // owner -> alice (owner muaf, sınırsız aktarım yapabilir)
    await token.transfer(alice.address, limit * 5n);

    await token.setMaxLimits(limit, 0);
    await token.setAntibotConfig(false, 0);

    // alice limit'i aşacak şekilde gönderirse revert
    await expect(token.connect(alice).transfer(bob.address, limit + 1n)).to.be.reverted;
    await token.connect(alice).transfer(bob.address, limit);
  }});

  it("max-wallet limit aşılırsa revert eder (alice -> bob)", async function () {{
    if ((await token.tradingEnabled()) === false) await token.enableTrading();
    const wlimit = ethers.parseUnits("100", {decimals});
    await token.transfer(alice.address, wlimit * 3n);

    await token.setMaxLimits(0, wlimit);
    await token.setAntibotConfig(false, 0);

    // bob bakiyesi 0; tam wlimit kadar al → OK
    await token.connect(alice).transfer(bob.address, wlimit);
    // sonraki 1 wei → wallet limit aşar → revert
    await expect(token.connect(alice).transfer(bob.address, 1)).to.be.reverted;
  }});

  it("priceUSD ve tokenURI okunabilir, admin güncelleyebilir", async function () {{
    const initialPrice = await token.priceUSD();
    expect(initialPrice).to.be.a("bigint");
    await token.setPriceUSD(150_000_000n); // $1.50
    expect(await token.priceUSD()).to.equal(150_000_000n);

    await token.setTokenURI("ipfs://QmTestCid");
    expect(await token.tokenURI()).to.equal("ipfs://QmTestCid");
  }});
}});
"""


# -------------------------- Audit / Misc Templates --------------------------

def build_audit_runner(cfg: dict) -> str:
    contract_id = cfg["contract_id"]
    return f"""\"\"\"Audit runner: Hardhat + Slither + (opsiyonel) Mythril/Echidna/Foundry.\"\"\"

import argparse
import json
import os
import shutil
import subprocess


def run(cmd, env=None):
    print(f"$ {{' '.join(cmd)}}")
    return subprocess.run(cmd, env=env, capture_output=True, text=True)


def run_hardhat():
    print("🧪 Hardhat testleri çalışıyor...")
    r = run(["npx", "hardhat", "test"])
    print(r.stdout or r.stderr)
    return r.stdout + r.stderr


def run_slither():
    if shutil.which("slither") is None:
        return "⚠️ Slither yüklü değil."
    print("🔍 Slither başlatılıyor...")
    r = run(["slither", "contracts/{contract_id}.sol"])
    out = r.stdout + r.stderr
    print(out)
    return out


def run_mythril():
    if shutil.which("myth") is None:
        return "⚠️ Mythril yüklü değil."
    print("🛡️ Mythril analizi çalışıyor...")
    r = run(["myth", "analyze", "contracts-audit/{contract_id}.sol",
             "--solv", "{cfg['pragma_version']}", "--max-depth", "30",
             "--execution-timeout", "60"])
    out = r.stdout + r.stderr
    print(out)
    return out


def run_echidna():
    binary = "echidna" if shutil.which("echidna") else "echidna-test" if shutil.which("echidna-test") else None
    if binary is None:
        return "⚠️ Echidna yüklü değil."
    print("🧪 Echidna testleri çalışıyor...")
    r = run([binary, "contracts-audit/{contract_id}.sol", "--config", "audit/echidna.yaml"])
    print(r.stdout)
    return r.stdout + r.stderr


def run_foundry():
    if shutil.which("forge") is None:
        return "⚠️ Foundry yüklü değil."
    print("🔬 Foundry testleri çalışıyor...")
    r = run(["forge", "test"])
    print(r.stdout)
    return r.stdout + r.stderr


def write_summary(outputs):
    os.makedirs("audit", exist_ok=True)
    with open("audit/test_results.json", "w", encoding="utf-8") as f:
        json.dump(outputs, f, indent=2)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--fast", action="store_true")
    parser.add_argument("--full", action="store_true")
    args = parser.parse_args()

    outputs = {{}}
    if args.fast or not args.full:
        outputs["hardhat"] = run_hardhat()
        outputs["slither"] = run_slither()
    if args.full:
        outputs["mythril"]  = run_mythril()
        outputs["echidna"]  = run_echidna()
        outputs["foundry"]  = run_foundry()

    write_summary(outputs)
    print("📄 Sonuçlar: audit/test_results.json")


if __name__ == "__main__":
    main()
"""


def build_audit_report_md(cfg: dict) -> str:
    extras = []
    if cfg["include_mythril"]:   extras.append("- Mythril (symbolic)")
    if cfg["include_manticore"]: extras.append("- Manticore (symbolic)")
    if cfg["include_tenderly"]:  extras.append("- Tenderly (runtime)")
    extras_str = "\n".join(extras) if extras else "- (none extra)"

    return f"""# Audit Report: {cfg["name"]} ({cfg["symbol"]})

## Overview
- Contract:        `{cfg["contract_id"]}`
- Decimals:        {cfg["decimals"]}
- Initial supply:  {cfg["total_supply"]}
- Mint cap politikası:  {describe_cap_human(cfg)}
- Varlık sınıfı:   {cfg.get("asset_class", "volatile")}
- Pragma:          `{cfg["pragma_version"]}`
- Variant:         {"UUPS Upgradeable" if cfg["include_uups"] else "Standalone"}
- Target chain(s): {cfg["network_choice"]}

## Tools
- Slither (static analysis)
- Hardhat unit tests
- Foundry fuzz tests
- Echidna property tests
{extras_str}

## Security Properties
- Pausable (`whenNotPaused`) enforced in `_beforeTokenTransfer`.
- Blacklist (both `from` and `to`).
- Anti-bot (configurable, exempt list).
- Trading-enabled gate (until `enableTrading()` only owner / whitelisted).
- Max-tx / max-wallet limits (with exemption).
- Burn-fee + transfer-fee (each capped at 5%).
- `rescueTokens` / `rescueETH` use SafeERC20 + ReentrancyGuard.
- `mint(...)` yalnızca `MINTER_ROLE` ile ve `ERC20Capped.cap()` sınırına kadar (somut cap; `uint256.max` yok).
- Granular roles: MINTER, PAUSER, BLACKLIST, FEE, LIMIT{', SNAPSHOT' if cfg['include_snapshot'] else ''}{', UPGRADER' if cfg['include_uups'] else ''}.
- Ownable2Step.

## How to Run
```bash
python3 audit_runner.py --full
```
"""


def build_readme(cfg: dict) -> str:
    contract_id = cfg["contract_id"]
    is_tron = cfg["is_tron"]
    networks = cfg["networks_evm"]
    network_cmds = []
    for nid in networks:
        meta = CHAINS[nid]
        network_cmds.append(f"npx hardhat run scripts/deploy.js --network {nid}    # {meta['label']}")
    network_section = "\n".join(network_cmds) if network_cmds else "# (No EVM networks selected)"

    tron_section = """
### Tron deploy (TronBox)
```bash
# .env içine PRIVATE_KEY_SHASTA / PRIVATE_KEY_NILE / PRIVATE_KEY_MAINNET koy
tronbox compile
tronbox migrate --network shasta   # testnet
tronbox migrate --network mainnet  # canlı
```
""" if is_tron else ""

    socials = []
    if cfg["website"]:  socials.append(f"- Website:  {cfg['website']}")
    if cfg["twitter"]:  socials.append(f"- Twitter:  {cfg['twitter']}")
    if cfg["telegram"]: socials.append(f"- Telegram: {cfg['telegram']}")
    if cfg["discord"]:  socials.append(f"- Discord:  {cfg['discord']}")
    socials_str = "\n".join(socials) if socials else "_(set via metadata)_"

    return f"""# {cfg["name"]} ({cfg["symbol"]})

Ultra-secure ERC20 / BEP20 / TRC20 token, OpenZeppelin v4.9.6 üzerinde.

## Genel
- Token Adı:        **{cfg["name"]}**
- Sembol:           **{cfg["symbol"]}**
- Solidity ID:      `{contract_id}`
- Decimals:         {cfg["decimals"]}
- Initial Supply:   {cfg["total_supply"]} (× 10^{cfg["decimals"]})
- Cap / mint politikası:  {describe_cap_human(cfg)}
- Varlık sınıfı:        {cfg.get("asset_class", "volatile")}
- Lisans:           {cfg["license"]}
- Variant:          {"UUPS Upgradeable" if cfg["include_uups"] else "Non-Upgradeable"}
- Target chain(s):  {cfg["network_choice"]}
- Pragma:           `{cfg["pragma_version"]}`

## Sosyaller
{socials_str}

## Özellikler
- ERC20Capped, ERC20Burnable, Pausable, Ownable2Step, AccessControl, ReentrancyGuard
- Anti-bot (admin tarafından kapatılabilir, exempt mapping)
- Fee-on-Transfer (max %5, feeExempt mapping)
- Burn-on-Transfer fee (max %5)
- Trading-enabled gate (`enableTrading()` çağrılana kadar sadece owner/whitelisted)
- Whitelist (mapping, batch fonksiyonu var)
- Max-tx / Max-wallet limits (limitExempt mapping)
- SafeERC20 + nonReentrant rescueTokens / rescueETH
{"- ERC20Permit (EIP-2612)" if cfg["include_permit"] else ""}
{"- ERC20Snapshot (SNAPSHOT_ROLE)" if cfg["include_snapshot"] else ""}
{"- UUPS Proxy (initialize() pattern, _disableInitializers, UPGRADER_ROLE)" if cfg["include_uups"] else ""}

## Kurulum
```bash
bash setup.sh
```

## Test
```bash
npx hardhat test
```

## Deploy (EVM)
```bash
cp .env.example .env  # PRIVATE_KEY + ADMIN_ADDRESS + MINT_TO_ADDRESS + API key'ler
{network_section}
```
{tron_section}
## Verify
```bash
npx hardhat verify --network <NETWORK> <DEPLOYED_ADDRESS>
```
(`AUTO_VERIFY=true` env varsa deploy script otomatik çağırır.)

## Belirli adres / cüzdan kontrolü

### 1) Initial supply'ı belirli bir cüzdana gönder
`.env`'e `MINT_TO_ADDRESS=0x...` ekle. Deploy script constructor'a (UUPS'da `initialize`'a) bunu geçer.
`ADMIN_ADDRESS=0x...` de aynı şekilde — multisig önerilir.

### 2) Belirli bir cüzdandan deploy (deployer = ben)
`.env`'e o cüzdanın `PRIVATE_KEY=0x...`'ini koy. Deployer = bu adres olur.
Kontrat adresi yine bu adres + nonce kombinasyonundan **deterministik** üretilir.

### 3) Aynı adres BSC + ETH + Polygon... (CROSS-CHAIN)
CREATE2 ile aynı `factory + salt + bytecode` her zincirde aynı kontrat adresine düşer.
```bash
# Tek seferlik factory deploy (her zincirde aynı şekilde)
FACTORY_ADDRESS= npx hardhat run scripts/deploy-create2.js --network bsc
# Sonraki ağlarda aynı FACTORY_ADDRESS + CREATE2_SALT kullan:
FACTORY_ADDRESS=0x... CREATE2_SALT=0x... npx hardhat run scripts/deploy-create2.js --network ethereum
```

### 4) Vanity adres üret (prefix/suffix eşle)
```bash
FACTORY_ADDRESS=0x... VANITY_PREFIX=c0ffee VANITY_SUFFIX=dead \
  npx hardhat run scripts/vanity_miner.js --network hardhat
```
Bulunan `salt`'ı `CREATE2_SALT` olarak deploy-create2.js'e ver.

### 5) Adresi deploy ETMEDEN gör
```bash
PREDICT_MODE=create  DEPLOYER_ADDRESS=0x... DEPLOYER_NONCE=5 \
  npx hardhat run scripts/predict-address.js --network bsc

PREDICT_MODE=create2 FACTORY_ADDRESS=0x... CREATE2_SALT=0x... \
  npx hardhat run scripts/predict-address.js --network bsc
```

> **Önemli**: 40-karakter tam bir hedef adresi (`0x4be3...07db4` gibi) tutturmak
> matematiksel olarak 2^160 olasılık demektir; vanity miner ile sadece **prefix/suffix**
> eşlemesi yapılabilir (6-8 karakter mantıklı sınır).

## Multi-DEX Oracle Consensus (ZORUNLU)

Gölge (paralel) RPC'lerin BscScan'de olmayan uydurma kontratları import etmesine karşı:

- `backend/multi_dex_verifier.py` — PancakeSwap / Uniswap / SunSwap Factory **getPair ↔ CREATE2 hash**
- `scripts/deploy.js` deploy sonrası otomatik kapı (`MULTI_DEX_VERIFY=1`)
- `backend/api.py` — cüzdan/dApp REST: `POST /api/verify`

```bash
python3 backend/multi_dex_verifier.py --chain bsc --address 0xYourToken
TOKEN_ADDRESS=0x... npx hardhat run scripts/verify-multi-dex.js --network bsc
npm run backend:api   # dApp için
```

Detay: [docs/MULTI_DEX_VERIFICATION.md](./docs/MULTI_DEX_VERIFICATION.md)

## Audit
```bash
python3 audit_runner.py --fast    # Hardhat + Slither
python3 audit_runner.py --full    # + Mythril + Echidna + Foundry
```

## Güvenlik Notları
1. **Admin = Multisig**: DEFAULT_ADMIN_ROLE ve owner bir Gnosis Safe + TimelockController olmalı.
2. **Trading açma**: `enableTrading()` çağrılmadan owner/whitelisted dışı kimse transfer yapamaz (eğer trading-flag aktifse).
3. **Anti-bot launch window**: Listing sonrası 24-48h içinde `setAntibotConfig(false, 0)`.
4. **CEX/DEX exempt**: Hot wallet'lere `setFeeExempt`, `setAntibotExempt`, `setLimitExempt`.
5. **UUPS upgrade**: `UPGRADER_ROLE` sadece audit edilmiş, timelock arkasındaki adres olmalı.

## Yasal & Branding
- "{cfg["symbol"]}" sembolü Tether / başka marka koruması nedeniyle bazı borsalarda reddedilebilir.
"""


def build_metadata_files(cfg: dict, metadata_dir: str) -> None:
    write_file(os.path.join(metadata_dir, "tokenlist.json"), json.dumps({
        "name": cfg["name"],
        "symbol": cfg["symbol"],
        "decimals": cfg["decimals"],
        "total_supply": str(cfg["total_supply"]),
        "asset_class": cfg.get("asset_class", "volatile"),
        "cap_supply": str(cfg["cap_supply"]),
        "cap_multiplier": cfg["cap_multiplier"],
        "max_cap_units": MAX_CAP_SUPPLY_UNITS,
        "cap_policy": describe_cap_human(cfg),
        "description": "Ultra Secure BEP20/TRC20 Token with audit-ready configuration."
    }, indent=2))

    cap_feat = "Capped mint (min(initial×mult, 1B tokens); no uint256.max)"
    features = ["Pausable", "Blacklist", "Burnable", cap_feat,
                "AccessControl", "Anti-bot (configurable)",
                "Fee-on-Transfer (capped)", "Burn-on-Transfer (capped)",
                "Trading-enabled gate", "Whitelist", "Max-tx / Max-wallet limits"]
    if cfg["include_permit"]:   features.append("Permit (EIP-2612)")
    if cfg["include_snapshot"]: features.append("Snapshot")
    if cfg["include_uups"]:     features.append("UUPS Upgradeable")

    write_file(os.path.join(metadata_dir, "info.json"), json.dumps({
        "project": cfg["name"],
        "symbol": cfg["symbol"],
        "decimals": cfg["decimals"],
        "license": cfg["license"],
        "network_choice": cfg["network_choice"],
        "website":  cfg["website"],
        "twitter":  cfg["twitter"],
        "telegram": cfg["telegram"],
        "discord":  cfg["discord"],
        "logo_url": cfg["logo_url"],
        "features": features,
        "audit": "Slither, Echidna, Foundry, Mythril ready.",
        "management": "AccessControl + Ownable2Step. Multisig recommended."
    }, indent=2))

    write_file(os.path.join(metadata_dir, "project.json"), json.dumps({
        "project_name": cfg["name"],
        "symbol": cfg["symbol"],
        "network": cfg["network_choice"],
        "token_type": "BEP20" if "bsc" in cfg["network_choice"].lower() else ("TRC20" if cfg["is_tron"] else "ERC20"),
        "audit": True,
        "verified": False,
        "status": "pending-deploy",
        "features": features
    }, indent=2))


def build_audit_configs(cfg: dict, audit_dir: str) -> None:
    contract_id = cfg["contract_id"]
    pragma_v = cfg["pragma_version"]

    write_file(os.path.join(audit_dir, "slither.config.json"), json.dumps({
        "exclude_informational": False,
        "exclude_low": False,
        "filter_paths": "node_modules"
    }, indent=2))

    write_file(os.path.join(audit_dir, "echidna.yaml"), f"""test_mode: assertion
testLimit: 50000
contract: {contract_id}
""")

    write_file(os.path.join(audit_dir, "foundry.toml"), f"""[profile.default]
src = 'contracts'
out = 'out'
libs = ['lib', 'node_modules']
optimizer = true
optimizer_runs = 200
evm_version = '{("paris" if pragma_v == "0.8.18" else "shanghai")}'
fuzz = {{ runs = 1000 }}
remappings = [
  '@openzeppelin/contracts/=node_modules/@openzeppelin/contracts/',
  '@openzeppelin/contracts-upgradeable/=node_modules/@openzeppelin/contracts-upgradeable/'
]
""")

    write_file(os.path.join(audit_dir, "mythril.json"), json.dumps({
        "solc": pragma_v,
        "execution-timeout": 300,
        "max-depth": 30,
        "loop-bound": 10,
        "enable-assertions": True
    }, indent=2))


# -------------------------- Multi-DEX Security (shadow RPC gate) --------------------------

_GENERATOR_DIR = os.path.dirname(os.path.abspath(__file__))


def _multi_dex_deploy_gate_js() -> str:
    """Deploy sonrası zorunlu Python multi_dex_verifier kapısı."""
    return """
  // --- Zorunlu Multi-DEX / RPC konsensüs kapısı (gölge RPC import savunması) ---
  if (process.env.MULTI_DEX_VERIFY !== "0") {
    const { execSync } = require("child_process");
    const chainByNetwork = {
      bsc: "bsc", bscTestnet: "bsc",
      mainnet: "ethereum", sepolia: "ethereum",
      ethereum: "ethereum",
      polygon: "ethereum", arbitrum: "ethereum", base: "ethereum",
    };
    const chain = chainByNetwork[hre.network.name] || "bsc";
    const verifyAddr = address;
    console.log("🛡️ Multi-DEX oracle consensus (Factory pair hash + RPC consensus)...");
    try {
      execSync(
        `python3 backend/multi_dex_verifier.py --chain ${chain} --address ${verifyAddr}`,
        { stdio: "inherit", cwd: path.join(__dirname, "..") }
      );
      console.log("✅ Multi-DEX doğrulaması geçti.");
    } catch (e) {
      console.error("🚨 Deploy reddedildi: sahte/gölge kontrat veya DEX factory uyuşmazlığı.");
      process.exit(1);
    }
  } else {
    console.warn("⚠️ MULTI_DEX_VERIFY=0 — gölge RPC koruması devre dışı (önerilmez).");
  }
"""


def build_verify_multi_dex_js() -> str:
    return """const hre = require("hardhat");
const { execSync } = require("child_process");
const path = require("path");

async function main() {
  const address = process.env.TOKEN_ADDRESS || process.env.CONTRACT_ADDRESS;
  if (!address || !/^0x[0-9a-fA-F]{40}$/.test(address)) {
    throw new Error("TOKEN_ADDRESS veya CONTRACT_ADDRESS (0x…) gerekli.");
  }
  const chainByNetwork = {
    bsc: "bsc", bscTestnet: "bsc",
    mainnet: "ethereum", sepolia: "ethereum",
    ethereum: "ethereum",
    polygon: "ethereum", arbitrum: "ethereum", base: "ethereum",
  };
  const net = await hre.ethers.provider.getNetwork();
  const chain = chainByNetwork[hre.network.name] || process.env.CHAIN || "bsc";
  console.log("Network:", hre.network.name, "chainId:", Number(net.chainId));
  console.log("Token:", address, "→ chain profile:", chain);
  execSync(
    `python3 backend/multi_dex_verifier.py --chain ${chain} --address ${address} --json`,
    { stdio: "inherit", cwd: path.join(__dirname, "..") }
  );
}

main().catch((e) => { console.error(e); process.exit(1); });
"""


def build_backend_api_py() -> str:
    return '''#!/usr/bin/env python3
"""Minimal backend API — cüzdan/dApp katmanı Multi-DEX doğrulaması."""
import os
from flask import Flask, jsonify, request

from multi_dex_verifier import verify_contract_on_multi_dex

app = Flask(__name__)


@app.get("/health")
def health():
    return jsonify({"status": "ok", "service": "multi-dex-oracle"})


@app.post("/api/verify")
def api_verify():
    """
    Body JSON: { "chain": "bsc", "address": "0x...", "shadow_rpc": "..." (opsiyonel) }
    Gölge RPC'lerin uydurma kontrat import'unu reddeder; resmi DEX factory pair hash zorunlu.
    """
    body = request.get_json(force=True, silent=True) or {}
    chain = (body.get("chain") or request.args.get("chain") or "bsc").strip()
    address = (body.get("address") or request.args.get("address") or "").strip()
    shadow = body.get("shadow_rpc") or os.environ.get("SHADOW_RPC_URL", "")
    if not address:
        return jsonify({"ok": False, "error": "address required"}), 400
    report = verify_contract_on_multi_dex(
        chain,
        address,
        shadow_rpc=shadow or None,
        strict_explorer=os.environ.get("MULTI_DEX_STRICT_EXPLORER", "0") == "1",
        require_liquidity_pair=os.environ.get("MULTI_DEX_REQUIRE_PAIR", "0") == "1",
    )
    return jsonify(report.to_dict()), (200 if report.ok else 403)


if __name__ == "__main__":
    port = int(os.environ.get("BACKEND_PORT", "8787"))
    app.run(host="127.0.0.1", port=port, debug=False)
'''


def build_multi_dex_docs_md(cfg: dict) -> str:
    sym = cfg["symbol"]
    return f"""# Multi-DEX Oracle Consensus — {sym}

Gölge (paralel) RPC'lerin BscScan'de olmayan **uydurma kontrat adreslerini** cüzdana
import etmesine karşı zorunlu savunma katmanı.

## Kontroller

1. **Resmi RPC** `eth_getCode` — bytecode var mı?
2. **Gölge RPC konsensüsü** (`SHADOW_RPC_URL`) — resmi ile aynı hash mi?
3. **Explorer indeksi** (BscScan/Etherscan) — sahte adres filtresi
4. **DEX Factory pair hash** — PancakeSwap / Uniswap / SunSwap `getPair` ↔ CREATE2 eşleşmesi

## CLI

```bash
python3 backend/multi_dex_verifier.py --chain bsc --address 0xYourToken
python3 backend/multi_dex_verifier.py --chain bsc --address 0x... --shadow-rpc https://shadow-rpc.example
npx hardhat run scripts/verify-multi-dex.js --network bsc
```

## Backend API (dApp / cüzdan)

```bash
pip install flask requests pycryptodome
python3 backend/api.py
curl -X POST http://127.0.0.1:8787/api/verify \\
  -H 'Content-Type: application/json' \\
  -d '{{"chain":"bsc","address":"0x..."}}'
```

## Deploy kapısı

`scripts/deploy.js` deploy sonrası **MULTI_DEX_VERIFY=0** olmadıkça otomatik çalışır.
Likidite henüz yoksa `MULTI_DEX_REQUIRE_PAIR=0` (varsayılan) bırakın.
"""


def build_multi_dex_security_files(cfg: dict, folder: str) -> None:
    """verify_contract_on_multi_dex.py → paket backend + API + script + docs."""
    backend_dir = os.path.join(folder, "backend")
    os.makedirs(backend_dir, exist_ok=True)

    src = os.path.join(_GENERATOR_DIR, "verify_contract_on_multi_dex.py")
    if os.path.isfile(src):
        shutil.copy2(src, os.path.join(backend_dir, "multi_dex_verifier.py"))
    else:
        write_file(
            os.path.join(backend_dir, "multi_dex_verifier.py"),
            "# multi_dex_verifier: verify_contract_on_multi_dex.py bulunamadı\\n",
        )

    write_file(os.path.join(backend_dir, "api.py"), build_backend_api_py(), executable=True)
    write_file(os.path.join(folder, "scripts", "verify-multi-dex.js"), build_verify_multi_dex_js())
    docs_dir = os.path.join(folder, "docs")
    os.makedirs(docs_dir, exist_ok=True)
    write_file(os.path.join(docs_dir, "MULTI_DEX_VERIFICATION.md"), build_multi_dex_docs_md(cfg))

    req_path = os.path.join(backend_dir, "requirements.txt")
    write_file(req_path, "requests>=2.31.0\\nflask>=3.0.0\\npycryptodome>=3.20.0\\n")


def build_dapp_files_with_verify(cfg: dict, folder: str) -> None:
    """React dApp + Multi-DEX doğrulama paneli (backend API ile konuşur)."""
    dapp_dir = os.path.join(folder, "frontend")
    api_port = "8787"
    write_file(os.path.join(dapp_dir, "README.md"), f"""# Frontend dApp — {cfg["symbol"]}

Vite + React. Token adresini backend Multi-DEX API ile doğrular.

```bash
# Terminal 1
pip install -r backend/requirements.txt
python3 backend/api.py

# Terminal 2
cd frontend && npm install && npm run dev
```
""")
    write_file(os.path.join(dapp_dir, "index.html"), """<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><title>Token dApp — Multi-DEX Verify</title></head>
<body><div id="root"></div><script type="module" src="/main.jsx"></script></body>
</html>
""")
    write_file(
        os.path.join(dapp_dir, "main.jsx"),
        f"""import React, {{ useState }} from 'react';
import ReactDOM from 'react-dom/client';

const API = import.meta.env.VITE_BACKEND_URL || 'http://127.0.0.1:{api_port}';

function App() {{
  const [chain, setChain] = useState('bsc');
  const [address, setAddress] = useState('');
  const [result, setResult] = useState(null);
  const [err, setErr] = useState('');

  async function verify() {{
    setErr('');
    setResult(null);
    try {{
      const r = await fetch(`${{API}}/api/verify`, {{
        method: 'POST',
        headers: {{ 'Content-Type': 'application/json' }},
        body: JSON.stringify({{ chain, address }}),
      }});
      const data = await r.json();
      setResult(data);
      if (!r.ok) setErr('Doğrulama reddedildi (gölge RPC / DEX factory).');
    }} catch (e) {{
      setErr(String(e));
    }}
  }}

  return (
    <div style={{ fontFamily: 'system-ui', maxWidth: 640, margin: '2rem auto', padding: 16 }}>
      <h1>{cfg["name"]} ({cfg["symbol"]})</h1>
      <p>Multi-DEX Oracle — resmi factory pair hash + gölge RPC konsensüsü.</p>
      <label>Chain<br/>
        <select value={{chain}} onChange={{e => setChain(e.target.value)}}>
          <option value="bsc">BSC</option>
          <option value="ethereum">Ethereum</option>
          <option value="tron">Tron</option>
        </select>
      </label>
      <br/><br/>
      <label>Token address<br/>
        <input style={{ width: '100%' }} value={{address}} onChange={{e => setAddress(e.target.value)}} placeholder="0x..." />
      </label>
      <br/><br/>
      <button onClick={{verify}}>Verify on Multi-DEX</button>
      {{err && <p style={{ color: 'crimson' }}>{{err}}</p>}}
      {{result && (
        <pre style={{ background: '#111', color: '#0f0', padding: 12, marginTop: 16 }}>
          {{JSON.stringify(result, null, 2)}}
        </pre>
      )}}
    </div>
  );
}}

ReactDOM.createRoot(document.getElementById('root')).render(<App />);
""",
    )
    write_file(
        os.path.join(dapp_dir, "package.json"),
        json.dumps(
            {
                "name": "ultra-secure-dapp",
                "version": "1.0.0",
                "private": True,
                "scripts": {"dev": "vite", "build": "vite build", "preview": "vite preview"},
                "dependencies": {"react": "^18.2.0", "react-dom": "^18.2.0"},
                "devDependencies": {"vite": "^5.0.0", "@vitejs/plugin-react": "^4.2.0"},
            },
            indent=2,
        ),
    )
    write_file(
        os.path.join(dapp_dir, "vite.config.js"),
        """import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
export default defineConfig({ plugins: [react()] });
""",
    )


# -------------------------- DAO / dApp / Audit Copy --------------------------

def build_dao_files(cfg: dict, folder: str) -> None:
    pragma_v = cfg["pragma_version"]
    license_id = cfg["license"]
    dao_dir = os.path.join(folder, "dao")
    write_file(os.path.join(dao_dir, "GovernorContract.sol"), f"""// SPDX-License-Identifier: {license_id}
pragma solidity {pragma_v};

import "@openzeppelin/contracts/governance/Governor.sol";
import "@openzeppelin/contracts/governance/extensions/GovernorSettings.sol";
import "@openzeppelin/contracts/governance/extensions/GovernorCountingSimple.sol";
import "@openzeppelin/contracts/governance/extensions/GovernorVotes.sol";
import "@openzeppelin/contracts/governance/extensions/GovernorVotesQuorumFraction.sol";
import "@openzeppelin/contracts/governance/extensions/GovernorTimelockControl.sol";

contract GovernorContract is
    Governor, GovernorSettings, GovernorCountingSimple,
    GovernorVotes, GovernorVotesQuorumFraction, GovernorTimelockControl
{{
    constructor(IVotes _token, TimelockController _timelock)
        Governor("GovernorContract")
        GovernorSettings(1, 45818, 0)
        GovernorVotes(_token)
        GovernorVotesQuorumFraction(4)
        GovernorTimelockControl(_timelock)
    {{}}
    function votingDelay() public view override(IGovernor, GovernorSettings) returns (uint256) {{ return super.votingDelay(); }}
    function votingPeriod() public view override(IGovernor, GovernorSettings) returns (uint256) {{ return super.votingPeriod(); }}
    function quorum(uint256 b) public view override(IGovernor, GovernorVotesQuorumFraction) returns (uint256) {{ return super.quorum(b); }}
    function state(uint256 p) public view override(Governor, GovernorTimelockControl) returns (ProposalState) {{ return super.state(p); }}
    function propose(address[] memory t, uint256[] memory v, bytes[] memory c, string memory d) public override(Governor, IGovernor) returns (uint256) {{ return super.propose(t, v, c, d); }}
    function proposalThreshold() public view override(Governor, GovernorSettings) returns (uint256) {{ return super.proposalThreshold(); }}
    function _execute(uint256 p, address[] memory t, uint256[] memory v, bytes[] memory c, bytes32 h) internal override(Governor, GovernorTimelockControl) {{ super._execute(p, t, v, c, h); }}
    function _cancel(address[] memory t, uint256[] memory v, bytes[] memory c, bytes32 h) internal override(Governor, GovernorTimelockControl) returns (uint256) {{ return super._cancel(t, v, c, h); }}
    function _executor() internal view override(Governor, GovernorTimelockControl) returns (address) {{ return super._executor(); }}
    function supportsInterface(bytes4 i) public view override(Governor, GovernorTimelockControl) returns (bool) {{ return super.supportsInterface(i); }}
}}
""")
    write_file(os.path.join(dao_dir, "TimelockController.sol"), f"""// SPDX-License-Identifier: {license_id}
pragma solidity {pragma_v};

import "@openzeppelin/contracts/governance/TimelockController.sol";
""")


def build_dapp_files(folder: str) -> None:
    dapp_dir = os.path.join(folder, "frontend")
    write_file(os.path.join(dapp_dir, "README.md"), """# Frontend dApp

Vite + React skeleton.

```bash
cd frontend && npm install && npm run dev
```
""")
    write_file(os.path.join(dapp_dir, "index.html"), """<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><title>dApp Interface</title></head>
<body><div id="root"></div><script type="module" src="/main.jsx"></script></body>
</html>
""")
    write_file(os.path.join(dapp_dir, "main.jsx"), """import React from 'react';
import ReactDOM from 'react-dom/client';
ReactDOM.createRoot(document.getElementById('root')).render(<h1>Welcome to your Token dApp</h1>);
""")
    write_file(os.path.join(dapp_dir, "package.json"), json.dumps({
        "name": "ultra-secure-dapp", "version": "1.0.0", "private": True,
        "scripts": {"dev": "vite", "build": "vite build", "preview": "vite preview"},
        "dependencies": {"react": "^18.2.0", "react-dom": "^18.2.0"},
        "devDependencies": {"vite": "^5.0.0", "@vitejs/plugin-react": "^4.2.0"}
    }, indent=2))
    write_file(os.path.join(dapp_dir, "vite.config.js"), """import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
export default defineConfig({ plugins: [react()] });
""")


def rewrite_imports_for_audit(code: str) -> str:
    code = re.sub(r'(^\s*import\s+")@openzeppelin/contracts/',
                  r'\1../node_modules/@openzeppelin/contracts/', code, flags=re.MULTILINE)
    code = re.sub(r'(^\s*import\s+")@openzeppelin/contracts-upgradeable/',
                  r'\1../node_modules/@openzeppelin/contracts-upgradeable/', code, flags=re.MULTILINE)
    return code


def render_audit_report(docs_dir: str, audit_md_path: str) -> None:
    try:
        import markdown
        with open(audit_md_path, "r", encoding="utf-8") as f:
            html_body = markdown.markdown(f.read())
        html_full = f"""<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>Audit Report</title></head>
<body>{html_body}</body></html>"""
        html_path = os.path.join(docs_dir, "audit_report.html")
        with open(html_path, "w", encoding="utf-8") as f:
            f.write(html_full)
        print(f"📄 HTML üretildi: {html_path}")
        try:
            import pdfkit
            pdfkit.from_file(html_path, os.path.join(docs_dir, "audit_report.pdf"))
            print("📄 PDF üretildi: docs/audit_report.pdf")
        except Exception as e:
            print(f"⚠️ PDF üretilemedi (wkhtmltopdf gerekli): {e}")
    except ImportError:
        print("⚠️ markdown modülü eksik. `pip install markdown` ile yükleyin.")
    except Exception as e:
        print(f"⚠️ Audit raporu render edilemedi: {e}")


# -------------------------- Config Collection --------------------------

def collect_config(*, chain_preset: str = "evm") -> dict:
    """İnteraktif yapılandırma.

    chain_preset:
      - \"evm\": BSC varsayılan (BEP20); ağ menüsü gösterilir.
      - \"tron\": TRC20; ağ Tron (Mainnet + Shasta) olarak sabitlenir.
    """
    if chain_preset not in ("evm", "tron"):
        chain_preset = "evm"
    print("=" * 70)
    if chain_preset == "tron":
        print(" Ultra Secure TRC20 Token Generator (Tron)")
    else:
        print(" Ultra Secure BEP20 / TRC20 / ERC20 Token Generator")
    print("=" * 70)

    print("\n[1/7] Token türü, metadata ve başlangıç arzı")
    print("  1 — Stablecoin: tipik 6 decimals, USD metadata ($1 hedefli) önerilir.")
    print("  2 — Volatil kripto: tipik 18 decimals, kur bilgisi borsalar/oracle ile.")
    asset_raw = input("  Varlık sınıfı [1=Stablecoin, 2=Volatil] [1]: ").strip() or "1"
    asset_class = "volatile" if asset_raw.startswith("2") else "stablecoin"

    chain_hint = (
        "(Varsayılan: TRC20 — "
        if chain_preset == "tron"
        else "(Varsayılan: BEP20 — "
    )
    print(f"  {chain_hint}{DEFAULT_BEP20_TOKEN_NAME} / {DEFAULT_BEP20_TOKEN_SYMBOL})")

    name = input(f"  Token adı [{DEFAULT_BEP20_TOKEN_NAME}]: ").strip() or DEFAULT_BEP20_TOKEN_NAME
    symbol_raw = (
        input(f"  Token sembolü [{DEFAULT_BEP20_TOKEN_SYMBOL}]: ").strip() or DEFAULT_BEP20_TOKEN_SYMBOL
    )

    sug_decimals = DEFAULT_DECIMALS_VOLATILE if asset_class == "volatile" else DEFAULT_DECIMALS_STABLECOIN
    decimals = parse_int(
        input(
            f"  Decimals (0–30; önerilen: {asset_class} → {sug_decimals}) [{sug_decimals}]: "
        ).strip()
        or str(sug_decimals),
        default=sug_decimals,
        min_v=0,
        max_v=30,
    )


    total_supply = parse_int(
        input(
            f"  Initial supply — deploy’da mint edilen token miktarı (tam sayı) [{DEFAULT_INITIAL_SUPPLY_UNITS:,}]: "
        ).strip()
        or str(DEFAULT_INITIAL_SUPPLY_UNITS),
        default=DEFAULT_INITIAL_SUPPLY_UNITS,
        min_v=1,
    )

    print(
        f"  Mint tavanı: min(initial × çarpan, {MAX_CAP_SUPPLY_UNITS:,} token) "
        f"— uint256.max kullanılmaz (MetaMask/Trust tarayıcı uyumu)."
    )
    cap_mult = parse_int(
        input(
            f"  Cap çarpanı — cap = min(initial × çarpan, {MAX_CAP_SUPPLY_UNITS:,}) "
            f"[{DEFAULT_CAP_MULTIPLIER}]: "
        ).strip()
        or str(DEFAULT_CAP_MULTIPLIER),
        default=DEFAULT_CAP_MULTIPLIER,
        min_v=1,
    )
    cap_supply = compute_cap_supply(total_supply, cap_mult)

    license_id = input("  Lisans (MIT/Apache-2.0/GPL-3.0/UNLICENSED) [MIT]: ").strip() or "MIT"

    print("\n[2/7] Network seçimi")
    if chain_preset == "tron":
        print("  TRC20 paketi — Tron (Mainnet + Shasta). EVM zinciri seçilmez.")
        network_choice = "tron"
        is_tron = True
        networks_evm = [n for n in NETWORK_PRESETS[network_choice] if CHAINS[n]["evm"]]
        pragma_version = "0.8.18"
    else:
        print("  (USDT.z için Enter = BSC Mainnet + Testnet)")
        for idx, (key, label) in enumerate(NETWORK_LABELS, start=1):
            print(f"  {idx}) {label}")
        raw = input("  Seçim [1=BSC]: ").strip() or "1"
        try:
            net_idx = int(raw) - 1
            net_idx = max(0, min(len(NETWORK_LABELS) - 1, net_idx))
        except Exception:
            net_idx = 0
        network_choice = NETWORK_LABELS[net_idx][0]
        is_tron = network_choice == "tron"
        networks_evm = [n for n in NETWORK_PRESETS[network_choice] if CHAINS[n]["evm"]]
        pragma_version = "0.8.18" if is_tron else "0.8.28"

    print("\n[3/7] Admin & deployment adresleri")
    admin_addr = input("  Admin/owner adresi (boş = deployer): ").strip()
    if admin_addr and not is_valid_eth_address(admin_addr) and not is_tron:
        print("    ⚠️ Geçersiz EVM adresi, yok sayılıyor.")
        admin_addr = ""
    mint_to = input("  Initial mint recipient (boş = admin): ").strip()
    if mint_to and not is_valid_eth_address(mint_to) and not is_tron:
        print("    ⚠️ Geçersiz EVM adresi, yok sayılıyor.")
        mint_to = ""

    print("\n[4/7] Fee, burn-fee ve anti-bot başlangıç ayarları")
    init_fee_bps = parse_int(input("  Başlangıç fee (basis points, 0-500) [0]: ") or "0", default=0, min_v=0, max_v=500)
    init_burn_fee_bps = parse_int(input("  Burn-on-transfer fee (basis points, 0-500) [0]: ") or "0", default=0, min_v=0, max_v=500)
    antibot_enabled = yes_no("  Anti-bot başlangıçta aktif olsun mu?", default=True)
    antibot_delay = parse_int(input("  Anti-bot delay saniye (0-3600) [60]: ") or "60", default=60, min_v=0, max_v=3600)

    print("\n[5/7] Gelişmiş özellikler (opt-in)")
    trading_flag = yes_no("  Trading-enabled flag (manuel açma ile launch koruması)?", default=False)
    enable_max_limits = yes_no("  Max-tx / max-wallet limitleri eklensin mi?", default=False)
    max_tx = 0
    max_wallet = 0
    if enable_max_limits:
        max_tx_tokens = parse_int(input("    Max tx (token adedi, 0=sınırsız): ") or "0", default=0, min_v=0)
        max_wallet_tokens = parse_int(input("    Max wallet (token adedi, 0=sınırsız): ") or "0", default=0, min_v=0)
        max_tx = max_tx_tokens * (10 ** decimals)
        max_wallet = max_wallet_tokens * (10 ** decimals)

    include_snapshot = yes_no("  Snapshot eklensin mi?", default=False)
    include_permit = yes_no("  Permit (EIP-2612) eklensin mi?", default=False)
    permit_version = "1"
    if include_permit:
        permit_version = input("    EIP-712 domain version [1]: ").strip() or "1"

    if is_tron:
        print("  ℹ️ Tron için UUPS desteği sınırlı; bu generator UUPS'u kapatır (manual proxy deploy gerekir).")
        include_uups = False
    else:
        include_uups = yes_no("  UUPS Upgradeable Proxy eklensin mi?", default=False)

    print("\n[6/7] Audit & ek araçlar")
    include_mythril   = yes_no("  Mythril script eklensin mi?", default=False)
    include_manticore = yes_no("  Manticore script eklensin mi?", default=False)
    include_tenderly  = yes_no("  Tenderly config eklensin mi?", default=False)
    include_dao       = yes_no("  DAO Governance dosyaları eklensin mi?", default=False)
    include_dapp      = yes_no("  Frontend dApp (React+Vite) eklensin mi?", default=False)
    include_timelock  = yes_no("  TimelockController dosyası eklensin mi?", default=False)

    print("\n[7/7] Metadata & branding (boş geçilebilir)")
    website  = input("  Website: ").strip()
    logo_url = input("  Logo URL: ").strip()
    twitter  = input("  Twitter: ").strip()
    telegram = input("  Telegram: ").strip()
    discord  = input("  Discord: ").strip()
    print("  ─ Kontrat-içi metadata (admin sonradan değiştirebilir) ─")
    print("    Cüzdanlar bunları doğrudan okumaz; CoinGecko/CMC/TrustWallet listing gerekir.")
    token_uri = input("  Token metadata URI (kontratta saklanır, ipfs://Qm... örn) [boş]: ").strip()

    price_def = 100_000_000 if asset_class == "stablecoin" else 0
    price_prompt = (
        str(100_000_000) if asset_class == "stablecoin"
        else "0 (bilgi amaçlı; volatilde genelde oracle/listing kullanılır)"
    )
    price_usd_e8 = parse_int(
        input(
            f"  Kontratta sabit görünen USD fiyat hint’i — 8 ondalık ($1 → 100000000) [{price_prompt if price_def == 100_000_000 else '0'}]: "
        ).strip()
        or (str(price_def) if asset_class == "stablecoin" else "0"),
        default=price_def,
        min_v=0,
    )
    auto_verify = yes_no("  Deploy sonrası otomatik verify aktif olsun mu?", default=True) if not is_tron else False

    contract_id = sanitize_solidity_identifier(symbol_raw + "Token")
    folder = sanitize_folder_name(symbol_raw) + "_UltraSecureToken"

    cfg = {
        "name": name,
        "symbol": symbol_raw,
        "contract_id": contract_id,
        "folder": folder,
        "decimals": decimals,
        "total_supply": total_supply,
        "cap_multiplier": cap_mult,
        "cap_supply": cap_supply,
        "asset_class": asset_class,
        "license": license_id,
        "pragma_version": pragma_version,
        "network_choice": network_choice,
        "networks_evm": networks_evm,
        "is_tron": is_tron,
        "admin_addr": admin_addr,
        "mint_to": mint_to,
        "init_fee_bps": init_fee_bps,
        "init_burn_fee_bps": init_burn_fee_bps,
        "antibot_enabled": antibot_enabled,
        "antibot_delay": antibot_delay,
        "trading_flag": trading_flag,
        "max_tx": max_tx,
        "max_wallet": max_wallet,
        "include_snapshot": include_snapshot,
        "include_permit": include_permit,
        "permit_version": permit_version,
        "include_uups": include_uups,
        "include_mythril": include_mythril,
        "include_manticore": include_manticore,
        "include_tenderly": include_tenderly,
        "include_dao": include_dao,
        "include_dapp": include_dapp,
        "include_timelock": include_timelock,
        "website": website,
        "logo_url": logo_url,
        "twitter": twitter,
        "telegram": telegram,
        "discord": discord,
        "token_uri": token_uri,
        "price_usd_e8": price_usd_e8,
        "auto_verify": auto_verify,
    }

    print("\n" + "=" * 70)
    print(" ÖZET")
    print("=" * 70)
    print(f"  Token:           {name} ({symbol_raw}), {decimals} decimals")
    print(f"  Varlık:          {asset_class}")
    print(f"  Initial supply: {total_supply:,}")
    print(f"  Cap / mint:      {describe_cap_human(cfg)}")
    print(f"  License:         {license_id}")
    print(f"  Pragma:          {pragma_version}")
    print(f"  Network:         {network_choice} → {networks_evm if not is_tron else ['tron','tronShasta']}")
    print(f"  Variant:         {'UUPS Upgradeable' if include_uups else 'Standalone'}")
    print(f"  Admin:           {admin_addr or '(deployer)'}")
    print(f"  Mint to:         {mint_to or '(admin)'}")
    print(f"  Initial fee:     {init_fee_bps} bps → {'(admin)'}")
    print(f"  Burn fee:        {init_burn_fee_bps} bps")
    print(f"  Anti-bot:        enabled={antibot_enabled}, delay={antibot_delay}s")
    print(f"  Trading flag:    {trading_flag}")
    print(f"  Max-tx / wallet: {max_tx} / {max_wallet}")
    print(f"  Token URI:       {token_uri or '(boş, sonra setTokenURI ile)'}")
    print(f"  Price USD:       {price_usd_e8} (= ${price_usd_e8 / 1e8:.4f})")
    extras = [f for f, on in [
        ("snapshot", include_snapshot), ("permit", include_permit),
        ("uups", include_uups), ("dao", include_dao), ("dapp", include_dapp),
        ("mythril", include_mythril), ("manticore", include_manticore),
        ("tenderly", include_tenderly), ("auto-verify", auto_verify),
    ] if on]
    print(f"  Extras:          {', '.join(extras) if extras else 'none'}")
    print(f"  Output folder:   {folder}/")
    print("=" * 70)

    if not yes_no("\nDevam edilsin mi?", default=True):
        print("İptal edildi.")
        sys.exit(0)

    return cfg


# -------------------------- Main --------------------------

def create_ultra_secure_token_package(cfg: dict) -> None:
    folder = cfg["folder"]
    contract_id = cfg["contract_id"]

    if os.path.exists(folder):
        print(f"⚠️ {folder} zaten var, içeriği üzerine yazılacak.")
    os.makedirs(folder, exist_ok=True)

    os.system(f"python3 -m venv {folder}/.venv >/dev/null 2>&1")

    # contracts/
    contract_code = (
        build_upgradeable_contract(cfg) if cfg["include_uups"]
        else build_non_upgradeable_contract(cfg)
    )
    contracts_dir = os.path.join(folder, "contracts")
    os.makedirs(contracts_dir, exist_ok=True)
    write_file(os.path.join(contracts_dir, f"{contract_id}.sol"), contract_code)

    # contracts-audit/ (relative imports)
    contracts_audit_dir = os.path.join(folder, "contracts-audit")
    os.makedirs(contracts_audit_dir, exist_ok=True)
    write_file(
        os.path.join(contracts_audit_dir, f"{contract_id}.sol"),
        rewrite_imports_for_audit(contract_code),
    )

    # Tron migrations
    if cfg["is_tron"]:
        build_tron_migrations(cfg, folder)
        write_file(os.path.join(folder, "tronbox-config.js"), build_tronbox_config(cfg))
        write_file(os.path.join(folder, "tronbox.js"), build_tronbox_config(cfg))

    # scripts/
    write_file(os.path.join(folder, "scripts", "deploy.js"), build_deploy_script(cfg))
    build_multi_dex_security_files(cfg, folder)
    # CREATE2 + adres tahmin + vanity miner (sadece EVM zincirler için anlamlı)
    if not cfg["is_tron"]:
        # Factory contract (contracts/ altına; Tron'da pragma uyumsuz olabilir, atlanır)
        write_file(os.path.join(folder, "contracts", "Create2Factory.sol"), build_create2_factory(cfg))
        write_file(os.path.join(folder, "scripts", "deploy-create2.js"), build_create2_deploy_script(cfg))
        write_file(os.path.join(folder, "scripts", "predict-address.js"), build_predict_address_script(cfg))
        write_file(os.path.join(folder, "scripts", "vanity_miner.js"), build_vanity_miner_script(cfg))

    # hardhat.config.js (yine üretilir, çünkü Tron'da bile testler Hardhat ile yapılır)
    write_file(os.path.join(folder, "hardhat.config.js"), build_hardhat_config(cfg))

    # package.json
    deploy_scripts = {
        "compile": "hardhat compile",
        "test": "hardhat test",
        "verify:multi-dex": "hardhat run scripts/verify-multi-dex.js --network bsc",
        "backend:api": "python3 backend/api.py",
    }
    for nid in cfg["networks_evm"]:
        deploy_scripts[f"deploy:{nid}"] = f"hardhat run scripts/deploy.js --network {nid}"
    if cfg["is_tron"]:
        deploy_scripts["deploy:tron-shasta"] = "tronbox migrate --network shasta"
        deploy_scripts["deploy:tron-mainnet"] = "tronbox migrate --network mainnet"
    if not cfg["is_tron"] and cfg["networks_evm"]:
        first_evm = cfg["networks_evm"][0]
        deploy_scripts["deploy:create2"]   = f"hardhat run scripts/deploy-create2.js --network {first_evm}"
        deploy_scripts["predict-address"]  = f"hardhat run scripts/predict-address.js --network {first_evm}"
        deploy_scripts["vanity-miner"]     = "hardhat run scripts/vanity_miner.js --network hardhat"

    write_file(os.path.join(folder, "package.json"), json.dumps({
        "name": cfg["folder"].lower(),
        "version": "1.0.0",
        "private": True,
        "scripts": deploy_scripts
    }, indent=2))

    # .gitignore / .env.example
    write_file(os.path.join(folder, ".gitignore"), """node_modules/
.env
artifacts/
cache/
out/
deployments/localhost/
.openzeppelin/
.venv/
""")
    env_lines = [
        "# Deployer",
        "PRIVATE_KEY=0xYOUR_PRIVATE_KEY",
        "",
        "# Token roles & initial mint hedefi",
        "ADMIN_ADDRESS=         # boş = deployer (DEFAULT_ADMIN_ROLE + Ownable owner)",
        "MINT_TO_ADDRESS=       # boş = admin (initial supply'ın gönderileceği adres)",
        "",
        "# V2 Unified Etherscan API Key (BSC + ETH + Polygon + Arb + Base hepsi için tek key)",
        "# https://etherscan.io/myapikey  (V2 API key)",
        "ETHERSCAN_API_KEY=YOUR_ETHERSCAN_V2_KEY",
        "",
        "# Auto-verify",
        "AUTO_VERIFY=true",
        "",
        "# Multi-DEX oracle consensus (ZORUNLU — gölge RPC / sahte kontrat savunması)",
        "MULTI_DEX_VERIFY=1          # 0 = kapıyı kapat (önerilmez)",
        "SHADOW_RPC_URL=             # Paralel/gölge RPC (resmi RPC ile karşılaştırılır)",
        "MULTI_DEX_STRICT_EXPLORER=0 # 1 = explorer indeksi zorunlu",
        "MULTI_DEX_REQUIRE_PAIR=0    # 1 = DEX'te likidite pair zorunlu (yeni deploy için 0)",
        "BACKEND_PORT=8787           # dApp → backend/api.py",
        "TOKEN_ADDRESS=              # verify-multi-dex.js için",
        "",
        "# CREATE2 deterministic / vanity deploy (opsiyonel)",
        "FACTORY_ADDRESS=0x4e59b44847b379578588920cA78FbF26c0B4956C  # Canonical (BSC, ETH, Polygon, Arb, Base ...)",
        "CREATE2_SALT=          # 0x prefix'li 32-byte hex; vanity miner çıktısı",
        "VANITY_PREFIX=         # örn: c0ffee  (vanity_miner için)",
        "VANITY_SUFFIX=         # örn: dead    (vanity_miner için)",
        "PREDICT_MODE=create    # 'create' veya 'create2' (predict-address için)",
        "",
        "# RPC endpoints (default'lar zaten OK)",
    ]
    for nid in cfg["networks_evm"]:
        meta = CHAINS[nid]
        env_lines.append(f"{nid.upper()}_RPC={meta['rpc']}")
    if cfg["is_tron"]:
        env_lines += [
            "",
            "# Tron",
            "PRIVATE_KEY_MAINNET=YOUR_TRON_PRIVATE_KEY",
            "PRIVATE_KEY_SHASTA=YOUR_TRON_TESTNET_PRIVATE_KEY",
            "PRIVATE_KEY_NILE=YOUR_TRON_TESTNET_PRIVATE_KEY",
        ]
    write_file(os.path.join(folder, ".env.example"), "\n".join(env_lines) + "\n")

    # setup.sh
    write_file(os.path.join(folder, "setup.sh"), build_setup_sh(cfg), executable=True)
    write_file(os.path.join(folder, "venv_activate.sh"),
               "#!/bin/bash\necho '📦 .venv aktifleştiriliyor...'\nsource .venv/bin/activate\n",
               executable=True)

    # tests/
    test_dir = os.path.join(folder, "test")
    os.makedirs(test_dir, exist_ok=True)
    write_file(os.path.join(test_dir, f"{contract_id}.test.js"), build_main_test(cfg))
    write_file(os.path.join(test_dir, f"{contract_id}.fee.test.js"), build_fee_test(cfg))
    write_file(os.path.join(test_dir, f"{contract_id}.antibot.test.js"), build_antibot_test(cfg))
    write_file(os.path.join(test_dir, f"{contract_id}.advanced.test.js"), build_advanced_test(cfg))

    # audit/
    audit_dir = os.path.join(folder, "audit")
    os.makedirs(audit_dir, exist_ok=True)
    build_audit_configs(cfg, audit_dir)

    if cfg["include_uups"]:
        fuzz_setup = (
            f"token = new {contract_id}();\n"
            f"        token.initialize(owner, owner, new address[](0));"
        )
    else:
        fuzz_setup = f"token = new {contract_id}(owner, owner, new address[](0));"

    write_file(os.path.join(audit_dir, "token_fuzz.t.sol"), f"""// SPDX-License-Identifier: {cfg["license"]}
pragma solidity {cfg["pragma_version"]};

import "forge-std/Test.sol";
import "../contracts/{contract_id}.sol";

contract TokenFuzzTest is Test {{
    {contract_id} token;
    address owner = address(this);

    function setUp() public {{
        {fuzz_setup}
        token.setAntibotConfig(false, 0);
    }}

    function testFuzz_TransferConservesSupply(address to, uint96 amount) public {{
        vm.assume(to != address(0) && to != address(token));
        uint256 supplyBefore = token.totalSupply();
        try token.transfer(to, uint256(amount)) returns (bool) {{}} catch {{}}
        assertEq(token.totalSupply(), supplyBefore);
    }}
}}
""")

    if cfg["include_mythril"]:
        write_file(os.path.join(audit_dir, "run_mythril.sh"), f"""#!/bin/bash
echo "🔍 Mythril analizi..."
myth analyze contracts-audit/{contract_id}.sol --solv {cfg["pragma_version"]} --max-depth 30 --execution-timeout 60
""", executable=True)

    if cfg["include_manticore"]:
        write_file(os.path.join(audit_dir, "manticore_test.py"), f"""\"\"\"Manticore EVM senaryosu (taslak).\"\"\"
from manticore.ethereum import ManticoreEVM
m = ManticoreEVM()
deployer = m.create_account(balance=10**18)
with open("contracts-audit/{contract_id}.sol") as f:
    src = f.read()
contract = m.solidity_create_contract(src, owner=deployer)
print("🧪 Manticore setup complete.")
""")

    if cfg["include_tenderly"]:
        write_file(os.path.join(audit_dir, "tenderly_config.json"), json.dumps({
            "project_slug": "your-project", "username": "your-username",
            "network": cfg["network_choice"], "contracts": ["0xYourTokenAddress"]
        }, indent=2))
        write_file(os.path.join(audit_dir, "tenderly_upload.sh"),
                   "#!/bin/bash\ntenderly login && tenderly push\n", executable=True)

    # metadata/
    metadata_dir = os.path.join(folder, "metadata")
    os.makedirs(metadata_dir, exist_ok=True)
    build_metadata_files(cfg, metadata_dir)

    # trustwallet_submission/
    tw_dir = os.path.join(folder, "trustwallet_submission")
    os.makedirs(tw_dir, exist_ok=True)
    write_file(os.path.join(tw_dir, "info.json"), json.dumps({
        "name": cfg["name"], "symbol": cfg["symbol"],
        "type": "BEP20" if "bsc" in cfg["network_choice"].lower() else ("TRC20" if cfg["is_tron"] else "ERC20"),
        "decimals": cfg["decimals"],
        "description": "Audit-ready, ultra-secure token.",
        "website": cfg["website"] or "https://example.com",
        "explorer": "https://bscscan.com/token/0xYourTokenAddress",
        "status": "active",
        "id": "bsc/0xYourTokenAddress"
    }, indent=2))

    # docs/
    docs_dir = os.path.join(folder, "docs")
    os.makedirs(docs_dir, exist_ok=True)
    write_file(os.path.join(docs_dir, "token_whitepaper.md"), f"""# {cfg["name"]} Whitepaper

## Özet
{cfg["name"]} ({cfg["symbol"]}) {cfg["network_choice"].upper()} üzerinde **{cfg["total_supply"]:,}** initial supply ile bir
{("BEP20" if "bsc" in cfg["network_choice"] else ("TRC20" if cfg["is_tron"] else "ERC20"))} tokendir. Profil: **{cfg.get("asset_class", "volatile")}**.

## Teknik
- Decimals: {cfg["decimals"]}
- Mint limiti / cap: {describe_cap_human(cfg)}
- Variant: {"UUPS Upgradeable" if cfg["include_uups"] else "Non-Upgradeable"}
- License: {cfg["license"]}
- Audit-ready: Slither, Echidna, Foundry, Mythril.
""")

    audit_md_path = os.path.join(docs_dir, "audit_report.md")
    write_file(audit_md_path, build_audit_report_md(cfg))
    render_audit_report(docs_dir, audit_md_path)

    write_file(os.path.join(docs_dir, "listing_checklist.md"), f"""# {cfg["symbol"]} Listing Checklist

## TrustWallet
- [ ] Logo (256×256 PNG)
- [ ] info.json metadata
- [ ] Web sitesi ve explorer linki

## CoinGecko / CoinMarketCap
- [ ] Verified contract
- [ ] Whitepaper linki
- [ ] Logo (512×512 PNG)
- [ ] Min. 2 DEX işlem hacmi
""")

    # README
    write_file(os.path.join(folder, "README.md"), build_readme(cfg))

    # run_coverage.sh
    write_file(os.path.join(folder, "run_coverage.sh"),
               "#!/bin/bash\nnpx hardhat coverage\n", executable=True)

    # audit_runner.py
    write_file(os.path.join(folder, "audit_runner.py"), build_audit_runner(cfg))

    # DAO / dApp
    if cfg["include_dao"]:
        build_dao_files(cfg, folder)
    if cfg["include_dapp"]:
        build_dapp_files_with_verify(cfg, folder)

    # ZIP
    if os.path.exists(folder + ".zip"):
        os.remove(folder + ".zip")
    shutil.make_archive(folder, "zip", folder)
    print(f"\n✅ Paket hazır: {folder}.zip")
    print(f"📁 Klasör:    {folder}/")
    print(f"⚙️  Kurulum:   cd {folder} && bash setup.sh")
    print(f"🧪 Test:      cd {folder} && npx hardhat test")
    if cfg["is_tron"]:
        print(f"🟥 Tron:      cd {folder} && tronbox migrate --network shasta")
    if cfg["networks_evm"]:
        first = cfg["networks_evm"][0]
        print(f"🚀 Deploy:    cd {folder} && npx hardhat run scripts/deploy.js --network {first}")


def create_ultra_secure_bep20() -> None:
    create_ultra_secure_token_package(collect_config(chain_preset="evm"))


if __name__ == "__main__":
    create_ultra_secure_bep20()
