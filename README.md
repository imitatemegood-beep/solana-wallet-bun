# Solana Wallet (MVP++)

Wallet CLI + mini API pentru Solana:
- BIP39/BIP44, keystore local criptat (scrypt + AES-GCM)
- Balance SOL, listare SPL
- Transfer SOL, Transfer SPL (ATA auto)
- FastAPI pentru integrare mobilă

## Setup local
```bash
python -m venv .venv
# Win: .\.venv\Scripts\activate
# Unix: source .venv/bin/activate
python -m pip install --upgrade pip wheel
python -m pip install -r requirements.txt
cp .env.example .env  # opțional
```

## CLI
```bash
python sol_wallet.py --help
python sol_wallet.py init
python sol_wallet.py addr
python sol_wallet.py balance
python sol_wallet.py tokens
python sol_wallet.py send-sol <DEST> 0.01
python sol_wallet.py send-spl <MINT> <DEST_OWNER> 5.0 6
```

## API (local)
```bash
python sol_wallet.py api
# GET http://127.0.0.1:8787/addr?password=<parola>
# GET http://127.0.0.1:8787/balance?password=<parola>
```

## Codex
- Agent internet access: **On**
- Domain allowlist: **Common dependencies**
- Additional allowed domains:
`api.mainnet-beta.solana.com, public-api.birdeye.so, quote-api.jup.ag, price.jup.ag, token.jup.ag, api.dexscreener.com`
- Allowed HTTP Methods: **All methods**
- Setup script: rulează `./setup.sh`

## Securitate
Nu încărca niciodată seed/chei în repo sau .env. Seed-ul rămâne doar local, criptat în `~/.solwallet/keystore.json`.
