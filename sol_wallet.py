#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Solana wallet (MVP++) inspirat de Solflare:
- BIP39 + BIP44 (m/44'/501'/account'/change/index)
- Keystore criptat local (scrypt + AES-GCM)
- Balance SOL, listează SPL token accounts
- Transfer SOL, transfer SPL (cu creare automată ATA)
- CLI (Typer) + mini API (FastAPI) pentru integrare mobilă

ATENȚIE: demo educațional. Nu trimite seed/chei pe rețea. Fără audit.
"""
import os
import json
import base64
import getpass
from pathlib import Path
from typing import List

from dotenv import load_dotenv
load_dotenv()

from rich import print, box
from rich.table import Table
from rich.prompt import Prompt, Confirm
import typer

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

from bip_utils import (
    Bip39MnemonicGenerator, Bip39SeedGenerator, Bip39WordsNum, Bip39MnemonicValidator,
    Bip44, Bip44Coins, Bip44Changes
)

from solana.rpc.api import Client
from solana.rpc.types import TxOpts
from solana.transaction import Transaction
from solana.system_program import TransferParams, transfer

from solders.keypair import Keypair
from solders.pubkey import Pubkey

from spl.token.instructions import (
    get_associated_token_address,
    create_associated_token_account,
    transfer_checked,
    TransferCheckedParams,
)
from spl.token.constants import TOKEN_PROGRAM_ID

app = typer.Typer(add_completion=False, no_args_is_help=True)
api_app = None  # construit dinamic

DEFAULT_RPC = os.environ.get("SOLANA_RPC_URL", "https://api.mainnet-beta.solana.com")
HOME = Path(os.environ.get("SOLWALLET_HOME", Path.home() / ".solwallet"))
HOME.mkdir(parents=True, exist_ok=True)
KEYSTORE = HOME / "keystore.json"

# ---------- Crypto utils (keystore) ----------
def _derive_key(password: str, salt: bytes) -> bytes:
    kdf = Scrypt(salt=salt, length=32, n=2**14, r=8, p=1)
    return kdf.derive(password.encode())

def encrypt_secret(data: bytes, password: str) -> dict:
    salt = os.urandom(16)
    key = _derive_key(password, salt)
    aes = AESGCM(key)
    nonce = os.urandom(12)
    ct = aes.encrypt(nonce, data, None)
    return {
        "kdf": "scrypt",
        "salt": base64.b64encode(salt).decode(),
        "nonce": base64.b64encode(nonce).decode(),
        "ciphertext": base64.b64encode(ct).decode(),
        "version": 1,
    }

def decrypt_secret(blob: dict, password: str) -> bytes:
    salt = base64.b64decode(blob["salt"])
    nonce = base64.b64decode(blob["nonce"])
    ct = base64.b64decode(blob["ciphertext"])
    key = _derive_key(password, salt)
    aes = AESGCM(key)
    return aes.decrypt(nonce, ct, None)

# ---------- Derivation (BIP39/44) ----------
def mnemonic_to_keypair(mnemonic: str, account: int = 0, change: int = 0, index: int = 0) -> Keypair:
    if not Bip39MnemonicValidator(mnemonic).Validate():
        raise ValueError("Mnemonic invalid.")
    seed = Bip39SeedGenerator(mnemonic).Generate()
    ctx = Bip44.FromSeed(seed, Bip44Coins.SOLANA).Purpose().Coin().Account(account).Change(Bip44Changes(change)).AddressIndex(index)
    priv_key_bytes = ctx.PrivateKey().RawCompressed().ToBytes()
    return Keypair.from_seed(priv_key_bytes)

def generate_mnemonic(words: int = 24) -> str:
    words_num = {12: Bip39WordsNum.WORDS_NUM_12, 24: Bip39WordsNum.WORDS_NUM_24}[words]
    return Bip39MnemonicGenerator().FromWordsNumber(words_num)

# ---------- Wallet core ----------
class Wallet:
    def __init__(self, rpc_url: str = DEFAULT_RPC):
        self.client = Client(rpc_url)

    def save_keystore(self, mnemonic: str, password: str):
        blob = encrypt_secret(mnemonic.encode(), password)
        KEYSTORE.write_text(json.dumps({"mnemonic": blob}, indent=2))
        try:
            os.chmod(KEYSTORE, 0o600)
        except Exception:
            pass

    def load_mnemonic(self, password: str) -> str:
        if not KEYSTORE.exists():
            raise FileNotFoundError("Nu există keystore. Creează/importă mai întâi.")
        data = json.loads(KEYSTORE.read_text())
        return decrypt_secret(data["mnemonic"], password).decode()

    def keypair_from_keystore(self, password: str, account: int = 0, change: int = 0, index: int = 0) -> Keypair:
        mnemonic = self.load_mnemonic(password)
        return mnemonic_to_keypair(mnemonic, account, change, index)

    # --- Queries ---
    def get_balance_sol(self, pubkey: Pubkey) -> float:
        lamports = self.client.get_balance(pubkey).value
        return lamports / 1_000_000_000

    def list_spl_accounts(self, owner: Pubkey) -> List[dict]:
        resp = self.client.get_token_accounts_by_owner_json_parsed(owner, {"programId": str(TOKEN_PROGRAM_ID)})
        out = []
        for item in (resp.value or []):
            info = item.account.data.parsed["info"]
            out.append({
                "mint": info["mint"],
                "amount": int(info["tokenAmount"]["amount"]),
                "decimals": int(info["tokenAmount"]["decimals"]),
                "ui_amount": float(info["tokenAmount"].get("uiAmount", 0.0)),
                "pubkey": str(item.pubkey),
            })
        return out

    # --- Transfers ---
    def transfer_sol(self, sender: Keypair, dest: Pubkey, sol: float, skip_preflight: bool=False) -> str:
        lamports = int(sol * 1_000_000_000)
        tx = Transaction().add(transfer(TransferParams(from_pubkey=sender.pubkey(), to_pubkey=dest, lamports=lamports)))
        resp = self.client.send_transaction(tx, sender, opts=TxOpts(skip_preflight=skip_preflight))
        return str(resp.value)

    def _ensure_ata_ix(self, owner: Pubkey, mint: Pubkey, payer: Pubkey):
        ata = get_associated_token_address(owner, mint)
        acc = self.client.get_account_info(ata)
        if acc.value is None:
            return create_associated_token_account(payer=payer, owner=owner, mint=mint), ata
        return None, ata

    def transfer_spl(self, sender: Keypair, dest_owner: Pubkey, mint: Pubkey, amount_ui: float, decimals: int, skip_preflight: bool=False) -> str:
        create_ix, dest_ata = self._ensure_ata_ix(dest_owner, mint, sender.pubkey())
        src_ata = get_associated_token_address(sender.pubkey(), mint)
        tx = Transaction()
        if create_ix:
            tx.add(create_ix)
        amt = int(round(amount_ui * (10 ** decimals)))
        tx.add(transfer_checked(TransferCheckedParams(
            program_id=TOKEN_PROGRAM_ID,
            source=src_ata,
            mint=mint,
            dest=dest_ata,
            owner=sender.pubkey(),
            amount=amt,
            decimals=decimals,
            signers=[]
        )))
        resp = self.client.send_transaction(tx, sender, opts=TxOpts(skip_preflight=skip_preflight))
        return str(resp.value)

# ---------- Helpers (UI) ----------
def show_accounts_table(accounts: List[dict]):
    table = Table(title="SPL Token Accounts", box=box.SIMPLE_HEAVY)
    table.add_column("Mint")
    table.add_column("UI Amount", justify="right")
    table.add_column("Decimals", justify="right")
    table.add_column("Token Account")
    for a in accounts:
        table.add_row(a["mint"], f'{a["ui_amount"]}', str(a["decimals"]), a["pubkey"])
    print(table)

def ask_password(confirm: bool=False) -> str:
    pwd = getpass.getpass("Parolă keystore: ")
    if confirm:
        pwd2 = getpass.getpass("Confirmă parola: ")
        if pwd != pwd2:
            raise typer.BadParameter("Parolele nu coincid.")
    return pwd

# ---------- CLI ----------
@app.command("init")
def cmd_init(words: int = typer.Option(24, help="Număr cuvinte (12/24)")):
    mnemonic = generate_mnemonic(words)
    print("\n[bold]Seed-ul tău (scrie-l pe hârtie, nu-l salva online!):[/bold]\n")
    print(f"[yellow]{mnemonic}[/yellow]\n")
    if not Confirm.ask("Salvez acest seed (criptat) în keystore-ul local?", default=True):
        raise typer.Abort()
    pwd = ask_password(confirm=True)
    Wallet().save_keystore(mnemonic, pwd)
    print(f"[green]Keystore salvat la[/green] {KEYSTORE}")

@app.command("import")
def cmd_import(mnemonic: str = typer.Option(None, "--mnemonic", "-m", help="Seed BIP-39 (12/24 cuvinte) sau omit pentru prompt securizat")):
    if not mnemonic:
        mnemonic = Prompt.ask("Introdu mnemonic-ul (nu se salvează în history)")
    pwd = ask_password(confirm=True)
    Wallet().save_keystore(mnemonic.strip(), pwd)
    print(f"[green]Import reușit.[/green] Keystore: {KEYSTORE}")

@app.command("addr")
def cmd_addr(account: int = 0, change: int = 0, index: int = 0, rpc: str = DEFAULT_RPC):
    pwd = ask_password()
    w = Wallet(rpc)
    kp = w.keypair_from_keystore(pwd, account, change, index)
    print(f"[bold]Adresa:[/bold] {kp.pubkey()}")

@app.command("balance")
def cmd_balance(account: int = 0, change: int = 0, index: int = 0, rpc: str = DEFAULT_RPC):
    pwd = ask_password()
    w = Wallet(rpc)
    kp = w.keypair_from_keystore(pwd, account, change, index)
    bal = w.get_balance_sol(kp.pubkey())
    print(f"[bold]{kp.pubkey()}[/bold] => [cyan]{bal:.9f} SOL[/cyan]")

@app.command("tokens")
def cmd_tokens(account: int = 0, change: int = 0, index: int = 0, rpc: str = DEFAULT_RPC):
    pwd = ask_password()
    w = Wallet(rpc)
    kp = w.keypair_from_keystore(pwd, account, change, index)
    accs = w.list_spl_accounts(kp.pubkey())
    if not accs:
        print("[yellow]Nu există token accounts.[/yellow]")
    else:
        show_accounts_table(accs)

@app.command("send-sol")
def cmd_send_sol(
    to: str = typer.Argument(..., help="Adresa destinatarului"),
    amount: float = typer.Argument(..., help="Cantitate în SOL"),
    account: int = 0, change: int = 0, index: int = 0,
    rpc: str = DEFAULT_RPC, skip_preflight: bool = False,
):
    pwd = ask_password()
    w = Wallet(rpc)
    sender = w.keypair_from_keystore(pwd, account, change, index)
    sig = w.transfer_sol(sender, Pubkey.from_string(to), amount, skip_preflight)
    print(f"[green]Trimis.[/green] Tx: [cyan]{sig}[/cyan]")

@app.command("send-spl")
def cmd_send_spl(
    mint: str = typer.Argument(..., help="Mint-ul tokenului"),
    to_owner: str = typer.Argument(..., help="Adresa publică a destinatarului (owner, nu ATA)"),
    amount: float = typer.Argument(..., help="Cantitate UI (ex: 1.5)"),
    decimals: int = typer.Argument(..., help="Decimale ale tokenului (ex: 6, 9)"),
    account: int = 0, change: int = 0, index: int = 0,
    rpc: str = DEFAULT_RPC, skip_preflight: bool = False,
):
    pwd = ask_password()
    w = Wallet(rpc)
    sender = w.keypair_from_keystore(pwd, account, change, index)
    sig = w.transfer_spl(
        sender,
        Pubkey.from_string(to_owner),
        Pubkey.from_string(mint),
        amount,
        decimals,
        skip_preflight
    )
    print(f"[green]Trimis.[/green] Tx: [cyan]{sig}[/cyan]")

# ---------- Minimal FastAPI ----------
def build_api():
    from fastapi import FastAPI, HTTPException, Query
    fast = FastAPI(title="SolWallet Local API", version="0.1.0")

    @fast.get("/addr")
    def api_addr(
        password: str = Query(..., min_length=1),
        account: int = 0, change: int = 0, index: int = 0, rpc: str = DEFAULT_RPC
    ):
        try:
            w = Wallet(rpc)
            kp = w.keypair_from_keystore(password, account, change, index)
            return {"address": str(kp.pubkey())}
        except Exception as e:
            raise HTTPException(400, str(e))

    @fast.get("/balance")
    def api_balance(
        password: str = Query(..., min_length=1),
        account: int = 0, change: int = 0, index: int = 0, rpc: str = DEFAULT_RPC
    ):
        try:
            w = Wallet(rpc)
            kp = w.keypair_from_keystore(password, account, change, index)
            bal = w.get_balance_sol(kp.pubkey())
            return {"address": str(kp.pubkey()), "sol": bal}
        except Exception as e:
            raise HTTPException(400, str(e))

    return fast

@app.command("api")
def cmd_api(host: str="127.0.0.1", port: int=8787):
    global api_app
    api_app = build_api()
    import uvicorn
    uvicorn.run(api_app, host=host, port=port)

if __name__ == "__main__":
    app()
