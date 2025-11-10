#!/usr/bin/env python3
"""
Shared-Key Password Vault (Intermediate Version)
- AES-GCM encrypted vault
- Shamir's Secret Sharing (N-of-M) for the master key
- Optional passphrase-wrapped shares (Argon2id + AES-GCM)
- Tamper-evident audit log (hash chain)
- Password generator + basic strength check
This is an educational reference. Use battle-tested libraries and security reviews for production.
"""
import os, sys, json, base64, secrets, getpass, argparse, time, hashlib, math, re
from dataclasses import dataclass
from typing import List, Tuple, Optional
from datetime import datetime, timezone
from tkinter import simpledialog

# Crypto deps
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from argon2.low_level import hash_secret_raw, Type as Argon2Type
from secretsharing import HexToHexSecretSharer as SSS

# ---------- Constants & Paths ----------
VAULT_FILE = "vault.enc"
META_FILE  = "vault.meta.json"
AUDIT_FILE = "audit.log"
AAL = b"vault-v2"  # Associated Additional Data label

# ---------- Small utils ----------
def b64e(b: bytes) -> str:
    return base64.b64encode(b).decode("utf-8")

def b64d(s: str) -> bytes:
    return base64.b64decode(s.encode("utf-8"))

def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()

def wipe_bytes(b: bytearray):
    # Best-effort wipe for educational purposes (Python doesn't guarantee)
    for i in range(len(b)):
        b[i] = 0

# ---------- KDF (Argon2id) for wrapping shares ----------
def argon2id(password: str, salt: bytes, length: int = 32) -> bytes:
    return hash_secret_raw(
        secret=password.encode("utf-8"),
        salt=salt,
        time_cost=2,
        memory_cost=256*1024,
        parallelism=2,
        hash_len=length,
        type=Argon2Type.ID
    )

# ---------- AES-GCM helpers ----------
@dataclass
class Blob:
    nonce: str
    ciphertext: str

def aesgcm_encrypt(key: bytes, plaintext: bytes, aad: bytes = b"") -> Blob:
    nonce = secrets.token_bytes(12)
    ct = AESGCM(key).encrypt(nonce, plaintext, aad)
    return Blob(nonce=b64e(nonce), ciphertext=b64e(ct))

def aesgcm_decrypt(key: bytes, blob: Blob, aad: bytes = b"") -> bytes:
    return AESGCM(key).decrypt(b64d(blob.nonce), b64d(blob.ciphertext), aad)

# ---------- SSS helpers ----------
def split_key(master_key: bytes, threshold: int, total: int) -> List[str]:
    return SSS.split_secret(master_key.hex(), threshold, total)

def combine_shares(shares: List[str]) -> bytes:
    hex_key = SSS.recover_secret(shares)
    return bytes.fromhex(hex_key)

# ---------- Audit log (hash chain) ----------
def _audit_hash(record: dict, prev_hash_hex: Optional[str]) -> str:
    m = hashlib.sha256()
    if prev_hash_hex:
        m.update(bytes.fromhex(prev_hash_hex))
    m.update(json.dumps(record, sort_keys=True).encode("utf-8"))
    return m.hexdigest()

def audit(event: str, detail: dict):
    rec = {"ts": now_iso(), "event": event, "detail": detail}
    prev = None
    if os.path.exists(AUDIT_FILE):
        with open(AUDIT_FILE, "rb") as f:
            try:
                *_, last = f.read().splitlines()
                prev = json.loads(last.decode("utf-8"))["hash"]
            except Exception:
                prev = None
    h = _audit_hash(rec, prev)
    rec["prev_hash"] = prev
    rec["hash"] = h
    with open(AUDIT_FILE, "a", encoding="utf-8") as f:
        f.write(json.dumps(rec) + "\n")

# ---------- Password generator & strength ----------
WORDS = [
    "orchid","nebula","quartz","velvet","ember","goblin","lunar","maple","pixel","raven",
    "saffron","topaz","ultra","vortex","willow","xenon","yodel","zephyr","avocado","biscuit"
]

def generate_password(length: int = 20, mode: str = "mixed") -> str:
    """mode: mixed|passphrase|digits"""
    if mode == "passphrase":
        words = [secrets.choice(WORDS) for _ in range(4)]
        sep = secrets.choice(["-", "_", ".", "•"])
        tail = str(secrets.randbelow(1000)).zfill(3)
        return sep.join(words) + sep + tail
    elif mode == "digits":
        return "".join(str(secrets.randbelow(10)) for _ in range(length))
    else:
        alphabet = (
            "abcdefghijklmnopqrstuvwxyz"
            "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
            "0123456789"
            "!@#$%^&*()-_=+[]{};:,.?/"
        )
        return "".join(secrets.choice(alphabet) for _ in range(length))

def strength_report(pw: str) -> dict:
    length = len(pw)
    classes = sum([
        any(c.islower() for c in pw),
        any(c.isupper() for c in pw),
        any(c.isdigit() for c in pw),
        any(c in "!@#$%^&*()-_=+[]{};:,.?/" for c in pw)
    ])
    repeats = bool(re.search(r"(.)\1{2,}", pw))
    sequential = bool(re.search(r"(0123|1234|abcd|qwer|asdf|zxcv)", pw.lower()))
    # Very rough entropy proxy:
    pool = 26 if classes == 1 else 52 if classes == 2 else 62 if classes == 3 else 90
    entropy_bits = length * math.log2(pool)
    score = min(100, int(entropy_bits / 1.2) - (10 if repeats else 0) - (8 if sequential else 0))
    level = "weak" if score < 40 else "ok" if score < 70 else "strong"
    return {
        "length": length,
        "classes": classes,
        "entropy_bits_est": round(entropy_bits, 1),
        "repeats": repeats,
        "sequential": sequential,
        "score": score,
        "level": level,
    }

# ---------- Vault operations ----------
def save_vault(master_key: bytes, data: dict):
    blob = aesgcm_encrypt(master_key, json.dumps(data).encode("utf-8"), aad=AAL)
    with open(VAULT_FILE, "w", encoding="utf-8") as f:
        json.dump({"nonce": blob.nonce, "ciphertext": blob.ciphertext}, f, indent=2)

def load_vault_blob() -> Blob:
    if not os.path.exists(VAULT_FILE):
        sys.exit("Vault not found. Run 'init' first.")
    with open(VAULT_FILE, "r", encoding="utf-8") as f:
        d = json.load(f)
        return Blob(nonce=d["nonce"], ciphertext=d["ciphertext"])

def load_meta() -> dict:
    if not os.path.exists(META_FILE):
        sys.exit("Metadata not found. Run 'init' first.")
    with open(META_FILE, "r", encoding="utf-8") as f:
        return json.load(f)

def write_meta(meta: dict):
    with open(META_FILE, "w", encoding="utf-8") as f:
        json.dump(meta, f, indent=2)

def create_vault(threshold: int, total: int, wrap: bool):
    if os.path.exists(VAULT_FILE):
        sys.exit(f"{VAULT_FILE} already exists. Move/backup it first.")
    master_key = secrets.token_bytes(32)
    shares = split_key(master_key, threshold, total)

    # empty vault
    data = {"version": 2, "entries": []}
    save_vault(master_key, data)
    write_meta({"threshold": threshold, "total": total, "aad": b64e(AAL)})

    print("✅ Created new vault")
    print(f"  - {VAULT_FILE}")
    print(f"  - {META_FILE}")
    print("\nDistribute these shares securely:\n")

    if wrap:
        for i, sh in enumerate(shares, 1):
            pw = getpass.getpass(f"Set passphrase to protect Share #{i} (blank to skip): ")
            if pw:
                salt = secrets.token_bytes(16)
                k = argon2id(pw, salt, 32)
                blob = aesgcm_encrypt(k, sh.encode("utf-8"))
                payload = {"salt": b64e(salt), "nonce": blob.nonce, "ciphertext": blob.ciphertext}
                print(f"Share #{i} (WRAPPED JSON): {json.dumps(payload)}")
            else:
                print(f"Share #{i}: {sh}")
    else:
        for i, sh in enumerate(shares, 1):
            print(f"Share #{i}: {sh}")

    audit("init", {"threshold": threshold, "total": total})

def unwrap_share_if_needed(s: str, prompt_callback=None) -> str:
    """
    If share is wrapped JSON, unwrap it.
    Uses prompt_callback() to get the passphrase (GUI or CLI fallback).
    """
    s = s.strip()
    if s.startswith("{") and s.endswith("}"):
        obj = json.loads(s)
        # Ask for passphrase using provided callback, or fallback to CLI
        if prompt_callback:
            pw = prompt_callback()
        else:
            import getpass
            pw = getpass.getpass("Enter passphrase for this wrapped share: ")

        if not pw:
            raise ValueError("No passphrase entered for wrapped share.")

        salt = b64d(obj["salt"])
        k = argon2id(pw, salt, 32)
        sh = aesgcm_decrypt(k, Blob(nonce=obj["nonce"], ciphertext=obj["ciphertext"]))
        return sh.decode("utf-8")

    return s


def read_shares_interactively(min_count: int) -> List[str]:
    print(f"Paste at least {min_count} share(s). End with an empty line:")
    shares = []
    while True:
        line = input().strip()
        if not line:
            break
        shares.append(unwrap_share_if_needed(line))
    if len(shares) < min_count:
        sys.exit(f"Need at least {min_count} shares.")
    return shares

def unlock_with_shares(shares: List[str]) -> Tuple[bytes, dict]:
    blob = load_vault_blob()
    meta = load_meta()
    master_key = combine_shares(shares[: meta["threshold"]])
    try:
        plaintext = aesgcm_decrypt(master_key, blob, aad=AAL)
        data = json.loads(plaintext.decode("utf-8"))
        return master_key, data
    except Exception as e:
        audit("unlock_failed", {"reason": str(e)})
        sys.exit("❌ Unlock failed. Wrong shares or corrupted vault.")

def add_entry(site: str, username: str, password: Optional[str], generate: bool):
    meta = load_meta()
    shares = read_shares_interactively(meta["threshold"])
    master_key, data = unlock_with_shares(shares)

    if generate or not password:
        mode = "passphrase" if site.lower() in ("bank", "email", "aws") else "mixed"
        password = generate_password(20, mode=mode)
        rep = strength_report(password)
        print(f"Generated password (score {rep['score']}, {rep['level']}):\n  {password}")

    data["entries"].append({
        "site": site,
        "username": username,
        "password": password,
        "created": now_iso()
    })
    save_vault(master_key, data)
    audit("add_entry", {"site": site, "username": username})
    print(f"✅ Added entry for {site}.")

def list_entries():
    meta = load_meta()
    shares = read_shares_interactively(meta["threshold"])
    master_key, data = unlock_with_shares(shares)

    print("\nYour entries:")
    for i, e in enumerate(data.get("entries", []), 1):
        print(f"{i:02d}. {e['site']} — {e['username']}  (password hidden, created {e.get('created','?')})")
    audit("list_entries", {"count": len(data.get("entries", []))})

def show_entry(index: int):
    meta = load_meta()
    shares = read_shares_interactively(meta["threshold"])
    master_key, data = unlock_with_shares(shares)
    entries = data.get("entries", [])
    if index < 1 or index > len(entries):
        sys.exit("Invalid index.")
    e = entries[index-1]
    print("\n⚠️  Revealing password. Make sure no one is watching.")
    print(f"Site: {e['site']}\nUser: {e['username']}\nPassword: {e['password']}")
    audit("show_entry", {"index": index, "site": e["site"]})

def rotate_shares(new_threshold: int, new_total: int, wrap: bool, passphrases: Optional[List[str]] = None, existing_shares: Optional[List[str]] = None):
    """
    Re-split the same master key with new threshold/total parameters.
    GUI-safe: no terminal input; accepts shares from UI.
    """
    try:
        meta = load_meta()

        # ✅ Use GUI-provided shares instead of asking via terminal
        shares = existing_shares or read_shares_interactively(meta["threshold"])
        master_key, _ = unlock_with_shares(shares)

        # Ensure key is hex string
        key_hex = master_key.hex() if isinstance(master_key, bytes) else master_key

        # Generate new shares
        new_shares = split_key(bytes.fromhex(key_hex), new_threshold, new_total)

        # Update metadata
        meta.update({
            "threshold": new_threshold,
            "total": new_total,
            "rotated_on": now_iso(),
            "aad": b64e(AAL)
        })
        write_meta(meta)

        # Wrap if requested
        wrapped_outputs = []
        for i, sh in enumerate(new_shares, 1):
            if wrap and passphrases and passphrases[i - 1]:
                pw = passphrases[i - 1]
                salt = secrets.token_bytes(16)
                k = argon2id(pw, salt, 32)
                blob = aesgcm_encrypt(k, sh.encode("utf-8"))
                payload = {
                    "salt": b64e(salt),
                    "nonce": blob.nonce,
                    "ciphertext": blob.ciphertext
                }
                wrapped_outputs.append(f"Share #{i} (WRAPPED JSON): {json.dumps(payload)}")
            else:
                wrapped_outputs.append(f"Share #{i}: {sh}")

        audit("rotate_shares", {"new_threshold": new_threshold, "new_total": new_total})
        return wrapped_outputs

    except Exception as e:
        audit("rotate_shares_failed", {
            "error": str(e),
            "new_threshold": new_threshold,
            "new_total": new_total
        })
        backup_file = f"meta_backup_{int(time.time())}.json"
        with open(backup_file, "w", encoding="utf-8") as f:
            json.dump(meta, f, indent=2)
        raise RuntimeError(f"Error during rotation: {e}\nOld metadata backed up to {backup_file}")




def check_strength(password: str):
    rep = strength_report(password)
    print(json.dumps(rep, indent=2))

def main():
    p = argparse.ArgumentParser(description="Shared-Key Password Vault (Intermediate)")
    sub = p.add_subparsers(dest="cmd")

    sp = sub.add_parser("init", help="Create a new vault and generate shares")
    sp.add_argument("-t","--threshold", type=int, default=2)
    sp.add_argument("-n","--total", type=int, default=3)
    sp.add_argument("--wrap-shares", action="store_true", help="Protect each share with its own passphrase")

    sp_add = sub.add_parser("add", help="Add a credential entry")
    sp_add.add_argument("--site", required=True)
    sp_add.add_argument("--username", required=True)
    sp_add.add_argument("--password", required=False, help="If omitted, a strong one is generated")
    sp_add.add_argument("--generate", action="store_true", help="Force generate a strong password")

    sp_ls = sub.add_parser("list", help="List entries (passwords hidden)")

    sp_show = sub.add_parser("show", help="Reveal an entry's password (caution)")
    sp_show.add_argument("--index", type=int, required=True)

    sp_rot = sub.add_parser("rotate-shares", help="Re-split the same master key into new shares/policy")
    sp_rot.add_argument("-t","--threshold", type=int, required=True)
    sp_rot.add_argument("-n","--total", type=int, required=True)
    sp_rot.add_argument("--wrap-shares", action="store_true")

    sp_gen = sub.add_parser("genpass", help="Generate a strong password locally")
    sp_gen.add_argument("--length", type=int, default=20)
    sp_gen.add_argument("--mode", choices=["mixed","passphrase","digits"], default="mixed")

    sp_chk = sub.add_parser("check", help="Check strength of a given password (local)")
    sp_chk.add_argument("--password", required=True)

    args = p.parse_args()

    if args.cmd == "init":
        if args.threshold < 1 or args.total < 1 or args.threshold > args.total:
            sys.exit("Invalid threshold/total.")
        create_vault(args.threshold, args.total, args.wrap_shares)

    elif args.cmd == "add":
        add_entry(args.site, args.username, args.password, args.generate)

    elif args.cmd == "list":
        list_entries()

    elif args.cmd == "show":
        show_entry(args.index)

    elif args.cmd == "rotate-shares":
        if args.threshold < 1 or args.total < 1 or args.threshold > args.total:
            sys.exit("Invalid threshold/total.")
        rotate_shares(args.threshold, args.total, args.wrap_shares)

    elif args.cmd == "genpass":
        print(generate_password(args.length, args.mode))

    elif args.cmd == "check":
        check_strength(args.password)

    else:
        p.print_help()

if __name__ == "__main__":
    main()
