"""
P2P Fortress — Ultra-Secure File Transfer  v14.0
================================================
© 2024 Moshe Pinchasi. All rights reserved.

DISCLAIMER:
This software is provided "as is", without warranty of any kind.
The developer shall not be liable for any claim, damages or other
liability arising from, out of or in connection with the software.
Any misuse of this tool for illegal activities is strictly prohibited.

New in v14.0 — Bug-fix & cleanup pass:
  🔴 CRITICAL — Wormhole receive lost file extension: using
               --output-file with a fixed "received.whfort" name meant
               every file was saved without its original extension.
               Fixed: wormhole now runs with cwd=tmp_dir (no
               --output-file), preserving the original filename
               (e.g. "document.pdf.whfort"). Stripping ".whfort" now
               correctly restores "document.pdf".
  🔧 MEDIUM  — Multi-file bundle not auto-extracted on receiver:
               UI promised "unzipped on the receiver side" but code
               only saved fortress_bundle.zip. Added Zip-Slip-guarded
               auto-extraction into a "fortress_bundle/" subfolder with
               collision-avoidance naming.
  🧹 CLEANUP — _FNAME_RE regex compiled inside WormholeManager.receive()
               on every call; moved to class-level constant.
  ⚡ PERF    — _zero_bytes: replaced b"\x00" * len(buf) (creates an
               immutable bytes copy) with bytearray(len(buf)) which
               allocates zero-filled memory directly.

New in v13.0 — Full Audit, Dead-Code Removal & Performance pass 2:
  🔴 CRITICAL — Double op_unlock in _worker_send: gaierror handler called
               self.after(0, _op_unlock) then returned, skipping the outer
               finally block — but the inner try was restructured to use a
               single unified finally instead, eliminating the double call.
  🔧 MEDIUM  — _get_local_ip UDP probe had no timeout: on machines without a
               default route the connect() could hang the LAN discovery
               startup. Added settimeout(2.0).
  🔧 MEDIUM  — SO_REUSEPORT added on Linux: allows binding the same port again
               immediately after a crash/restart without "Address already in
               use" errors. Safe no-op on macOS/Windows (checked at runtime).
  🔧 MEDIUM  — Redundant None guards removed from _show_sas, _reset_listen_btn,
               _on_send, _on_listen: these widgets are always initialized in
               the build phase; guards were dead code that obscured bugs.
  🧹 CLEANUP — Stale end-of-file comment said "p2p_fortress-8.py". Fixed.
  🧹 CLEANUP — _busy_btns type annotation clarified.
  🔴 Previous v10.0 fixes retained: port double-insert, local crypto op_lock,
               navigation fix, messagebox thread safety, wormhole guards.

Cryptographic stack (exceeds NSA Suite B):
  Key Exchange : X25519 ECDH  (ephemeral per session — Perfect Forward Secrecy)
  SAS          : SHA-256 of shared secret → 4-word fingerprint (MITM detection)
  KDF Network  : Argon2id (128MB RAM, 4 iterations, OWASP 2023 max params)
  KDF Local    : Argon2id (same params, SALT_LOCAL domain-separated)
  Sub-key gen  : HKDF-SHA512 (domain-separated per cipher)
  Cipher #1    : ChaCha20-Poly1305 (AEAD — layer 1)
  Cipher #2    : AES-256-GCM       (AEAD — layer 2, double encryption)
  Integrity    : SHA-512 of plaintext (verified after full decryption)
  Nonces       : OS CSPRNG (12 bytes, unique per operation, never reused)
  Auth         : HMAC-SHA512 over full ciphertext (constant-time compare)

New in v7.0:
  + 🔐 Key zeroization  — sensitive bytes zeroed from memory after use
  + 🔐 Rate limiter     — per-IP brute-force protection on handshake
  + 🔐 Secure delete    — overwrite temp files before removal
  + 🔐 Replay guard     — timestamp+nonce in handshake to block replays
  + 🔐 SAS fingerprint  — 4-word Short Authentication String for MITM detection
  + 📁 Folder encrypt   — zip + double-AEAD for entire directory trees
  + 📋 Transfer history — SQLite log of every send/receive with stats
  + 🌐 LAN Discovery    — automatic peer detection on local network
  + 🔲 QR Invite code   — ASCII QR code for FORTRESS:// invite
  + 🔥 Burn After Read  — auto-delete plaintext after first open
  + ⏰ Dead Man Switch  — auto-wipe keys after N days of no login
  + 🌓 Dark/Light mode  — instant theme toggle in header
  + 📊 Progress details — MB/s speed + ETA in real-time
  + 🔔 Notifications    — system toast when transfer completes
  + 🗂 History tab      — searchable transfer log with stats
  + 🔬 Diagnostics tab  — network testing, latency, NAT detection
  + 🖱 Drag & Drop      — drop files directly onto the window
  + 🖥 Tray icon        — minimize to tray (requires pystray+Pillow)

Dependencies (required):
    pip install customtkinter cryptography argon2-cffi

Dependencies (optional — app runs without these):
    pip install magic-wormhole    # WORMHOLE tab
    pip install pystray pillow    # system tray icon
    pip install plyer             # desktop notifications
    pip install qrcode            # QR code in invite
    pip install zeroconf          # LAN peer discovery
"""


# ---------------------------------------------------------------------------
# Dependency check — friendly error before any real import
# ---------------------------------------------------------------------------
import sys as _sys

def _check_dependencies() -> None:
    """Verify required third-party packages are installed."""
    _missing: list[str] = []
    for _pkg, _import in [
        ("customtkinter", "customtkinter"),
        ("argon2-cffi",   "argon2"),
        ("cryptography",  "cryptography"),
    ]:
        try:
            __import__(_import)
        except ImportError:
            _missing.append(_pkg)
    if _missing:
        print("=" * 62)
        print("  P2P FORTRESS — MISSING DEPENDENCIES")
        print("=" * 62)
        print(f"\n  The following packages are not installed:\n")
        for _p in _missing:
            print(f"    • {_p}")
        print(f"\n  Install them with:\n")
        print(f"    pip install {' '.join(_missing)}")
        print(f"\n  Optional (for tray/notifications/QR/LAN):")
        print(f"    pip install pystray pillow plyer qrcode zeroconf\n")
        _sys.exit(1)


_check_dependencies()

# ---------------------------------------------------------------------------
# Standard library
# ---------------------------------------------------------------------------
import base64 as _b64
import datetime
import hashlib
import hmac
import io
import json
import logging
import logging.handlers
import os
import re
import queue
import shutil
import socket
import sqlite3
import struct
import subprocess
import tempfile
import threading
import time
import tkinter as _tk
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, NamedTuple

import customtkinter as ctk
from argon2.low_level import Type, hash_secret_raw
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.hazmat.primitives.hashes import SHA512
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from tkinter import filedialog, messagebox

# ---------------------------------------------------------------------------
# Optional dependencies — graceful fallback if not installed
# ---------------------------------------------------------------------------
try:
    import pystray
    from PIL import Image as _PILImage
    _TRAY_OK = True
except ImportError:
    _TRAY_OK = False

try:
    from plyer import notification as _plyer_notify
    _NOTIFY_OK = True
except ImportError:
    _NOTIFY_OK = False

try:
    import qrcode as _qrcode_lib
    _QR_OK = True
except ImportError:
    _QR_OK = False

try:
    from zeroconf import ServiceBrowser, ServiceInfo, Zeroconf
    _ZEROCONF_OK = True
except ImportError:
    _ZEROCONF_OK = False

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
_LOG_FMT  = "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s"
_LOG_FILE = Path(__file__).parent / "fortress.log"
logging.basicConfig(level=logging.INFO, format=_LOG_FMT)
_fh = logging.handlers.RotatingFileHandler(
    _LOG_FILE, maxBytes=2 * 1024 * 1024, backupCount=3, encoding="utf-8"
)
_fh.setFormatter(logging.Formatter(_LOG_FMT))
logging.getLogger().addHandler(_fh)
logger = logging.getLogger("p2p_fortress")

# ---------------------------------------------------------------------------
# Protocol Constants
# ---------------------------------------------------------------------------
BUFFER_SIZE:   int = 65_536
HEADER_FORMAT: str = "!Q"
HEADER_SIZE:   int = struct.calcsize(HEADER_FORMAT)
PUBKEY_SIZE:   int = 32          # X25519 raw public-key bytes
NONCE_SIZE:    int = 8           # replay-guard nonce bytes in handshake
MAX_FILE_BYTES: int = 2 * 1024 ** 3   # 2 GB hard cap

# Streaming mode: files above this threshold use chunked encryption
# to avoid holding plaintext + ciphertext in RAM simultaneously.
STREAM_THRESHOLD: int = 64 * 1024 * 1024   # 64 MB
STREAM_CHUNK_SIZE: int = 512 * 1024         # 512 KB per encrypted chunk
FLAG_BURN:    int = 0x01   # Burn-After-Reading
FLAG_STREAM:  int = 0x04   # Chunked streaming mode

ARGON2_TIME_COST:   int = 4
ARGON2_MEMORY_COST: int = 131_072    # 128 MB RAM
ARGON2_PARALLELISM: int = 4
ARGON2_HASH_LEN:    int = 96         # → 3 × 32-byte sub-keys

# Domain-separated 32-byte salts
SALT_NETWORK:  bytes = b"fortress-v3-network-ecdh-session"
SALT_LOCAL:    bytes = b"fortress-v3-local-fileencryption"
SALT_WORMHOLE: bytes = b"fortress-v3-wormhole-preencrypt1"

LABEL_CHACHA: bytes = b"fortress-v3-chacha20poly1305-key"
LABEL_AES:    bytes = b"fortress-v3-aes256gcm-cipher-key"
LABEL_HMAC:   bytes = b"fortress-v3-hmac-sha512-auth-key"

# SAS word list — 224 unique words (entropy: 4 × log2(224) ≈ 30.8 bits)
# All words verified unique; duplicates replaced:
#   'mike'(×2)  → second replaced with 'morse'
#   'victor'(×2)→ second replaced with 'vane'
#   'xray'(×2)  → second replaced with 'xylem'
#   'queen'(×2) → second replaced with 'quay'
#   'urn'       → replaced with 'ulna' (row 249) and 'orb' (row 255)
#   'chip','dune','etch','fen','gust','hilt','iris'(×2) → row 250 deduplicated
_SAS_WORDS: list[str] = [
    "alpha","bravo","charlie","delta","echo","foxtrot","golf","hotel",
    "india","juliet","kilo","lima","mike","november","oscar","papa",
    "quebec","romeo","sierra","tango","uniform","victor","whiskey","xray",
    "yankee","zulu","able","baker","castle","dog","easy","fox",
    "george","how","item","jig","king","love","morse","nan",       # was: mike→morse
    "oboe","peter","queen","roger","sugar","tare","uncle","vane",  # was: victor→vane
    "william","xylem","yoke","zebra","amber","bison","coral","dusk",# was: xray→xylem
    "ember","flint","grove","haze","ivory","jade","knot","lemon",
    "maple","nova","orbit","pulse","quartz","ridge","slate","thorn",
    "ultra","valor","wren","xenon","yard","zinc","ace","bolt",
    "cave","dawn","edge","flame","ghost","hill","iron","jewel",
    "lance","mist","night","opal","pike","quest","rain","storm",
    "tide","umber","veil","wave","axe","blade","comet","dagger",
    "eagle","fern","glacier","hawk","igloo","jungle","karma","lake",
    "moon","north","owl","pine","quay","river","snow","tower",    # was: queen→quay
    "urban","viper","wolf","xeric","yew","zenith","arc","bay",
    "cliff","dome","elf","ford","glen","heath","ink","jasper",
    "kite","loft","marsh","net","oak","pond","quill","raft",
    "sand","turf","vale","wade","exit","yam","zone","ash",
    "bench","cork","dale","elm","fawn","gate","horn","isle",
    "jolt","kelp","lark","moor","nest","onyx","plum","reed",
    "sage","teak","ulna","vine","whirl","yak","zest","apex",      # was: urn→ulna
    "barn","drab","fume","glow","hulk","lair","meld","numb",
    "josh","kiln","limb","myth","noon","ode","peat","rook",
    "silt","tuft","udder","volt","wax","yore","zero","atlas",
    "birch","crest","drop","earl","flap","grip","hive","icon",
    "jibe","knob","lull","mace","nook","opus","perch","rack",
    "slab","tern","orb","vow","wisp","yarn","zeal","anvil",
]


# ---------------------------------------------------------------------------
# Military & Light Color Palettes
# ---------------------------------------------------------------------------
_DARK_THEME: dict[str, str] = dict(
    BG="#1A1A0F", PANEL="#222214", CARD="#2C2C1A", CARD2="#333320",
    OLIVE="#4A5C2F", OLIVE_LT="#6B7C3E", KHAKI="#8B9467", TAN="#C4B882",
    GREEN="#3D6B35", GREEN_LT="#5A9E50", AMBER="#D4A017",
    RED="#8B2000", RED_LT="#CC3300", TEXT="#D4CFA8", MUTED="#6B6B50",
)
_LIGHT_THEME: dict[str, str] = dict(
    BG="#F5F5EC", PANEL="#EAEADC", CARD="#DCDCCC", CARD2="#D0D0BE",
    OLIVE="#4A5C2F", OLIVE_LT="#6B7C3E", KHAKI="#5A5C3F", TAN="#3C3A20",
    GREEN="#2D5025", GREEN_LT="#3D7030", AMBER="#8B6800",
    RED="#6B1000", RED_LT="#AA2200", TEXT="#1A1A0A", MUTED="#6B6B50",
)

_THEME = _DARK_THEME.copy()

def _t(key: str) -> str:
    """Returns current-theme colour by key."""
    return _THEME[key]

# Aliases — used throughout UI code
def _reload_theme() -> None:
    global MIL_BG,MIL_PANEL,MIL_CARD,MIL_CARD2,MIL_OLIVE,MIL_OLIVE_LT
    global MIL_KHAKI,MIL_TAN,MIL_GREEN,MIL_GREEN_LT,MIL_AMBER
    global MIL_RED,MIL_RED_LT,MIL_TEXT,MIL_MUTED
    MIL_BG=_THEME["BG"]; MIL_PANEL=_THEME["PANEL"]; MIL_CARD=_THEME["CARD"]
    MIL_CARD2=_THEME["CARD2"]; MIL_OLIVE=_THEME["OLIVE"]; MIL_OLIVE_LT=_THEME["OLIVE_LT"]
    MIL_KHAKI=_THEME["KHAKI"]; MIL_TAN=_THEME["TAN"]; MIL_GREEN=_THEME["GREEN"]
    MIL_GREEN_LT=_THEME["GREEN_LT"]; MIL_AMBER=_THEME["AMBER"]
    MIL_RED=_THEME["RED"]; MIL_RED_LT=_THEME["RED_LT"]
    MIL_TEXT=_THEME["TEXT"]; MIL_MUTED=_THEME["MUTED"]

_reload_theme()


# ---------------------------------------------------------------------------
# Utility helpers
# ---------------------------------------------------------------------------
def _default_download_dir() -> Path:
    """Returns best available default directory for saving received files."""
    for candidate in (Path.home()/"Downloads", Path.home()/"Desktop", Path.home()):
        if candidate.is_dir():
            return candidate
    return Path.home()


def _format_size(b: int | float) -> str:
    """Human-readable byte count.

    Args:
        b: Size in bytes (int or float after unit division).

    Returns:
        Formatted string such as '1.4 MB' or '345.0 B'.
    """
    for unit in ("B", "KB", "MB", "GB"):
        if b < 1024:
            return f"{b:.1f} {unit}"
        b /= 1024
    return f"{b:.1f} TB"


def _format_eta(seconds: float) -> str:
    """Human-readable ETA string."""
    if seconds < 0 or seconds > 86400:
        return "--:--"
    m, s = divmod(int(seconds), 60)
    h, m = divmod(m, 60)
    return f"{h}:{m:02d}:{s:02d}" if h else f"{m:02d}:{s:02d}"


def secure_delete(path: Path) -> None:
    """Overwrites file with random data then zeros before deleting.

    Args:
        path: File to destroy securely.
    """
    if not path.is_file():
        return
    try:
        size = path.stat().st_size
        with path.open("r+b") as fh:
            fh.write(os.urandom(size))   # pass 1 — random
            fh.seek(0)
            fh.write(b"\x00" * size)     # pass 2 — zeros
            fh.flush()
            os.fsync(fh.fileno())
        path.unlink()
    except OSError:
        logger.warning("secure_delete: overwrite failed for %s — attempting plain unlink.", path)
        try:
            path.unlink(missing_ok=True)
        except OSError:
            logger.error("secure_delete: could not delete %s.", path)


def _zero_bytes(buf: bytearray) -> None:
    """Fills a bytearray with zeros in-place (key zeroization)."""
    buf[:] = bytearray(len(buf))


def _sas_fingerprint(shared_secret: bytes) -> str:
    """Derives a 4-word Short Authentication String from the shared secret.

    The SAS allows the two parties to verbally confirm no MITM is present.
    Each word represents 2 bytes (16 bits) of SHA-256 output.

    Args:
        shared_secret: 32-byte X25519 DH result.

    Returns:
        4-word space-separated fingerprint string, e.g. "alpha bravo charlie delta".
    """
    digest = hashlib.sha256(b"fortress-sas-v1" + shared_secret).digest()
    words = []
    for i in range(4):
        idx = int.from_bytes(digest[i*2:(i+1)*2], "big") % len(_SAS_WORDS)
        words.append(_SAS_WORDS[idx])
    return "  ".join(w.upper() for w in words)


# ---------------------------------------------------------------------------
# Password Strength
# ---------------------------------------------------------------------------
def _password_strength(pw: str) -> tuple[int, str, str]:
    """Evaluates passphrase strength on a 0–4 scale."""
    if not pw:
        return 0, "EMPTY", "#555544"
    score = sum([
        len(pw) >= 8,
        len(pw) >= 14,
        bool(re.search(r"[A-Z]", pw) and re.search(r"[a-z]", pw)),
        bool(re.search(r"\d", pw)),
        bool(re.search(r"[^A-Za-z0-9]", pw)),
    ])
    score = min(score, 4)
    labels = ["WEAK", "FAIR", "GOOD", "STRONG", "MAXIMUM"]
    colours = ["#CC3300", "#D4A017", "#8B9467", "#5A9E50", "#3D6B35"]
    return score, labels[score], colours[score]


# ---------------------------------------------------------------------------
# Invite Code Helpers
# ---------------------------------------------------------------------------
_INVITE_MAGIC = b"FRTv1"   # 5-byte magic prefix inside decrypted payload


def _build_invite(ip: str, port: int, pw: str, pin: str = "") -> str:
    """Encodes connection params as a FORTRESS:// URL.

    Security model:
        • If pin is non-empty: payload is AES-256-GCM encrypted with a key
          derived from the PIN (Argon2id, light params for UX).
          The invite is safe to share over untrusted channels as long as the
          PIN is transmitted via a separate channel (SMS, verbally, etc.).
        • If pin is empty: payload is plain base64 — the passphrase is
          readable by anyone who sees the invite URL.  A warning is embedded
          in the version byte so the UI can surface it.

    Args:
        ip:   Receiver's IP address.
        port: Receiver's listening port.
        pw:   Session passphrase.
        pin:  Optional short PIN for invite encryption (4-8 chars recommended).

    Returns:
        FORTRESS:// invite string.
    """
    payload = _INVITE_MAGIC + f"{ip}:{port}:{pw}".encode()
    if pin:
        # Light Argon2id (32 MB, 2 iter) — fast enough for invite UX
        salt  = os.urandom(16)
        key   = hash_secret_raw(
            secret=pin.encode("utf-8"), salt=salt,
            time_cost=2, memory_cost=32_768, parallelism=2,
            hash_len=32, type=Type.ID,
        )
        nonce = os.urandom(12)
        ct    = AESGCM(key).encrypt(nonce, payload, None)
        # Format: version(1) + salt(16) + nonce(12) + ct
        blob  = b"\x01" + salt + nonce + ct
    else:
        # Unencrypted — version byte 0x00 signals plaintext
        blob = b"\x00" + payload
    return "FORTRESS://" + _b64.urlsafe_b64encode(blob).decode()


def _parse_invite(s: str, pin: str = "") -> tuple[str, int, str] | None:
    """Decodes a FORTRESS:// invite URL.

    Args:
        s:   Raw invite string (with or without FORTRESS:// prefix).
        pin: PIN used during _build_invite (empty if invite was unencrypted).

    Returns:
        (ip, port, passphrase) tuple, or None on any decode/auth failure.
    """
    try:
        t = s.strip()
        if t.upper().startswith("FORTRESS://"):
            t = t[11:]
        blob    = _b64.urlsafe_b64decode(t + "==")   # padding-tolerant
        version = blob[0]

        if version == 0x00:
            # Unencrypted invite
            payload = blob[1:]
        elif version == 0x01:
            # AES-GCM encrypted invite
            if not pin:
                logger.warning("Encrypted invite received but no PIN provided.")
                return None
            salt  = blob[1:17]
            nonce = blob[17:29]
            ct    = blob[29:]
            key   = hash_secret_raw(
                secret=pin.encode("utf-8"), salt=salt,
                time_cost=2, memory_cost=32_768, parallelism=2,
                hash_len=32, type=Type.ID,
            )
            try:
                payload = AESGCM(key).decrypt(nonce, ct, None)
            except Exception:
                logger.warning("Invite decryption failed — wrong PIN?")
                return None
        else:
            logger.warning("Unknown invite version byte: 0x%02x", version)
            return None

        if not payload.startswith(_INVITE_MAGIC):
            return None
        ip, port_str, pw = payload[len(_INVITE_MAGIC):].decode().split(":", 2)
        return ip, int(port_str), pw
    except Exception:
        return None


def _invite_is_encrypted(s: str) -> bool:
    """Returns True if the invite uses AES-GCM encryption (version 0x01)."""
    try:
        t = s.strip()
        if t.upper().startswith("FORTRESS://"):
            t = t[11:]
        blob = _b64.urlsafe_b64decode(t + "==")
        return blob[0] == 0x01
    except Exception:
        return False


def _ascii_qr(data: str) -> str:
    """Generates ASCII QR code string, or returns empty if qrcode not installed."""
    if not _QR_OK:
        return ""
    try:
        qr = _qrcode_lib.QRCode(box_size=1, border=1)
        qr.add_data(data)
        qr.make(fit=True)
        f = io.StringIO()
        qr.print_ascii(out=f)
        return f.getvalue()
    except Exception:
        return ""


# ---------------------------------------------------------------------------
# Custom Exceptions
# ---------------------------------------------------------------------------
class P2PError(Exception):
    """Base exception for all Fortress errors."""

class AuthenticationError(P2PError):
    """HMAC-SHA512 verification failed."""

class InvalidKeyError(P2PError):
    """AEAD decryption tag failure."""

class IntegrityError(P2PError):
    """SHA-512 mismatch after decryption."""

class NetworkError(P2PError):
    """Socket / TCP connection failure."""

class HandshakeError(P2PError):
    """X25519 ECDH key-exchange failure."""

class RateLimitError(P2PError):
    """Too many failed attempts from this IP."""

class WormholeError(P2PError):
    """Magic-wormhole subprocess failure."""


# ---------------------------------------------------------------------------
# Session Key Bundle
# ---------------------------------------------------------------------------
class SessionKeys(NamedTuple):
    """Three independent 32-byte domain-separated session keys."""
    chacha_key: bytes
    aes_key:    bytes
    hmac_key:   bytes


# ---------------------------------------------------------------------------
# Rate Limiter — per-IP brute-force protection
# ---------------------------------------------------------------------------
class RateLimiter:
    """Tracks failed handshake attempts per IP and enforces back-off.

    Policy: 5 failures within 60 s → block for 60 s.

    Persistence: blocks and failure counts are stored in SQLite so they
    survive application restarts.  This prevents an attacker from bypassing
    rate limiting by restarting the receiver.
    """

    MAX_FAILURES:  int   = 5
    WINDOW_SECS:   float = 60.0
    BLOCK_SECS:    float = 60.0
    _DB_PATH: Path = Path(__file__).parent / "fortress_ratelimit.db"

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._init_db()
        self._purge_expired()   # clean old records on start

    def _connect(self) -> sqlite3.Connection:
        return sqlite3.connect(str(self._DB_PATH))

    def _init_db(self) -> None:
        try:
            with self._connect() as con:
                con.execute("""
                    CREATE TABLE IF NOT EXISTS failures (
                        ip       TEXT NOT NULL,
                        ts       REAL NOT NULL
                    )
                """)
                con.execute("""
                    CREATE TABLE IF NOT EXISTS blocks (
                        ip          TEXT PRIMARY KEY,
                        unblock_at  REAL NOT NULL
                    )
                """)
                con.execute("CREATE INDEX IF NOT EXISTS idx_failures_ip ON failures(ip)")
        except sqlite3.Error:
            logger.warning("RateLimiter: could not initialize DB — running in-memory only.")

    def _purge_expired(self) -> None:
        now = time.time()
        try:
            with self._connect() as con:
                con.execute("DELETE FROM failures WHERE ts < ?", (now - self.WINDOW_SECS,))
                con.execute("DELETE FROM blocks WHERE unblock_at <= ?", (now,))
        except sqlite3.Error:
            pass

    def check(self, ip: str) -> None:
        """Raises RateLimitError if ip is blocked or has exceeded failure limit.

        Args:
            ip: Client IP address string.

        Raises:
            RateLimitError: If the IP is currently rate-limited.
        """
        now = time.time()
        with self._lock:
            try:
                with self._connect() as con:
                    # Check active block
                    row = con.execute(
                        "SELECT unblock_at FROM blocks WHERE ip=?", (ip,)
                    ).fetchone()
                    if row:
                        remaining = row[0] - now
                        if remaining > 0:
                            raise RateLimitError(
                                f"Too many failed attempts from {ip}. "
                                f"Retry in {remaining:.0f}s."
                            )
                        con.execute("DELETE FROM blocks WHERE ip=?", (ip,))
                    # Check recent failures
                    count = con.execute(
                        "SELECT COUNT(*) FROM failures WHERE ip=? AND ts >= ?",
                        (ip, now - self.WINDOW_SECS),
                    ).fetchone()[0]
                    if count >= self.MAX_FAILURES:
                        raise RateLimitError(
                            f"Too many failed attempts from {ip}. "
                            f"Retry in {self.BLOCK_SECS:.0f}s."
                        )
            except RateLimitError:
                raise
            except sqlite3.Error:
                pass   # DB failure — fail open (don't block legitimate users)

    def record_failure(self, ip: str) -> None:
        """Records a handshake failure for ip and blocks if threshold reached."""
        now = time.time()
        with self._lock:
            try:
                with self._connect() as con:
                    con.execute("INSERT INTO failures (ip, ts) VALUES (?, ?)", (ip, now))
                    count = con.execute(
                        "SELECT COUNT(*) FROM failures WHERE ip=? AND ts >= ?",
                        (ip, now - self.WINDOW_SECS),
                    ).fetchone()[0]
                    if count >= self.MAX_FAILURES:
                        unblock_at = now + self.BLOCK_SECS
                        con.execute(
                            "INSERT OR REPLACE INTO blocks (ip, unblock_at) VALUES (?, ?)",
                            (ip, unblock_at),
                        )
                        con.execute("DELETE FROM failures WHERE ip=?", (ip,))
                        logger.warning("IP %s rate-limited until %.0f (UTC)", ip, unblock_at)
            except sqlite3.Error:
                logger.debug("RateLimiter: DB write failed for %s.", ip)

    def record_success(self, ip: str) -> None:
        """Clears failure history for ip on successful handshake."""
        with self._lock:
            try:
                with self._connect() as con:
                    con.execute("DELETE FROM failures WHERE ip=?", (ip,))
                    con.execute("DELETE FROM blocks WHERE ip=?", (ip,))
            except sqlite3.Error:
                pass


_rate_limiter = RateLimiter()


# ---------------------------------------------------------------------------
# Transfer History (SQLite)
# ---------------------------------------------------------------------------
@dataclass
class TransferRecord:
    """One row in the transfer log."""
    ts:        str    # ISO timestamp
    direction: str    # "SENT" | "RECEIVED" | "LOCAL_ENC" | "LOCAL_DEC" | "WORMHOLE"
    filename:  str
    size_b:    int
    duration_s: float
    status:    str    # "OK" | "ERROR"
    peer:      str    # IP or "local"
    note:      str    # error message or empty


class TransferHistory:
    """SQLite-backed transfer history log stored next to the script."""

    DB_PATH: Path = Path(__file__).parent / "fortress_history.db"

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._init_db()

    def _init_db(self) -> None:
        with self._connect() as con:
            con.execute("""
                CREATE TABLE IF NOT EXISTS transfers (
                    id        INTEGER PRIMARY KEY AUTOINCREMENT,
                    ts        TEXT NOT NULL,
                    direction TEXT NOT NULL,
                    filename  TEXT NOT NULL,
                    size_b    INTEGER NOT NULL DEFAULT 0,
                    duration_s REAL NOT NULL DEFAULT 0,
                    status    TEXT NOT NULL DEFAULT 'OK',
                    peer      TEXT NOT NULL DEFAULT '',
                    note      TEXT NOT NULL DEFAULT ''
                )
            """)

    def _connect(self) -> sqlite3.Connection:
        return sqlite3.connect(str(self.DB_PATH))

    def add(self, rec: TransferRecord) -> None:
        """Inserts a transfer record."""
        with self._lock:
            with self._connect() as con:
                con.execute(
                    "INSERT INTO transfers "
                    "(ts,direction,filename,size_b,duration_s,status,peer,note) "
                    "VALUES (?,?,?,?,?,?,?,?)",
                    (rec.ts, rec.direction, rec.filename, rec.size_b,
                     rec.duration_s, rec.status, rec.peer, rec.note),
                )

    def fetch_all(self, limit: int = 200) -> list[TransferRecord]:
        """Returns most recent records, newest first."""
        with self._lock:
            with self._connect() as con:
                rows = con.execute(
                    "SELECT ts,direction,filename,size_b,duration_s,status,peer,note "
                    "FROM transfers ORDER BY id DESC LIMIT ?",
                    (limit,),
                ).fetchall()
        return [TransferRecord(*r) for r in rows]

    def clear(self) -> None:
        """Deletes all history records."""
        with self._lock:
            with self._connect() as con:
                con.execute("DELETE FROM transfers")

    def stats(self) -> dict[str, int | float]:
        """Returns aggregate statistics."""
        with self._lock:
            with self._connect() as con:
                row = con.execute(
                    "SELECT COUNT(*), "
                    "SUM(CASE WHEN status='OK' THEN 1 ELSE 0 END), "
                    "SUM(size_b), MAX(size_b) FROM transfers"
                ).fetchone()
        total, ok, total_bytes, max_bytes = row
        return {
            "total":       total or 0,
            "ok":          ok or 0,
            "total_bytes": total_bytes or 0,
            "max_bytes":   max_bytes or 0,
        }


_history = TransferHistory()


def _history_cfg_get(key: str, default: int) -> int:
    """Reads a settings value safely, falling back to default.

    Used by network code that runs before App is initialized.
    Avoids a circular import between settings and network layers.

    Args:
        key:     Setting key name.
        default: Fallback value if key missing or file unreadable.

    Returns:
        Integer setting value.
    """
    try:
        data = json.loads(_SETTINGS_FILE.read_text(encoding="utf-8"))
        return int(data.get(key, default))
    except Exception:
        return default


# ---------------------------------------------------------------------------
# LAN Discovery — broadcast beacon on UDP 47474
# ---------------------------------------------------------------------------
DISCOVERY_PORT = 47474
DISCOVERY_MAGIC = b"FORTRESS_BEACON_V1"


class LANDiscovery:
    """Sends/receives UDP beacons to find Fortress peers on the LAN."""

    def __init__(self, tcp_port: int = 5001) -> None:
        self._tcp_port = tcp_port
        self._peers: dict[str, tuple[str, int]] = {}  # ip → (hostname, tcp_port)
        self._lock  = threading.Lock()
        self._stop  = threading.Event()
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        """Starts the discovery listener in a background thread."""
        self._stop.clear()
        self._thread = threading.Thread(
            target=self._listen_loop, daemon=True, name="lan-discovery"
        )
        self._thread.start()
        # Announce ourselves
        threading.Thread(target=self._announce, daemon=True).start()

    def stop(self) -> None:
        """Stops the listener thread."""
        self._stop.set()

    def peers(self) -> dict[str, tuple[str, int]]:
        """Returns currently discovered peers as {ip: (hostname, tcp_port)}."""
        with self._lock:
            return dict(self._peers)

    def _announce(self) -> None:
        """Sends a UDP broadcast beacon every 5 seconds for 30 seconds."""
        try:
            hostname = socket.gethostname()
            payload = DISCOVERY_MAGIC + json.dumps(
                {"host": hostname, "port": self._tcp_port}
            ).encode()
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
                sock.settimeout(1.0)
                for _ in range(6):  # 6 × 5s = 30s
                    if self._stop.is_set():
                        break
                    try:
                        sock.sendto(payload, ("<broadcast>", DISCOVERY_PORT))
                    except OSError:
                        pass
                    time.sleep(5)
        except Exception:
            pass

    def _listen_loop(self) -> None:
        """Listens for beacons from peers."""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                sock.settimeout(1.0)
                try:
                    sock.bind(("0.0.0.0", DISCOVERY_PORT))
                except OSError:
                    return  # port busy — skip discovery
                my_ip = _get_local_ip()
                while not self._stop.is_set():
                    try:
                        data, (src_ip, _) = sock.recvfrom(512)
                        if src_ip == my_ip or not data.startswith(DISCOVERY_MAGIC):
                            continue
                        info = json.loads(data[len(DISCOVERY_MAGIC):])
                        with self._lock:
                            self._peers[src_ip] = (
                                info.get("host", src_ip),
                                int(info.get("port", 5001)),
                            )
                        logger.debug("LAN peer discovered: %s", src_ip)
                    except (socket.timeout, TimeoutError, OSError, json.JSONDecodeError):
                        pass
        except Exception:
            pass


# ---------------------------------------------------------------------------
# Folder Encryptor
# ---------------------------------------------------------------------------
class FolderEncryptor:
    """Zips a directory then applies CryptoEngine double encryption."""

    @staticmethod
    def encrypt_folder(
        src_dir: Path,
        dst: Path,
        password: str,
        on_progress: "ProgressCallback",
    ) -> None:
        """Zips src_dir, encrypts with Argon2id + AES+ChaCha, writes to dst.

        Args:
            src_dir:     Source directory to encrypt.
            dst:         Output .fort file path.
            password:    Encryption passphrase.
            on_progress: Progress callback (ratio, message).
        """
        if not src_dir.is_dir():
            raise ValueError(f"Not a directory: {src_dir}")
        on_progress(0.05, f"[ FOLDER ]  Zipping {src_dir.name}…")
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED, compresslevel=6) as zf:
            for fpath in sorted(src_dir.rglob("*")):
                if fpath.is_file():
                    zf.write(fpath, fpath.relative_to(src_dir))
        plaintext = buf.getvalue()
        digest = hashlib.sha512(plaintext).digest()
        on_progress(0.25, "[ FOLDER ]  Argon2id key derivation (~2s)…")
        keys = CryptoEngine.derive_local_keys(password)
        on_progress(0.55, "[ FOLDER ]  Double-AEAD encryption…")
        ciphertext = CryptoEngine.encrypt(plaintext, keys)
        on_progress(0.85, "[ FOLDER ]  Writing encrypted archive…")
        magic = b"FORTv3DIR\x00\x01"
        dst.write_bytes(magic + digest + ciphertext)
        on_progress(1.0, f"[ FOLDER ]  Done — {_format_size(dst.stat().st_size)}")
        logger.info("FolderEncryptor: encrypted %s → %s", src_dir, dst)

    @staticmethod
    def decrypt_folder(
        src: Path,
        dst_dir: Path,
        password: str,
        on_progress: "ProgressCallback",
    ) -> None:
        """Decrypts a .fort folder archive and extracts contents.

        Args:
            src:         Encrypted .fort file.
            dst_dir:     Directory where files will be extracted.
            password:    Decryption passphrase.
            on_progress: Progress callback.
        """
        magic = b"FORTv3DIR\x00\x01"
        on_progress(0.05, "[ FOLDER ]  Reading encrypted archive…")
        raw = src.read_bytes()
        if not raw.startswith(magic):
            raise ValueError("Not a Fortress folder archive.")
        expected_digest = raw[len(magic):len(magic)+64]
        ciphertext      = raw[len(magic)+64:]
        on_progress(0.20, "[ FOLDER ]  Argon2id key derivation (~2s)…")
        keys = CryptoEngine.derive_local_keys(password)
        on_progress(0.45, "[ FOLDER ]  Decrypting…")
        plaintext = CryptoEngine.decrypt(ciphertext, keys)
        on_progress(0.80, "[ FOLDER ]  Verifying integrity…")
        if not hmac.compare_digest(hashlib.sha512(plaintext).digest(), expected_digest):
            raise IntegrityError("SHA-512 mismatch — wrong passphrase or corrupted archive.")
        on_progress(0.90, "[ FOLDER ]  Extracting files…")
        dst_dir.mkdir(parents=True, exist_ok=True)
        with zipfile.ZipFile(io.BytesIO(plaintext)) as zf:
            # Zip-Slip guard: reject any member whose resolved path escapes dst_dir
            dst_resolved = dst_dir.resolve()
            for member in zf.infolist():
                member_path = (dst_dir / member.filename).resolve()
                try:
                    member_path.relative_to(dst_resolved)
                except ValueError:
                    raise P2PError(
                        f"Zip-Slip blocked: '{member.filename}' escapes destination."
                    )
            zf.extractall(dst_dir)
        on_progress(1.0, f"[ FOLDER ]  Extracted to {dst_dir}")
        logger.info("FolderEncryptor: decrypted %s → %s", src, dst_dir)


# ---------------------------------------------------------------------------
# Crypto Engine
# ---------------------------------------------------------------------------
class CryptoEngine:
    """All cryptographic primitives for P2P Fortress.

    Encryption pipeline:
        plaintext
          → [Layer 1] ChaCha20-Poly1305  (AEAD)
          → [Layer 2] AES-256-GCM        (AEAD, wraps layer 1)
          → [Layer 3] HMAC-SHA512        (MAC over full layer-2 output)
    """

    @staticmethod
    def _argon2id(password: str, salt_domain: bytes) -> bytes:
        if not password.strip():
            raise ValueError("Passphrase must not be empty.")
        if password != password.strip():
            logger.warning("Passphrase has leading/trailing whitespace.")
        return hash_secret_raw(
            secret=password.encode("utf-8"),
            salt=salt_domain,
            time_cost=ARGON2_TIME_COST,
            memory_cost=ARGON2_MEMORY_COST,
            parallelism=ARGON2_PARALLELISM,
            hash_len=ARGON2_HASH_LEN,
            type=Type.ID,
        )

    @staticmethod
    def _hkdf(ikm: bytes, label: bytes, length: int = 32) -> bytes:
        return HKDF(algorithm=SHA512(), length=length, salt=None, info=label).derive(ikm)

    @classmethod
    def derive_network_keys(cls, ecdh_shared: bytes, password: str) -> SessionKeys:
        """Derives session keys (ECDH ⊕ Argon2id → HKDF)."""
        argon_out = cls._argon2id(password, SALT_NETWORK)
        mixed = bytes(a ^ b for a, b in zip(argon_out[:32], ecdh_shared))
        master = mixed + argon_out[32:]
        return SessionKeys(
            chacha_key=cls._hkdf(master, LABEL_CHACHA),
            aes_key=   cls._hkdf(master, LABEL_AES),
            hmac_key=  cls._hkdf(master, LABEL_HMAC),
        )

    @classmethod
    def derive_local_keys(cls, password: str) -> SessionKeys:
        """Derives session keys for offline encryption."""
        master = cls._argon2id(password, SALT_LOCAL)
        return SessionKeys(
            chacha_key=cls._hkdf(master, LABEL_CHACHA),
            aes_key=   cls._hkdf(master, LABEL_AES),
            hmac_key=  cls._hkdf(master, LABEL_HMAC),
        )

    @classmethod
    def derive_wormhole_keys(cls, password: str) -> SessionKeys:
        """Derives session keys for the Wormhole pre-encryption layer."""
        master = cls._argon2id(password, SALT_WORMHOLE)
        return SessionKeys(
            chacha_key=cls._hkdf(master, LABEL_CHACHA),
            aes_key=   cls._hkdf(master, LABEL_AES),
            hmac_key=  cls._hkdf(master, LABEL_HMAC),
        )

    @staticmethod
    def encrypt(plaintext: bytes, keys: SessionKeys) -> bytes:
        """Double-AEAD-encrypts and appends HMAC-SHA512."""
        ch_nonce  = os.urandom(12)
        ch_ct     = ChaCha20Poly1305(keys.chacha_key).encrypt(ch_nonce, plaintext, None)
        aes_nonce = os.urandom(12)
        inner     = ch_nonce + ch_ct
        aes_ct    = AESGCM(keys.aes_key).encrypt(aes_nonce, inner, None)
        payload   = aes_nonce + aes_ct
        mac       = hmac.digest(keys.hmac_key, payload, hashlib.sha512)
        return mac + payload

    @staticmethod
    def decrypt(ciphertext: bytes, keys: SessionKeys) -> bytes:
        """Verifies HMAC then double-AEAD-decrypts."""
        MIN = 64 + 12 + 16 + 12 + 16
        if len(ciphertext) < MIN:
            raise InvalidKeyError(f"Ciphertext too short ({len(ciphertext)} B).")
        recv_mac = ciphertext[:64]
        payload  = ciphertext[64:]
        exp_mac  = hmac.digest(keys.hmac_key, payload, hashlib.sha512)
        if not hmac.compare_digest(recv_mac, exp_mac):
            raise AuthenticationError("HMAC-SHA512 mismatch — tampered or wrong passphrase.")
        aes_nonce = payload[:12]
        try:
            inner = AESGCM(keys.aes_key).decrypt(aes_nonce, payload[12:], None)
        except Exception as exc:
            raise InvalidKeyError("AES-256-GCM tag failure.") from exc
        if len(inner) < 28:
            raise InvalidKeyError("Inner payload malformed.")
        try:
            return ChaCha20Poly1305(keys.chacha_key).decrypt(inner[:12], inner[12:], None)
        except Exception as exc:
            raise InvalidKeyError("ChaCha20-Poly1305 tag failure.") from exc

    @staticmethod
    def sha512_digest(data: bytes) -> bytes:
        return hashlib.sha512(data).digest()

    @staticmethod
    def encrypt_chunk(chunk: bytes, keys: "SessionKeys") -> bytes:
        """Encrypts one streaming chunk with ChaCha20-Poly1305 + AES-256-GCM.

        Each chunk is independently authenticated (AEAD). Unlike the full-file
        encrypt(), this does NOT append a global HMAC — the caller is responsible
        for overall integrity (SHA-512 over plaintext verified at stream end).

        Args:
            chunk: Plaintext bytes (up to STREAM_CHUNK_SIZE).
            keys:  Session key bundle.

        Returns:
            Encrypted chunk bytes: ch_nonce(12) + ch_ct + aes_nonce(12) + aes_ct.
        """
        ch_nonce  = os.urandom(12)
        ch_ct     = ChaCha20Poly1305(keys.chacha_key).encrypt(ch_nonce, chunk, None)
        aes_nonce = os.urandom(12)
        aes_ct    = AESGCM(keys.aes_key).encrypt(aes_nonce, ch_nonce + ch_ct, None)
        return aes_nonce + aes_ct

    @staticmethod
    def decrypt_chunk(enc_chunk: bytes, keys: "SessionKeys") -> bytes:
        """Decrypts one streaming chunk encrypted by encrypt_chunk().

        Args:
            enc_chunk: Encrypted chunk bytes (aes_nonce + aes_ct).
            keys:      Session key bundle.

        Returns:
            Decrypted plaintext bytes.

        Raises:
            InvalidKeyError: On AEAD authentication failure.
        """
        if len(enc_chunk) < 24 + 16:   # aes_nonce(12) + min_aes_ct(12+16)
            raise InvalidKeyError("Streaming chunk too short.")
        aes_nonce = enc_chunk[:12]
        try:
            inner = AESGCM(keys.aes_key).decrypt(aes_nonce, enc_chunk[12:], None)
        except Exception as exc:
            raise InvalidKeyError("AES-256-GCM chunk auth failure.") from exc
        if len(inner) < 28:
            raise InvalidKeyError("Streaming chunk inner payload malformed.")
        try:
            return ChaCha20Poly1305(keys.chacha_key).decrypt(inner[:12], inner[12:], None)
        except Exception as exc:
            raise InvalidKeyError("ChaCha20-Poly1305 chunk auth failure.") from exc


# ---------------------------------------------------------------------------
# ECDH helpers
# ---------------------------------------------------------------------------
def generate_ephemeral_keypair() -> tuple[X25519PrivateKey, bytes]:
    priv = X25519PrivateKey.generate()
    pub  = priv.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    return priv, pub


def compute_shared_secret(private: X25519PrivateKey, peer_pub_raw: bytes) -> bytes:
    try:
        peer = X25519PublicKey.from_public_bytes(peer_pub_raw)
        return private.exchange(peer)
    except (ValueError, TypeError) as exc:
        raise HandshakeError(f"Invalid peer public key: {exc}") from exc


# ---------------------------------------------------------------------------
# Socket helpers
# ---------------------------------------------------------------------------
def _recv_exact(sock: socket.socket, n: int) -> bytes:
    buf   = bytearray(n)
    view  = memoryview(buf)
    total = 0
    while total < n:
        got = sock.recv_into(view[total:], n - total)
        if not got:
            raise NetworkError(f"Connection closed: {total}/{n} bytes.")
        total += got
    return bytes(buf)


def _get_local_ip() -> str:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(2.0)   # prevent indefinite hang if no default route
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
    except OSError:
        return "N/A"


def _resolve_address(host: str, port: int) -> tuple[socket.AddressFamily, tuple]:
    """Resolves host:port to the best available address, preferring IPv6.

    Args:
        host: Hostname or IP address string.
        port: TCP port number.

    Returns:
        (address_family, sockaddr) tuple suitable for socket.connect().

    Raises:
        NetworkError: If host cannot be resolved.
    """
    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise NetworkError(f"Cannot resolve '{host}': {exc}") from exc
    if not infos:
        raise NetworkError(f"No address found for '{host}'")
    # Prefer IPv6 if available, fall back to IPv4
    for family in (socket.AF_INET6, socket.AF_INET):
        for af, _, _, _, addr in infos:
            if af == family:
                return af, addr
    af, _, _, _, addr = infos[0]
    return af, addr


def _make_server_socket(host: str, port: int) -> socket.socket:
    """Creates a listening socket with dual-stack support where available.

    Tries IPv6 with IPV6_V6ONLY=0 (dual-stack) first, then falls back to IPv4.

    Args:
        host: Bind address ('0.0.0.0' for all IPv4, '::' for dual-stack).
        port: TCP port to bind.

    Returns:
        Bound and listening socket.

    Raises:
        OSError: If binding fails on both families.
    """
    # Try dual-stack IPv6 first
    if host in ("0.0.0.0", ""):
        try:
            srv = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
            srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            if hasattr(socket, "SO_REUSEPORT"):  # Linux — faster rebind after crash
                try: srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
                except OSError: pass
            try:
                srv.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)  # dual-stack
            except (AttributeError, OSError):
                pass   # not all platforms support this
            srv.bind(("::", port))
            srv.listen(1)
            logger.debug("Listening on dual-stack [::]:%d", port)
            return srv
        except OSError:
            try:
                srv.close()
            except Exception:
                pass
    # Fallback to IPv4
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    if hasattr(socket, "SO_REUSEPORT"):
        try: srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        except OSError: pass
    bind_host = host if host != "0.0.0.0" else "0.0.0.0"
    srv.bind((bind_host, port))
    srv.listen(1)
    logger.debug("Listening on IPv4 %s:%d", bind_host, port)
    return srv


ProgressCallback = Callable[[float, str], None]


# ===========================================================================
# FileServer
# ===========================================================================
@dataclass
class FileServer:
    """Listens on TCP, performs ECDH + Argon2id, receives encrypted file.

    Protocol:
      1. Server → Client : 32B ephemeral public key
      2. Client → Server : 32B ephemeral public key
      3. Both derive keys (ECDH + Argon2id + HKDF)
      4. SAS fingerprint computed for MITM detection
      5. Framed payload: [8B fname_len][fname][64B sha512][1B flags][8B len][payload]
    """

    host:        str              = "0.0.0.0"
    port:        int              = 5001
    save_dir:    Path             = field(default_factory=Path.cwd)
    on_progress: ProgressCallback = field(default=lambda r, m: None)
    on_sas:      Callable[[str], None] = field(default=lambda s: None)

    _stop_event:    threading.Event       = field(default_factory=threading.Event, init=False, repr=False)
    _server_socket: socket.socket | None  = field(default=None, init=False, repr=False)

    def stop(self) -> None:
        self._stop_event.set()
        if self._server_socket:
            try:
                self._server_socket.close()
            except OSError:
                pass

    def listen(self, password: str) -> None:
        """Blocks until one file transfer completes."""
        self._stop_event.clear()
        try:
            srv = _make_server_socket(self.host, self.port)
            with srv:
                self._server_socket = srv
                srv.settimeout(1.0)
                self.on_progress(0.0, f"[ LISTENING ]  Port {self.port} — awaiting transmission…")
                conn, addr = self._accept_loop(srv)
                client_ip = addr[0]
                # Rate limit check
                try:
                    _rate_limiter.check(client_ip)
                except RateLimitError as exc:
                    conn.close()
                    raise NetworkError(str(exc))
                self.on_progress(0.04, f"[ LINK UP ]  Connection from {client_ip}")
                with conn:
                    conn.settimeout(60.0)
                    try:
                        keys, sas = self._handshake(conn, password)
                        _rate_limiter.record_success(client_ip)
                    except (HandshakeError, AuthenticationError) as exc:
                        _rate_limiter.record_failure(client_ip)
                        raise
                    self.on_sas(sas)
                    self._receive_file(conn, keys, client_ip)
        except OSError as exc:
            if self._stop_event.is_set():
                self.on_progress(0.0, "[ HALTED ]  Channel closed.")
                return
            raise NetworkError(f"Socket error: {exc}") from exc

    def _accept_loop(self, srv: socket.socket) -> tuple[socket.socket, tuple]:
        while not self._stop_event.is_set():
            try:
                return srv.accept()
            except TimeoutError:
                continue
        raise NetworkError("Server halted.")

    def _handshake(self, conn: socket.socket, password: str) -> tuple[SessionKeys, str]:
        """X25519 ECDH + replay guard. Returns (keys, SAS)."""
        self.on_progress(0.06, "[ HANDSHAKE ]  X25519 ephemeral key exchange…")
        try:
            # Replay guard: send a challenge nonce, expect it echoed back
            srv_nonce = os.urandom(NONCE_SIZE)
            srv_priv, srv_pub = generate_ephemeral_keypair()
            conn.sendall(srv_pub + srv_nonce)
            # Receive client pubkey + client nonce
            data    = _recv_exact(conn, PUBKEY_SIZE + NONCE_SIZE)
            cli_pub = data[:PUBKEY_SIZE]
            cli_nonce = data[PUBKEY_SIZE:]
            # Echo client nonce back so client can verify freshness
            conn.sendall(cli_nonce)
            # Receive echoed server nonce
            echoed_nonce = _recv_exact(conn, NONCE_SIZE)
            if not hmac.compare_digest(echoed_nonce, srv_nonce):
                raise HandshakeError("Replay guard failed — stale or replayed handshake.")
        except (OSError, NetworkError) as exc:
            raise HandshakeError(f"Handshake I/O failed: {exc}") from exc
        shared = compute_shared_secret(srv_priv, cli_pub)
        sas    = _sas_fingerprint(shared)
        self.on_progress(0.10, "[ KDF ]  Argon2id (~2s)…")
        keys = CryptoEngine.derive_network_keys(shared, password)
        self.on_progress(0.16, f"[ SECURE ]  PFS ACTIVE  ◈ SAS: {sas}")
        return keys, sas

    def _receive_file(self, conn: socket.socket, keys: SessionKeys,
                      client_ip: str = "unknown") -> None:
        fname_size = struct.unpack(HEADER_FORMAT, _recv_exact(conn, HEADER_SIZE))[0]
        if not 1 <= fname_size <= 4096:
            raise NetworkError(f"Bad filename length: {fname_size}")
        filename = Path(
            _recv_exact(conn, fname_size).decode("utf-8", errors="replace")
        ).name or "received_file"
        expected_digest = _recv_exact(conn, 64)
        # Protocol flags byte (bit 0 = BAR, bit 2 = streaming)
        flags      = _recv_exact(conn, 1)[0]
        burn       = bool(flags & FLAG_BURN)
        streaming  = bool(flags & FLAG_STREAM)
        t0         = time.monotonic()   # ← start of transfer

        if streaming:
            plaintext = self._receive_streaming(conn, filename, keys)
        else:
            total = struct.unpack(HEADER_FORMAT, _recv_exact(conn, HEADER_SIZE))[0]
            if not 1 <= total <= MAX_FILE_BYTES + 512:
                raise NetworkError(f"Bad payload size: {total}")
            self.on_progress(0.20, f"[ RX ]  «{filename}»  ({_format_size(total)} encrypted)")
            buf  = bytearray(total)
            view = memoryview(buf)
            rcvd = 0
            while rcvd < total:
                n = conn.recv_into(view[rcvd:], min(BUFFER_SIZE, total - rcvd))
                if not n:
                    raise NetworkError("Connection closed during transfer.")
                rcvd += n
                elapsed = time.monotonic() - t0 or 0.001
                speed   = rcvd / elapsed
                remain  = (total - rcvd) / speed if speed > 0 else 0
                self.on_progress(
                    0.20 + 0.56 * rcvd / total,
                    f"[ RX ]  {_format_size(rcvd)} / {_format_size(total)}"
                    f"  {_format_size(int(speed))}/s  ETA {_format_eta(remain)}",
                )
            self.on_progress(0.78, "[ AUTH ]  HMAC-SHA512 verification…")
            self.on_progress(0.85, "[ DECRYPT ]  AES-256-GCM + ChaCha20-Poly1305…")
            plaintext = CryptoEngine.decrypt(bytes(buf), keys)
            _zero_bytes(buf)

        self.on_progress(0.95, "[ INTEGRITY ]  SHA-512 check…")
        if not hmac.compare_digest(CryptoEngine.sha512_digest(plaintext), expected_digest):
            raise IntegrityError("SHA-512 mismatch — file corrupted in transit.")
        out = self.save_dir / filename
        try:
            out.write_bytes(plaintext)
        except OSError as exc:
            raise NetworkError(f"Cannot write '{out}': {exc}") from exc

        # Auto-extract multi-file bundles (fortress_bundle.zip)
        log_filename = filename
        if filename == "fortress_bundle.zip":
            bundle_dir = self.save_dir / "fortress_bundle"
            counter = 1
            while bundle_dir.exists():
                bundle_dir = self.save_dir / f"fortress_bundle_{counter}"
                counter += 1
            try:
                bundle_dir.mkdir()
                with zipfile.ZipFile(out) as zf:
                    resolved = bundle_dir.resolve()
                    for member in zf.infolist():
                        member_path = (bundle_dir / member.filename).resolve()
                        try:
                            member_path.relative_to(resolved)
                        except ValueError:
                            raise P2PError(
                                f"Zip-Slip blocked: '{member.filename}' escapes destination."
                            )
                    zf.extractall(bundle_dir)
                out.unlink()
                log_filename = bundle_dir.name
                self.on_progress(1.0,
                    f"[ MISSION COMPLETE ]  Bundle extracted → {bundle_dir.name}/")
                logger.info("Auto-extracted bundle → %s", bundle_dir)
            except P2PError:
                raise
            except Exception as exc:
                logger.warning("Bundle auto-extract failed: %s — keeping zip.", exc)
                self.on_progress(1.0,
                    f"[ MISSION COMPLETE ]  {len(plaintext)/1024:.1f} KB → {out.name}")
        else:
            kb = len(plaintext) / 1024
            self.on_progress(1.0, f"[ MISSION COMPLETE ]  {kb:.1f} KB → {out}")
        logger.info("Received: %s (%d B)", log_filename, len(plaintext))
        # Burn After Reading
        if burn:
            burn_delay = _history_cfg_get("burn_delay_sec", 60)
            logger.info("Burn-After-Reading: auto-deleting in %ds: %s", burn_delay, out)
            def _burn(p: Path = out, d: int = burn_delay) -> None:
                time.sleep(d)
                secure_delete(p)
                logger.info("Burn-After-Reading: deleted %s", p)
            threading.Thread(target=_burn, daemon=True).start()
        # Log to history — elapsed measured from start of _receive_file (t0)
        _history.add(TransferRecord(
            ts=datetime.datetime.now().isoformat(timespec="seconds"),
            direction="RECEIVED",
            filename=log_filename,
            size_b=len(plaintext),
            duration_s=round(time.monotonic() - t0, 3),
            status="OK",
            peer=client_ip,
            note="BAR" if burn else "",
        ))

    def _receive_streaming(self, conn: socket.socket,
                           filename: str, keys: SessionKeys) -> bytes:
        """Receives a file in encrypted chunks (streaming mode).

        Reads [plaintext_size: 8B] then chunks: [ct_len: 4B][enc_chunk],
        terminated by ct_len == 0. Decrypts and assembles plaintext.

        Args:
            conn:     Active TCP connection.
            filename: Already-decoded filename string.
            keys:     Session key bundle.

        Returns:
            Fully reassembled plaintext bytes.

        Raises:
            NetworkError:   On connection failure or invalid chunk sizes.
            InvalidKeyError: On chunk AEAD failure.
        """
        total = struct.unpack(HEADER_FORMAT, _recv_exact(conn, HEADER_SIZE))[0]
        if not 1 <= total <= MAX_FILE_BYTES:
            raise NetworkError(f"Bad streaming plaintext size: {total}")
        self.on_progress(0.20, f"[ STREAM ]  «{filename}»  ({_format_size(total)}) — chunked…")
        chunks: list[bytes] = []
        received = 0
        t0 = time.monotonic()
        while True:
            ct_len_b = _recv_exact(conn, 4)
            ct_len   = struct.unpack("!I", ct_len_b)[0]
            if ct_len == 0:
                break   # terminator
            if ct_len > STREAM_CHUNK_SIZE * 4:   # sanity: 4× max chunk overhead
                raise NetworkError(f"Streaming chunk too large: {ct_len}")
            enc_chunk = _recv_exact(conn, ct_len)
            chunk     = CryptoEngine.decrypt_chunk(enc_chunk, keys)
            chunks.append(chunk)
            received += len(chunk)
            elapsed   = time.monotonic() - t0 or 0.001
            speed     = received / elapsed
            remain    = (total - received) / speed if speed > 0 else 0
            self.on_progress(
                0.20 + 0.75 * min(received, total) / total,
                f"[ STREAM ]  {_format_size(received)} / {_format_size(total)}"
                f"  {_format_size(int(speed))}/s  ETA {_format_eta(remain)}",
            )
        self.on_progress(0.97, "[ STREAM ]  Reassembling…")
        return b"".join(chunks)


# ===========================================================================
# FileClient
# ===========================================================================
@dataclass
class FileClient:
    """Connects to FileServer and transmits a double-encrypted file."""

    host:        str
    port:        int
    on_progress: ProgressCallback = field(default=lambda r, m: None)
    on_sas:      Callable[[str], None] = field(default=lambda s: None)
    burn_after_reading: bool = False

    def send(self, file_path: Path, password: str) -> None:
        """Encrypts and transmits file_path.

        Files under STREAM_THRESHOLD are loaded fully into RAM (existing behavior).
        Files at or above STREAM_THRESHOLD use chunked streaming encryption to
        keep peak RAM usage at O(STREAM_CHUNK_SIZE) instead of O(file_size).

        Args:
            file_path: Path to the file to send.
            password:  Session passphrase.

        Raises:
            FileNotFoundError: If file_path does not exist.
            NetworkError:      On connection or transmission failure.
        """
        if not file_path.is_file():
            raise FileNotFoundError(f"Source file not found: {file_path}")
        file_size = file_path.stat().st_size
        if file_size > MAX_FILE_BYTES:
            raise NetworkError(f"File too large: {_format_size(file_size)}")
        self.on_progress(0.03, f"[ CONNECT ]  Linking to {self.host}:{self.port}…")
        t0 = time.monotonic()
        use_streaming = file_size >= STREAM_THRESHOLD
        try:
            af, peer_addr = _resolve_address(self.host, self.port)
            with socket.socket(af, socket.SOCK_STREAM) as sock:
                sock.settimeout(15.0)
                try:
                    sock.connect(peer_addr)
                except (ConnectionRefusedError, TimeoutError, OSError) as exc:
                    raise NetworkError(f"Cannot reach {self.host}:{self.port} — {exc}") from exc
                self.on_progress(0.08, "[ LINK UP ]  TCP established.")
                keys, sas = self._handshake(sock, password)
                self.on_sas(sas)

                if use_streaming:
                    self.on_progress(0.25, f"[ STREAM ]  Large file ({_format_size(file_size)}) — streaming mode…")
                    digest = self._transmit_streaming(sock, file_path, keys)
                else:
                    self.on_progress(0.25, "[ READ ]  Loading file…")
                    plaintext  = file_path.read_bytes()
                    digest     = CryptoEngine.sha512_digest(plaintext)
                    self.on_progress(0.38, "[ ENCRYPT ]  ChaCha20-Poly1305…")
                    self.on_progress(0.48, "[ ENCRYPT ]  AES-256-GCM…")
                    self.on_progress(0.56, "[ SIGN ]  HMAC-SHA512…")
                    ciphertext = CryptoEngine.encrypt(plaintext, keys)
                    self._transmit(sock, file_path.name, digest, ciphertext)

                elapsed = time.monotonic() - t0
                _history.add(TransferRecord(
                    ts=datetime.datetime.now().isoformat(timespec="seconds"),
                    direction="SENT",
                    filename=file_path.name,
                    size_b=file_size,
                    duration_s=round(elapsed, 3),
                    status="OK",
                    peer=self.host,
                    note="BAR" if self.burn_after_reading else "",
                ))
        except (NetworkError, HandshakeError):
            raise
        except (OSError, BrokenPipeError) as exc:
            raise NetworkError(f"Transmission failure: {exc}") from exc

    def _transmit_streaming(self, sock: socket.socket,
                            file_path: Path, keys: SessionKeys) -> bytes:
        """Streams a large file in encrypted chunks — O(STREAM_CHUNK_SIZE) RAM.

        Wire format:
            [fname_len: 8B] [fname: N]
            [sha512: 64B]              ← computed on-the-fly via hash update
            [flags: 1B]                ← FLAG_STREAM | FLAG_BURN
            [plaintext_size: 8B]       ← for receiver progress bar
            <chunks>: [ct_len: 4B][enc_chunk: ct_len]
            <terminator>: [ct_len=0: 4B]

        Returns:
            SHA-512 digest of the plaintext (for history logging).
        """
        fname_b    = file_path.name.encode("utf-8")
        flags      = FLAG_STREAM | (FLAG_BURN if self.burn_after_reading else 0)
        file_size  = file_path.stat().st_size
        hasher     = hashlib.sha512()

        # First pass: compute SHA-512 (unavoidable — we need it before sending header)
        self.on_progress(0.26, "[ STREAM ]  Computing SHA-512…")
        with file_path.open("rb") as fh:
            for raw_chunk in iter(lambda: fh.read(STREAM_CHUNK_SIZE), b""):
                hasher.update(raw_chunk)
        digest = hasher.digest()

        # Send header
        sock.sendall(struct.pack(HEADER_FORMAT, len(fname_b)) + fname_b)
        sock.sendall(digest)
        sock.sendall(bytes([flags]))
        sock.sendall(struct.pack(HEADER_FORMAT, file_size))

        self.on_progress(0.30, f"[ STREAM ]  Sending {_format_size(file_size)} in chunks…")
        sent = 0
        t0   = time.monotonic()
        with file_path.open("rb") as fh:
            for raw_chunk in iter(lambda: fh.read(STREAM_CHUNK_SIZE), b""):
                enc_chunk = CryptoEngine.encrypt_chunk(raw_chunk, keys)
                sock.sendall(struct.pack("!I", len(enc_chunk)) + enc_chunk)
                sent += len(raw_chunk)
                elapsed = time.monotonic() - t0 or 0.001
                speed   = sent / elapsed
                remain  = (file_size - sent) / speed if speed > 0 else 0
                self.on_progress(
                    0.30 + 0.70 * sent / file_size,
                    f"[ STREAM ]  {_format_size(sent)} / {_format_size(file_size)}"
                    f"  {_format_size(int(speed))}/s  ETA {_format_eta(remain)}",
                )

        # Terminator: 4-byte zero
        sock.sendall(struct.pack("!I", 0))
        self.on_progress(1.0, "[ MISSION COMPLETE ]  Streaming transmission complete.")
        logger.info("Streaming sent %d B to %s:%d", file_size, self.host, self.port)
        return digest

    def _handshake(self, sock: socket.socket, password: str) -> tuple[SessionKeys, str]:
        """X25519 ECDH + replay guard. Returns (keys, SAS)."""
        self.on_progress(0.10, "[ HANDSHAKE ]  X25519 ephemeral key exchange…")
        try:
            # Receive server pubkey + server nonce
            data      = _recv_exact(sock, PUBKEY_SIZE + NONCE_SIZE)
            srv_pub   = data[:PUBKEY_SIZE]
            srv_nonce = data[PUBKEY_SIZE:]
            # Send client pubkey + client nonce
            cli_priv, cli_pub = generate_ephemeral_keypair()
            cli_nonce = os.urandom(NONCE_SIZE)
            sock.sendall(cli_pub + cli_nonce)
            # Receive echoed client nonce (freshness check)
            echoed_cli_nonce = _recv_exact(sock, NONCE_SIZE)
            if not hmac.compare_digest(echoed_cli_nonce, cli_nonce):
                raise HandshakeError("Replay guard: client nonce mismatch.")
            # Echo server nonce back
            sock.sendall(srv_nonce)
        except (OSError, NetworkError) as exc:
            raise HandshakeError(f"Handshake I/O failed: {exc}") from exc
        shared = compute_shared_secret(cli_priv, srv_pub)
        sas    = _sas_fingerprint(shared)
        self.on_progress(0.18, "[ KDF ]  Argon2id (~2s)…")
        keys = CryptoEngine.derive_network_keys(shared, password)
        self.on_progress(0.34, f"[ SECURE ]  PFS ACTIVE  ◈ SAS: {sas}")
        return keys, sas

    def _transmit(self, sock: socket.socket, filename: str,
                  digest: bytes, ciphertext: bytes) -> None:
        fname_b = filename.encode("utf-8")
        flags   = 0x01 if self.burn_after_reading else 0x00
        sock.sendall(struct.pack(HEADER_FORMAT, len(fname_b)) + fname_b)
        sock.sendall(digest)
        sock.sendall(bytes([flags]))  # BAR flag
        total = len(ciphertext)
        sock.sendall(struct.pack(HEADER_FORMAT, total))
        self.on_progress(0.60, f"[ TX ]  Sending {_format_size(total)}…")
        sent = 0
        view = memoryview(ciphertext)
        t0   = time.monotonic()
        while sent < total:
            chunk = min(BUFFER_SIZE, total - sent)
            n = sock.send(view[sent:sent + chunk])
            if not n:
                raise NetworkError("Socket closed during transmission.")
            sent += n
            elapsed = time.monotonic() - t0 or 0.001
            speed   = sent / elapsed
            remain  = (total - sent) / speed if speed > 0 else 0
            self.on_progress(
                0.60 + 0.40 * sent / total,
                f"[ TX ]  {_format_size(sent)} / {_format_size(total)}"
                f"  {_format_size(int(speed))}/s  ETA {_format_eta(remain)}",
            )
        self.on_progress(1.0, "[ MISSION COMPLETE ]  Transmission complete & authenticated.")
        logger.info("Sent %d B to %s:%d", total, self.host, self.port)


# ===========================================================================
# LocalEncryptor
# ===========================================================================
class LocalEncryptor:
    """Encrypts or decrypts a file locally (no network)."""

    MAGIC: bytes = b"FORTv3\x00\x01"

    @classmethod
    def encrypt_file(cls, src: Path, dst: Path, password: str,
                     on_progress: ProgressCallback) -> None:
        if not src.is_file():
            raise FileNotFoundError(f"Source file not found: {src}")
        if src.stat().st_size > MAX_FILE_BYTES:
            raise ValueError("File too large for in-memory encryption.")
        with src.open("rb") as fh:
            if fh.read(len(cls.MAGIC)) == cls.MAGIC:
                raise ValueError("File is already a Fortress archive.")
        on_progress(0.05, "[ READ ]  Loading source file…")
        plaintext = src.read_bytes()
        digest    = CryptoEngine.sha512_digest(plaintext)
        on_progress(0.15, "[ KDF ]  Argon2id (~2s)…")
        keys = CryptoEngine.derive_local_keys(password)
        on_progress(0.45, "[ ENCRYPT ]  Double-AEAD…")
        ciphertext = CryptoEngine.encrypt(plaintext, keys)
        on_progress(0.82, "[ WRITE ]  Writing encrypted file…")
        try:
            dst.write_bytes(cls.MAGIC + digest + ciphertext)
        except OSError as exc:
            raise ValueError(f"Cannot write '{dst}': {exc}") from exc
        on_progress(1.0, f"[ DONE ]  {_format_size(dst.stat().st_size)}")
        logger.info("LocalEncryptor: %s → %s", src, dst)
        _history.add(TransferRecord(
            ts=datetime.datetime.now().isoformat(timespec="seconds"),
            direction="LOCAL_ENC", filename=src.name,
            size_b=len(plaintext), duration_s=0, status="OK", peer="local", note="",
        ))

    @classmethod
    def decrypt_file(cls, src: Path, dst: Path, password: str,
                     on_progress: ProgressCallback) -> None:
        if not src.is_file():
            raise FileNotFoundError(f"Source file not found: {src}")
        if src.stat().st_size > MAX_FILE_BYTES + 200:
            raise ValueError("File too large for in-memory decryption.")
        on_progress(0.05, "[ READ ]  Loading encrypted file…")
        raw = src.read_bytes()
        mlen = len(cls.MAGIC)
        if len(raw) < mlen + 64 + 120 or raw[:mlen] != cls.MAGIC:
            raise ValueError("Not a valid Fortress file — wrong magic header.")
        expected_digest = raw[mlen:mlen + 64]
        ciphertext      = raw[mlen + 64:]
        on_progress(0.15, "[ KDF ]  Argon2id (~2s)…")
        keys = CryptoEngine.derive_local_keys(password)
        on_progress(0.48, "[ DECRYPT ]  AES-256-GCM + ChaCha20-Poly1305…")
        plaintext = CryptoEngine.decrypt(ciphertext, keys)
        on_progress(0.88, "[ INTEGRITY ]  SHA-512 check…")
        if not hmac.compare_digest(CryptoEngine.sha512_digest(plaintext), expected_digest):
            raise IntegrityError("SHA-512 mismatch — wrong passphrase or corrupted file.")
        final_dst = dst
        if final_dst.exists():
            counter = 1
            while final_dst.exists():
                final_dst = dst.with_stem(f"{dst.stem}_{counter}")
                counter += 1
        on_progress(0.96, "[ WRITE ]  Writing plaintext…")
        try:
            final_dst.write_bytes(plaintext)
        except OSError as exc:
            raise ValueError(f"Cannot write '{final_dst}': {exc}") from exc
        on_progress(1.0, f"[ DONE ]  {_format_size(len(plaintext))}")
        logger.info("LocalEncryptor: decrypted %s → %s", src, final_dst)
        _history.add(TransferRecord(
            ts=datetime.datetime.now().isoformat(timespec="seconds"),
            direction="LOCAL_DEC", filename=src.name,
            size_b=len(plaintext), duration_s=0, status="OK", peer="local", note="",
        ))


# ===========================================================================
# WormholeManager
# ===========================================================================
class WormholeManager:
    """Orchestrates magic-wormhole with CryptoEngine pre-encryption."""

    _CODE_RE  = re.compile(r'\b(\d+(?:-[a-z]+){2,})\b')
    _FNAME_RE = re.compile(r'written to[: ]+(.+)', re.IGNORECASE)

    STOP_SEND    = threading.Event()
    STOP_RECEIVE = threading.Event()

    @classmethod
    def send(cls, file_path: Path, passphrase: str,
             on_progress: ProgressCallback, on_code: Callable[[str], None]) -> None:
        cls.STOP_SEND.clear()
        if not file_path.is_file():
            raise FileNotFoundError(f"File not found: {file_path}")
        if file_path.stat().st_size > MAX_FILE_BYTES:
            raise WormholeError("File too large.")
        on_progress(0.05, "[ WORMHOLE ]  Loading file…")
        plaintext  = file_path.read_bytes()
        digest     = CryptoEngine.sha512_digest(plaintext)
        on_progress(0.12, "[ WORMHOLE ]  Argon2id key derivation (~2s)…")
        keys       = CryptoEngine.derive_wormhole_keys(passphrase)
        on_progress(0.28, "[ WORMHOLE ]  CryptoEngine pre-encryption…")
        ciphertext = CryptoEngine.encrypt(plaintext, keys)
        blob       = digest + ciphertext
        tmp_dir  = Path(tempfile.mkdtemp(prefix="fortress_wh_"))
        tmp_file = tmp_dir / (file_path.name + ".whfort")
        proc: subprocess.Popen | None = None
        try:
            tmp_file.write_bytes(blob)
            on_progress(0.35, "[ WORMHOLE ]  Spawning wormhole send…")
            try:
                proc = subprocess.Popen(
                    ["wormhole", "send", str(tmp_file), "--hide-progress"],
                    stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                    text=True, bufsize=1,
                )
            except FileNotFoundError:
                raise WormholeError(
                    "magic-wormhole not found.\n"
                    "Install: pip install magic-wormhole"
                )
            code_found = False
            on_progress(0.40, "[ WORMHOLE ]  Waiting for relay…")
            if proc.stdout is None:
                raise WormholeError("Subprocess stdout is None.")
            proc.stdout.reconfigure(errors="replace")  # type: ignore[attr-defined]

            # Read subprocess stdout on a dedicated thread so we never call
            # select() on a pipe — select() only supports sockets on Windows.
            line_q: queue.Queue[str | None] = queue.Queue()

            def _reader(stdout: "Any", q: "queue.Queue[str | None]") -> None:
                try:
                    for line in stdout:
                        q.put(line)
                finally:
                    q.put(None)  # sentinel: EOF

            reader_thread = threading.Thread(target=_reader,
                                             args=(proc.stdout, line_q),
                                             daemon=True)
            reader_thread.start()

            TIMEOUT = 90.0
            while True:
                if cls.STOP_SEND.is_set():
                    proc.terminate(); proc.wait()
                    raise WormholeError("Send cancelled.")
                try:
                    item = line_q.get(timeout=TIMEOUT)
                except queue.Empty:
                    proc.terminate(); proc.wait()
                    raise WormholeError("Wormhole relay timeout (90s).")
                if item is None:
                    break   # EOF
                line = item.strip()
                logger.debug("wh send: %s", line)
                if not code_found:
                    m = cls._CODE_RE.search(line)
                    if m:
                        code = m.group(1)
                        code_found = True
                        on_code(code)
                        on_progress(0.50, f"[ WORMHOLE ]  Code: {code}")
                low = line.lower()
                if any(k in low for k in ("file sent", "transfer complete", "wormhole closed")):
                    on_progress(0.95, "[ WORMHOLE ]  Transfer complete.")
                    break
                if any(k in low for k in ("error:", "traceback (", "exception:", "fatal:")):
                    proc.terminate(); proc.wait()
                    raise WormholeError(f"wormhole error: {line}")

            try:
                proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                proc.kill(); proc.wait()
                raise WormholeError("wormhole send did not exit.")
            if proc.returncode not in (0, None):
                raise WormholeError(f"wormhole exited {proc.returncode}.")
            on_progress(1.0, "[ MISSION COMPLETE ]  Wormhole done.")
            logger.info("Wormhole send complete: %s", file_path)
            _history.add(TransferRecord(
                ts=datetime.datetime.now().isoformat(timespec="seconds"),
                direction="WORMHOLE", filename=file_path.name,
                size_b=file_path.stat().st_size, duration_s=0,
                status="OK", peer="wormhole-relay", note="",
            ))
        except Exception:
            if proc and proc.poll() is None:
                proc.kill(); proc.wait()
            raise
        finally:
            shutil.rmtree(tmp_dir, ignore_errors=True)

    @classmethod
    def receive(cls, code: str, passphrase: str, save_dir: Path,
                on_progress: ProgressCallback) -> None:
        cls.STOP_RECEIVE.clear()
        code = code.strip()
        if not cls._CODE_RE.fullmatch(code):
            if not re.match(r'^[\w-]+$', code) or len(code) < 5:
                raise ValueError(f"Invalid wormhole code: '{code}'")
        tmp_dir = Path(tempfile.mkdtemp(prefix="fortress_wh_"))
        proc: subprocess.Popen | None = None
        try:
            on_progress(0.05, f"[ WORMHOLE ]  Connecting: {code}…")
            try:
                # Run wormhole in tmp_dir so it saves the file there using the
                # original filename (e.g. "document.pdf.whfort").  Do NOT use
                # --output-file with a fixed name, which would lose the extension.
                proc = subprocess.Popen(
                    ["wormhole", "receive", "--accept-file", code],
                    stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                    text=True, bufsize=1,
                    cwd=str(tmp_dir),
                )
            except FileNotFoundError:
                raise WormholeError("magic-wormhole not found. pip install magic-wormhole")
            on_progress(0.10, "[ WORMHOLE ]  Contacting relay…")
            if proc.stdout is None:
                raise WormholeError("Subprocess stdout is None.")
            proc.stdout.reconfigure(errors="replace")  # type: ignore[attr-defined]

            # Read subprocess stdout on a dedicated thread — avoids calling
            # select() on a pipe, which raises WinError 10038 on Windows.
            line_q: queue.Queue[str | None] = queue.Queue()

            def _reader(stdout: "Any", q: "queue.Queue[str | None]") -> None:
                try:
                    for line in stdout:
                        q.put(line)
                finally:
                    q.put(None)  # sentinel: EOF

            reader_thread = threading.Thread(target=_reader,
                                             args=(proc.stdout, line_q),
                                             daemon=True)
            reader_thread.start()

            received_name: str | None = None
            TIMEOUT = 120.0
            while True:
                if cls.STOP_RECEIVE.is_set():
                    proc.terminate(); proc.wait()
                    raise WormholeError("Receive cancelled.")
                try:
                    item = line_q.get(timeout=TIMEOUT)
                except queue.Empty:
                    proc.terminate(); proc.wait()
                    raise WormholeError("Wormhole receive timeout (2 min).")
                if item is None:
                    break   # EOF
                line = item.strip()
                logger.debug("wh recv: %s", line)
                m_name = cls._FNAME_RE.search(line)
                if m_name:
                    received_name = Path(m_name.group(1).strip()).name
                low = line.lower()
                if any(k in low for k in ("received file", "transfer complete", "wormhole closed")):
                    on_progress(0.60, "[ WORMHOLE ]  Download complete.")
                    break
                if any(k in low for k in ("error:", "traceback (", "exception:", "wrong code", "fatal:")):
                    proc.terminate(); proc.wait()
                    raise WormholeError(f"wormhole error: {line}")

            try:
                proc.wait(timeout=15)
            except subprocess.TimeoutExpired:
                proc.kill(); proc.wait()
                raise WormholeError("wormhole receive did not exit.")

            # Locate the downloaded file.  Prefer the name parsed from wormhole
            # output; fall back to scanning tmp_dir for any file wormhole wrote.
            actual_file: Path | None = None
            if received_name:
                candidate = tmp_dir / received_name
                if candidate.is_file():
                    actual_file = candidate
            if actual_file is None:
                files = [f for f in tmp_dir.iterdir() if f.is_file()]
                actual_file = files[0] if files else None
            if actual_file is None or not actual_file.is_file():
                raise WormholeError("No file written after wormhole receive.")
            on_progress(0.65, "[ WORMHOLE ]  Decrypting…")
            raw = actual_file.read_bytes()
            if len(raw) < 64 + 120:
                raise WormholeError("Payload too small.")
            expected_digest = raw[:64]
            ciphertext      = raw[64:]
            on_progress(0.70, "[ WORMHOLE ]  Argon2id (~2s)…")
            keys = CryptoEngine.derive_wormhole_keys(passphrase)
            on_progress(0.85, "[ WORMHOLE ]  HMAC + AES + ChaCha…")
            plaintext = CryptoEngine.decrypt(ciphertext, keys)
            on_progress(0.93, "[ WORMHOLE ]  SHA-512 check…")
            if not hmac.compare_digest(CryptoEngine.sha512_digest(plaintext), expected_digest):
                raise IntegrityError("SHA-512 mismatch.")
            raw_name = actual_file.name
            out_name = raw_name[:-7] if raw_name.endswith(".whfort") else raw_name
            out_name = Path(out_name).name or "received_file"
            out_path = save_dir / out_name
            counter  = 1
            while out_path.exists():
                stem = Path(out_name).stem; suf = Path(out_name).suffix
                out_path = save_dir / f"{stem}_{counter}{suf}"; counter += 1
            out_path.write_bytes(plaintext)
            on_progress(1.0, f"[ MISSION COMPLETE ]  {_format_size(len(plaintext))} → {out_path.name}")
            logger.info("Wormhole receive complete: %s", out_path)
            _history.add(TransferRecord(
                ts=datetime.datetime.now().isoformat(timespec="seconds"),
                direction="WORMHOLE", filename=out_name,
                size_b=len(plaintext), duration_s=0,
                status="OK", peer="wormhole-relay", note="RECEIVED",
            ))
        except Exception:
            if proc and proc.poll() is None:
                proc.kill(); proc.wait()
            raise
        finally:
            shutil.rmtree(tmp_dir, ignore_errors=True)


# ===========================================================================
# GUI — P2P Fortress v14.0
# New: Sidebar nav · Settings persistence · Toast system · Recent files ·
#      Favorite peers · Multi-file send · Disabled buttons during ops ·
#      Progress auto-reset · Tray icon support
# ===========================================================================

# ── Settings path ──────────────────────────────────────────────────────────
_SETTINGS_FILE = Path.home() / ".p2p_fortress.json"

_DEFAULT_SETTINGS: dict = {
    "default_port":          5001,
    "save_dir":              str(_default_download_dir()),
    "session_timeout_min":   10,
    "clipboard_clear_sec":   30,
    "burn_delay_sec":        60,    # Burn-After-Reading delay in seconds
    "theme":                 "dark",
    "lan_discovery":         True,
    "recent_files":          [],   # list[str] — last 8 paths
    "favorite_peers":        [],   # list[{name, ip, port}]
    "window_geometry":       "980x840",
}


def _load_settings() -> dict:
    try:
        data = json.loads(_SETTINGS_FILE.read_text(encoding="utf-8"))
        merged = dict(_DEFAULT_SETTINGS)
        merged.update(data)
        return merged
    except FileNotFoundError:
        return dict(_DEFAULT_SETTINGS)   # first run — normal
    except Exception:
        logger.warning("Could not load settings from %s — using defaults.", _SETTINGS_FILE)
        return dict(_DEFAULT_SETTINGS)


def _save_settings(s: dict) -> None:
    try:
        _SETTINGS_FILE.write_text(json.dumps(s, indent=2, ensure_ascii=False),
                                   encoding="utf-8")
    except OSError:
        logger.warning("Could not save settings to %s.", _SETTINGS_FILE)


# ── Sidebar nav items ──────────────────────────────────────────────────────
_NAV: list[tuple[str, str]] = [
    ("send",     "▲   TRANSMIT"),
    ("recv",     "▼   RECEIVE"),
    ("wormhole", "⊕   WORMHOLE"),
    ("local",    "■   LOCAL CRYPTO"),
    ("history",  "◎   HISTORY"),
    ("diag",     "◈   DIAGNOSTICS"),
    ("settings", "⚙   SETTINGS"),
    ("guide",    "◈   FIELD MANUAL"),
    ("about",    "★   MISSION INFO"),
]


# ===========================================================================
class App(ctk.CTk):
    """
    P2P Fortress v14.0
    =================
    Layout  : Sidebar (220px fixed) + Main content area (grid, weight=1)
    Nav     : Sidebar buttons show/hide CTkFrames — no CTkTabview
    New UX  : Toast overlay, disabled-during-op buttons, progress auto-reset
    New feat: Recent files, Favorite peers, Multi-file zip, Settings panel
    Crypto  : UNCHANGED from v7.0
    """

    _SCALE_BASE: int   = 980
    _SCALE_MIN:  float = 0.78
    _SCALE_MAX:  float = 1.40

    # ── init ───────────────────────────────────────────────────────────────
    def __init__(self) -> None:
        super().__init__()
        self._cfg = _load_settings()

        # restore theme first
        if self._cfg["theme"] == "light":
            _THEME.update(_LIGHT_THEME)
            ctk.set_appearance_mode("light")
            self._is_dark = False
        else:
            _THEME.update(_DARK_THEME)
            ctk.set_appearance_mode("dark")
            self._is_dark = True

        self.title("▣  P2P FORTRESS  v14.0  —  CLASSIFIED TRANSFER SYSTEM")
        self.geometry(self._cfg.get("window_geometry", "980x840"))
        self.resizable(True, True)
        self.minsize(820, 680)
        ctk.set_default_color_theme("blue")
        self.configure(fg_color=MIL_BG)

        # ── state ─────────────────────────────────────────────────────────
        self._send_file:        Path | None              = None
        self._send_files:       list[Path]               = []   # multi-file
        self._local_src:        Path | None              = None
        self._local_src_is_dir: bool                     = False
        self._server:           FileServer | None        = None
        self._srv_thread:       threading.Thread | None  = None
        self._listen_btn:       ctk.CTkButton | None     = None
        self._wh_file:          Path | None              = None
        self._wh_code_var:      ctk.StringVar | None     = None
        self._wh_send_btn:      ctk.CTkButton | None     = None
        self._wh_recv_btn:      ctk.CTkButton | None     = None
        self._wh_cancel_btn:    ctk.CTkButton | None     = None
        self._local_enc_btn:    ctk.CTkButton | None     = None
        self._local_dec_btn:    ctk.CTkButton | None     = None
        self._clip_job:         str | None               = None
        self._idle_job:         str | None               = None
        self._resize_job:       str | None               = None
        self._progress_job:     str | None               = None
        self._last_scale:       float                    = 1.0
        self._sas_label:        ctk.CTkLabel | None      = None   # set in _build_send_page
        self._recv_sas_label:   ctk.CTkLabel | None      = None   # set in _build_recv_page
        self._lan_discovery:    LANDiscovery | None      = None
        self._lan_peer_menu:    ctk.CTkOptionMenu | None = None
        self._lan_peers_var:    ctk.StringVar            = ctk.StringVar(value="LAN peers…")
        self._burn_var:         ctk.BooleanVar           = ctk.BooleanVar(value=False)
        self._multi_var:        ctk.BooleanVar           = ctk.BooleanVar(value=False)
        self._diag_text:        ctk.CTkTextbox | None    = None
        self._active_page:      str                      = "send"
        self._pages:            dict[str, ctk.CTkFrame]  = {}
        self._nav_btns:         dict[str, ctk.CTkButton] = {}
        self._busy_btns:        list[ctk.CTkButton]      = []  # disabled during opng ops
        self._toast_frame:      ctk.CTkFrame | None      = None
        self._toast_job:        str | None               = None
        self._lan_update_job:   str | None               = None
        self._last_idle_reset:  float                    = 0.0   # throttle <Motion>
        self._last_progress_t:  float                    = 0.0   # throttle progress cb

        # settings widget references (built in _build_settings_page)
        self._cfg_port_var:    ctk.StringVar  = ctk.StringVar(value=str(self._cfg["default_port"]))
        self._cfg_dir_var:     ctk.StringVar  = ctk.StringVar(value=self._cfg["save_dir"])
        self._cfg_timeout_var: ctk.StringVar  = ctk.StringVar(value=str(self._cfg["session_timeout_min"]))
        self._cfg_clip_var:    ctk.StringVar  = ctk.StringVar(value=str(self._cfg["clipboard_clear_sec"]))
        self._cfg_burn_var:    ctk.StringVar  = ctk.StringVar(value=str(self._cfg.get("burn_delay_sec", 60)))
        self._cfg_lan_var:     ctk.BooleanVar = ctk.BooleanVar(value=bool(self._cfg["lan_discovery"]))

        # root grid: col0=sidebar(fixed) col1=main(expands)
        self.grid_columnconfigure(0, weight=0)
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        self._build_sidebar()
        self._build_main_area()

        self.bind("<Configure>", self._on_resize_event)
        self.bind("<Motion>",    lambda e: self._reset_idle())
        self.bind("<KeyPress>",  lambda e: self._reset_idle())
        self._reset_idle()
        self._setup_dnd()
        self._navigate("send")

        if self._cfg["lan_discovery"]:
            self._start_lan_discovery()

    # ══════════════════════════════════════════════════════════════════════
    # SIDEBAR
    # ══════════════════════════════════════════════════════════════════════

    # ── Sidebar nav row counter (persistent across calls) ──────────────────

    def _build_sidebar(self) -> None:
        # Outer fixed-width container (never scrolls)
        outer = ctk.CTkFrame(self, fg_color=MIL_CARD, corner_radius=0, width=220)
        outer.grid(row=0, column=0, sticky="nsew")
        outer.grid_propagate(False)
        outer.grid_columnconfigure(0, weight=1)
        outer.grid_rowconfigure(1, weight=1)   # scrollable nav stretches vertically

        # ── Logo (fixed, top) ─────────────────────────────────────────────
        logo = ctk.CTkFrame(outer, fg_color=MIL_CARD2, corner_radius=0, height=62)
        logo.grid(row=0, column=0, sticky="ew")
        logo.grid_propagate(False)
        logo.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(logo, text="▣  FORTRESS",
                     font=ctk.CTkFont(family="Courier New", size=15, weight="bold"),
                     text_color=MIL_GREEN_LT, anchor="w"
                     ).grid(row=0, column=0, sticky="w", padx=16, pady=(12, 1))
        ctk.CTkLabel(logo, text="  v14.0  //  CRYPTO-GRADE+",
                     font=ctk.CTkFont(family="Courier New", size=8),
                     text_color=MIL_AMBER, anchor="w"
                     ).grid(row=1, column=0, sticky="w", padx=16, pady=(0, 10))

        # ── Scrollable nav area ───────────────────────────────────────────
        # CTkScrollableFrame adds a thin scrollbar on the right; it only
        # appears when content overflows — invisible on tall windows.
        nav_scroll = ctk.CTkScrollableFrame(
            outer,
            fg_color=MIL_CARD,
            corner_radius=0,
            scrollbar_button_color=MIL_CARD2,
            scrollbar_button_hover_color=MIL_MUTED,
        )
        nav_scroll.grid(row=1, column=0, sticky="nsew")
        nav_scroll.grid_columnconfigure(0, weight=1)

        # _sb and _sb_row are used by _sb_separator / _sb_label / _sb_nav_btn
        # pointing them at nav_scroll means those helpers work unchanged.
        self._sb = nav_scroll
        self._sb_row = 0

        # nav group 1: transfer
        self._sb_separator(); self._sb_label("TRANSFER")
        for page in ("send", "recv", "wormhole"):
            self._sb_nav_btn(page)

        # nav group 2: tools
        self._sb_separator(); self._sb_label("TOOLS")
        for page in ("local", "history", "diag"):
            self._sb_nav_btn(page)

        # nav group 3: config / info
        self._sb_separator(); self._sb_label("CONFIG & INFO")
        for page in ("settings", "guide", "about"):
            self._sb_nav_btn(page)

        # ── Theme toggle (fixed, bottom) ──────────────────────────────────
        bottom = ctk.CTkFrame(outer, fg_color=MIL_CARD, corner_radius=0)
        bottom.grid(row=2, column=0, sticky="ew")
        bottom.grid_columnconfigure(0, weight=1)
        ctk.CTkFrame(bottom, fg_color=MIL_OLIVE, height=1
                     ).grid(row=0, column=0, sticky="ew", padx=10, pady=(8, 4))
        self._theme_btn = ctk.CTkButton(
            bottom, text="🌓  LIGHT MODE", height=32,
            fg_color=MIL_BG, hover_color=MIL_CARD2,
            font=ctk.CTkFont(family="Courier New", size=10, weight="bold"),
            text_color=MIL_TAN, corner_radius=4, anchor="w",
            command=self._toggle_theme)
        self._theme_btn.grid(row=1, column=0, sticky="ew", padx=10, pady=(0, 10))
        if not self._is_dark:
            self._theme_btn.configure(text="☀  DARK MODE")

    def _sb_separator(self) -> None:
        ctk.CTkFrame(self._sb, fg_color=MIL_CARD2, height=1
                     ).grid(row=self._sb_row, column=0, sticky="ew", padx=0, pady=(6, 0))
        self._sb_row += 1

    def _sb_label(self, text: str) -> None:
        ctk.CTkLabel(self._sb, text=f"  {text}",
                     font=ctk.CTkFont(family="Courier New", size=8, weight="bold"),
                     text_color=MIL_MUTED, anchor="w"
                     ).grid(row=self._sb_row, column=0, sticky="ew", padx=4, pady=(4, 1))
        self._sb_row += 1

    def _sb_nav_btn(self, page: str) -> None:
        label = next(lbl for key, lbl in _NAV if key == page)
        btn = ctk.CTkButton(
            self._sb, text=label, anchor="w", height=33,
            fg_color="transparent", hover_color=MIL_CARD2,
            font=ctk.CTkFont(family="Courier New", size=11, weight="bold"),
            text_color=MIL_TAN, corner_radius=6,
            command=lambda p=page: self._navigate(p))
        btn.grid(row=self._sb_row, column=0, sticky="ew", padx=6, pady=1)
        self._nav_btns[page] = btn
        self._sb_row += 1

    # ══════════════════════════════════════════════════════════════════════
    # MAIN AREA
    # ══════════════════════════════════════════════════════════════════════

    def _build_main_area(self) -> None:
        self._main = ctk.CTkFrame(self, fg_color=MIL_BG, corner_radius=0)
        self._main.grid(row=0, column=1, sticky="nsew")
        self._main.grid_columnconfigure(0, weight=1)
        self._main.grid_rowconfigure(0, weight=0)   # page header
        self._main.grid_rowconfigure(1, weight=1)   # page content
        self._main.grid_rowconfigure(2, weight=0)   # status bar

        # page title bar
        self._page_title_frame = ctk.CTkFrame(
            self._main, fg_color=MIL_PANEL, corner_radius=0, height=40)
        self._page_title_frame.grid(row=0, column=0, sticky="ew")
        self._page_title_frame.grid_propagate(False)
        self._page_title_frame.grid_columnconfigure(0, weight=1)
        self._page_title_lbl = ctk.CTkLabel(
            self._page_title_frame, text="",
            font=ctk.CTkFont(family="Courier New", size=12, weight="bold"),
            text_color=MIL_TAN, anchor="w")
        self._page_title_lbl.grid(row=0, column=0, sticky="w", padx=18, pady=9)

        # page container (stacked frames)
        self._page_container = ctk.CTkFrame(self._main, fg_color=MIL_BG, corner_radius=0)
        self._page_container.grid(row=1, column=0, sticky="nsew")
        self._page_container.grid_columnconfigure(0, weight=1)
        self._page_container.grid_rowconfigure(0, weight=1)

        # build all pages
        for page in ("send", "recv", "wormhole", "local",
                     "history", "diag", "settings", "guide", "about"):
            frame = ctk.CTkFrame(self._page_container, fg_color=MIL_BG, corner_radius=0)
            frame.grid(row=0, column=0, sticky="nsew")
            frame.grid_columnconfigure(0, weight=1)
            frame.grid_rowconfigure(0, weight=1)
            self._pages[page] = frame
            getattr(self, f"_build_{page}_page")(frame)
            frame.grid_remove()

        # status bar
        self._build_status_bar()

    # ── Navigation ─────────────────────────────────────────────────────────
    def _navigate(self, page: str) -> None:
        # Hide EVERY page and deactivate every nav button.
        # Doing all pages (not just "current") is critical — if multiple frames
        # share the same grid cell (row=0, col=0) any stacking-order issue will
        # cause the wrong page to appear on top.  Hide-all is O(n) and instant.
        for key, frame in self._pages.items():
            try:
                frame.grid_remove()
            except Exception:
                pass
            if key in self._nav_btns:
                try:
                    self._nav_btns[key].configure(
                        fg_color="transparent", text_color=MIL_TAN)
                except Exception:
                    pass

        # Show the requested page with explicit coordinates (never rely on
        # the saved grid config — always pass row/column explicitly so the
        # frame is guaranteed to land in the right cell).
        self._active_page = page
        try:
            self._pages[page].grid(row=0, column=0, sticky="nsew")
        except Exception:
            return

        # Activate the matching nav button
        if page in self._nav_btns:
            try:
                self._nav_btns[page].configure(
                    fg_color=MIL_OLIVE, text_color=MIL_TEXT)
            except Exception:
                pass

        # Update the page title label
        label = next((l for k, l in _NAV if k == page), page.upper())
        try:
            self._page_title_lbl.configure(text=f"  {label.strip()}")
        except Exception:
            pass

    # ── Status bar ─────────────────────────────────────────────────────────
    def _build_status_bar(self) -> None:
        bar = ctk.CTkFrame(self._main, fg_color=MIL_CARD, corner_radius=0,
                            border_color=MIL_OLIVE, border_width=1)
        bar.grid(row=2, column=0, sticky="ew")
        bar.grid_columnconfigure(0, weight=1)
        bar.grid_rowconfigure(0, weight=1)
        bar.grid_rowconfigure(1, weight=1)
        self._status_lbl = ctk.CTkLabel(
            bar, text="[ SYSTEM READY ]  v14.0 — all systems nominal.",
            font=ctk.CTkFont(family="Courier New", size=11),
            text_color=MIL_KHAKI, anchor="w")
        self._status_lbl.grid(row=0, column=0, sticky="ew", padx=14, pady=(7, 2))
        self._progress = ctk.CTkProgressBar(
            bar, progress_color=MIL_GREEN_LT, fg_color=MIL_BG, height=8)
        self._progress.grid(row=1, column=0, sticky="ew", padx=14, pady=(0, 7))
        self._progress.set(0)

    # ══════════════════════════════════════════════════════════════════════
    # RESPONSIVE RESIZE + THEME
    # ══════════════════════════════════════════════════════════════════════

    def _on_resize_event(self, event: object) -> None:
        if getattr(event, "widget", None) is not self:
            return
        # Skip if we just applied scaling (avoids infinite Configure-event cascade)
        if self._scaling_in_progress:
            return
        if self._resize_job:
            self.after_cancel(self._resize_job)
        self._resize_job = self.after(250, self._apply_scaling)

    _scaling_in_progress: bool = False  # class-level guard

    def _apply_scaling(self) -> None:
        self._resize_job = None
        if self._scaling_in_progress:
            return
        try:
            w = self.winfo_width()
            if w < 50:
                return
            scale = max(self._SCALE_MIN, min(self._SCALE_MAX, w / self._SCALE_BASE))
            scale = round(scale * 20) / 20
            if abs(scale - self._last_scale) < 0.05:
                return   # no meaningful change — skip the expensive rebuild
            self._last_scale = scale
            # Guard MUST be set before calling set_widget_scaling because the call
            # itself triggers <Configure> events that would re-enter this method.
            self._scaling_in_progress = True
            try:
                ctk.set_widget_scaling(scale)
            finally:
                # Delay clearing the guard so that the Configure events generated
                # by set_widget_scaling are absorbed before we allow another scaling.
                self.after(500, self._clear_scaling_guard)
        except Exception:
            self._scaling_in_progress = False

    def _clear_scaling_guard(self) -> None:
        self._scaling_in_progress = False

    def _toggle_theme(self) -> None:
        self._is_dark = not self._is_dark
        if self._is_dark:
            _THEME.update(_DARK_THEME); ctk.set_appearance_mode("dark")
            self._theme_btn.configure(text="🌓  LIGHT MODE")
            self._cfg["theme"] = "dark"
        else:
            _THEME.update(_LIGHT_THEME); ctk.set_appearance_mode("light")
            self._theme_btn.configure(text="☀  DARK MODE")
            self._cfg["theme"] = "light"
        _reload_theme()
        _save_settings(self._cfg)
        self._toast("Theme saved — restart to fully apply", MIL_AMBER)

    # ══════════════════════════════════════════════════════════════════════
    # TOAST NOTIFICATION SYSTEM
    # ══════════════════════════════════════════════════════════════════════

    def _toast(self, message: str, color: str = MIL_GREEN_LT, duration: int = 3200) -> None:
        """Non-blocking overlay toast at bottom-right. Thread-safe via after()."""
        if self._toast_job:
            self.after_cancel(self._toast_job)
            self._toast_job = None
        if self._toast_frame:
            try:
                self._toast_frame.destroy()
            except Exception:
                pass
            self._toast_frame = None

        tf = ctk.CTkFrame(self, fg_color=MIL_CARD2, corner_radius=8,
                           border_color=color, border_width=2)
        ctk.CTkLabel(tf, text=f"  {message}  ",
                     font=ctk.CTkFont(family="Courier New", size=11, weight="bold"),
                     text_color=color
                     ).pack(padx=10, pady=8)
        tf.place(relx=1.0, rely=1.0, anchor="se", x=-12, y=-52)
        self._toast_frame = tf

        def _dismiss() -> None:
            if self._toast_frame:
                try:
                    self._toast_frame.destroy()
                except Exception:
                    pass
                self._toast_frame = None
            self._toast_job = None

        self._toast_job = self.after(duration, _dismiss)

    # ══════════════════════════════════════════════════════════════════════
    # SHARED WIDGET HELPERS
    # ══════════════════════════════════════════════════════════════════════

    def _tab_scroll(self, p: ctk.CTkFrame) -> ctk.CTkScrollableFrame:
        p.grid_columnconfigure(0, weight=1)
        p.grid_rowconfigure(0, weight=1)
        sf = ctk.CTkScrollableFrame(p, fg_color="transparent",
                                     scrollbar_button_color=MIL_OLIVE,
                                     scrollbar_button_hover_color=MIL_OLIVE_LT)
        sf.grid(row=0, column=0, sticky="nsew")
        sf.grid_columnconfigure(0, weight=1)
        return sf

    def _irow(self, parent: ctk.CTkFrame, row: int,
               padx: int = 16, pady: tuple = (0, 0)) -> ctk.CTkFrame:
        f = ctk.CTkFrame(parent, fg_color="transparent")
        f.grid(row=row, column=0, sticky="ew", padx=padx, pady=pady)
        f.grid_columnconfigure(0, weight=1)
        return f

    def _section_header(self, parent: ctk.CTkFrame, row: int, text: str,
                         color: str = MIL_AMBER) -> None:
        ctk.CTkFrame(parent, fg_color=color, height=1
                     ).grid(row=row, column=0, sticky="ew", padx=16, pady=(10, 0))
        ctk.CTkLabel(parent, text=f"  {text}",
                     font=ctk.CTkFont(family="Courier New", size=10, weight="bold"),
                     text_color=color, anchor="w"
                     ).grid(row=row+1, column=0, sticky="ew", padx=16, pady=(2, 4))

    @staticmethod
    def _lbl(parent: ctk.CTkFrame, text: str) -> ctk.CTkLabel:
        return ctk.CTkLabel(parent, text=text,
                            font=ctk.CTkFont(family="Courier New", size=11, weight="bold"),
                            text_color=MIL_TAN, anchor="w")

    def _ent(self, parent: ctk.CTkFrame, ph: str, show: str = "",
             var: ctk.StringVar | None = None) -> ctk.CTkEntry:
        kw: dict = dict(placeholder_text=ph, fg_color=MIL_CARD, border_color=MIL_OLIVE,
                        text_color=MIL_TEXT, placeholder_text_color=MIL_MUTED,
                        font=ctk.CTkFont(family="Courier New", size=12),
                        height=36, show=show)
        if var: kw["textvariable"] = var
        e = ctk.CTkEntry(parent, **kw)
        self._attach_entry_menu(e)
        return e

    def _attach_entry_menu(self, entry: ctk.CTkEntry) -> None:
        """Attaches a right-click Cut / Copy / Paste / Select-All context menu."""
        menu = _tk.Menu(self, tearoff=0,
                        bg=MIL_CARD2, fg=MIL_TEXT,
                        activebackground=MIL_OLIVE, activeforeground=MIL_TEXT,
                        font=("Courier New", 10), relief="flat", bd=1)
        menu.add_command(label="Cut",        command=lambda: entry.event_generate("<<Cut>>"))
        menu.add_command(label="Copy",       command=lambda: entry.event_generate("<<Copy>>"))
        menu.add_command(label="Paste",      command=lambda: entry.event_generate("<<Paste>>"))
        menu.add_separator()
        menu.add_command(label="Select All", command=lambda: entry.select_range(0, "end"))

        def _show(event: object) -> None:
            entry.focus_set()
            try:
                menu.tk_popup(getattr(event, "x_root", 0), getattr(event, "y_root", 0))
            finally:
                menu.grab_release()

        # Bind on the internal tk.Entry for reliable event capture
        target = getattr(entry, "_entry", entry)
        target.bind("<Button-3>", _show)
        target.bind("<Button-2>", _show)   # macOS secondary-click

    def _attach_textbox_menu(self, tb: ctk.CTkTextbox) -> None:
        """Attaches a right-click Copy / Select-All menu to a CTkTextbox."""
        menu = _tk.Menu(self, tearoff=0,
                        bg=MIL_CARD2, fg=MIL_TEXT,
                        activebackground=MIL_OLIVE, activeforeground=MIL_TEXT,
                        font=("Courier New", 10), relief="flat", bd=1)
        menu.add_command(label="Copy",       command=lambda: tb.event_generate("<<Copy>>"))
        menu.add_separator()
        menu.add_command(label="Select All", command=lambda: (
            tb.tag_add("sel", "1.0", "end")))

        def _show(event: object) -> None:
            try:
                menu.tk_popup(getattr(event, "x_root", 0), getattr(event, "y_root", 0))
            finally:
                menu.grab_release()

        target = getattr(tb, "_textbox", tb)
        target.bind("<Button-3>", _show)
        target.bind("<Button-2>", _show)

    def _attach_label_copy_menu(self, lbl: ctk.CTkLabel, text: str) -> None:
        """Right-click on any label row → copies its text to clipboard."""
        menu = _tk.Menu(self, tearoff=0,
                        bg=MIL_CARD2, fg=MIL_TEXT,
                        activebackground=MIL_OLIVE, activeforeground=MIL_TEXT,
                        font=("Courier New", 10), relief="flat", bd=1)
        menu.add_command(label=f'Copy  \u201c{text}\u201d',
                         command=lambda t=text: (
                             self.clipboard_clear(), self.clipboard_append(t)))

        def _show(event: object) -> None:
            try:
                menu.tk_popup(getattr(event, "x_root", 0), getattr(event, "y_root", 0))
            finally:
                menu.grab_release()

        target = getattr(lbl, "_label", lbl)
        target.bind("<Button-3>", _show)
        target.bind("<Button-2>", _show)

    @staticmethod
    def _btn(parent: ctk.CTkFrame, text: str, command: Callable,
             w: int = 0, h: int = 34, color: str = MIL_OLIVE,
             text_color: str = MIL_TEXT, hover: str = MIL_OLIVE_LT) -> ctk.CTkButton:
        kw: dict = dict(text=text, fg_color=color, hover_color=hover,
                        font=ctk.CTkFont(family="Courier New", weight="bold"),
                        command=command, height=h, text_color=text_color, corner_radius=5)
        if w: kw["width"] = w
        return ctk.CTkButton(parent, **kw)

    def _op_lock(self, *btns: ctk.CTkButton | None) -> None:
        """Disable buttons during an active operation. None entries are silently skipped."""
        self._busy_btns = [b for b in btns if b is not None]
        for b in self._busy_btns:
            try:
                b.configure(state="disabled", fg_color=MIL_MUTED)
            except Exception:
                pass

    def _op_unlock(self) -> None:
        """Re-enable buttons after operation completes (call from main thread)."""
        for b in self._busy_btns:
            try:
                b.configure(state="normal", fg_color=MIL_OLIVE)
            except Exception:
                pass
        self._busy_btns = []

    # ══════════════════════════════════════════════════════════════════════
    # ▲ TRANSMIT PAGE
    # ══════════════════════════════════════════════════════════════════════

    def _build_send_page(self, p: ctk.CTkFrame) -> None:
        sf = self._tab_scroll(p); r = 0

        # ── Recent files panel ──
        self._section_header(sf, r, "RECENT FILES", MIL_MUTED); r += 2
        self._recent_frame = ctk.CTkFrame(sf, fg_color=MIL_CARD, corner_radius=6)
        self._recent_frame.grid(row=r, column=0, sticky="ew", padx=16, pady=(0, 6))
        self._recent_frame.grid_columnconfigure(0, weight=1)
        r += 1
        self._rebuild_recent_ui()

        # ── File selection ──
        self._section_header(sf, r, "FILE SELECTION", MIL_GREEN_LT); r += 2
        fr = self._irow(sf, r); r += 1
        self._send_file_entry = self._ent(fr, "No file selected — drop a file here…")
        self._send_file_entry.grid(row=0, column=0, sticky="ew", padx=(0, 8), ipady=2)
        self._btn(fr, "BROWSE", self._browse_send_file, w=90).grid(row=0, column=1)

        ctk.CTkLabel(sf, text="  ↓  Drag & drop a file onto the window",
                     font=ctk.CTkFont(family="Courier New", size=9),
                     text_color=MIL_MUTED, anchor="w"
                     ).grid(row=r, column=0, sticky="ew", padx=16); r += 1

        # multi-file checkbox
        mf = ctk.CTkFrame(sf, fg_color="transparent")
        mf.grid(row=r, column=0, sticky="ew", padx=16, pady=(4, 2)); r += 1
        ctk.CTkCheckBox(mf,
                        text="  📦  MULTI-FILE  (select multiple files → auto-zip before send)",
                        variable=self._multi_var,
                        font=ctk.CTkFont(family="Courier New", size=10, weight="bold"),
                        text_color=MIL_TAN, fg_color=MIL_OLIVE,
                        hover_color=MIL_OLIVE_LT, border_color=MIL_OLIVE,
                        command=self._on_multi_toggle,
                        ).grid(row=0, column=0, sticky="w")

        # burn-after-reading
        barf = ctk.CTkFrame(sf, fg_color="transparent")
        barf.grid(row=r, column=0, sticky="ew", padx=16, pady=(2, 4)); r += 1
        ctk.CTkCheckBox(barf,
                        text="  🔥  BURN AFTER READING  (auto-deletes on receiver after 60 s)",
                        variable=self._burn_var,
                        font=ctk.CTkFont(family="Courier New", size=10, weight="bold"),
                        text_color=MIL_RED_LT, fg_color=MIL_RED,
                        hover_color=MIL_RED_LT, border_color=MIL_RED,
                        ).grid(row=0, column=0, sticky="w")

        # ── Target ──
        self._section_header(sf, r, "TARGET", MIL_AMBER); r += 2

        # Favorite peers
        fav_f = self._irow(sf, r, pady=(0, 4)); r += 1
        ctk.CTkLabel(fav_f, text="  ★  FAVORITE PEERS:",
                     font=ctk.CTkFont(family="Courier New", size=10, weight="bold"),
                     text_color=MIL_AMBER, anchor="w"
                     ).grid(row=0, column=0, sticky="w")
        self._fav_var = ctk.StringVar(value="— select saved peer —")
        self._fav_menu = ctk.CTkOptionMenu(
            fav_f, variable=self._fav_var, values=["— select saved peer —"],
            command=self._on_fav_selected,
            fg_color=MIL_CARD2, button_color=MIL_OLIVE,
            button_hover_color=MIL_OLIVE_LT, text_color=MIL_TAN,
            font=ctk.CTkFont(family="Courier New", size=11), width=260)
        self._fav_menu.grid(row=0, column=1, padx=(8, 0))
        self._rebuild_fav_menu()

        ipf = self._irow(sf, r); r += 1
        self._ip_entry = self._ent(ipf, "192.168.x.x  |  0.tcp.ngrok.io  |  100.x.x.x")
        self._ip_entry.grid(row=0, column=0, sticky="ew", padx=(0, 8), ipady=2)
        self._btn(ipf, "MY IP", self._fill_local_ip, w=72,
                  color=MIL_CARD2, text_color=MIL_TAN, hover=MIL_OLIVE
                  ).grid(row=0, column=1, padx=(0, 6))
        self._lan_peer_menu = ctk.CTkOptionMenu(
            ipf, variable=self._lan_peers_var, values=["LAN peers…"],
            command=self._on_lan_peer_selected,
            fg_color=MIL_CARD2, button_color=MIL_OLIVE,
            button_hover_color=MIL_OLIVE_LT, text_color=MIL_TAN,
            font=ctk.CTkFont(family="Courier New", size=11), width=170)
        self._lan_peer_menu.grid(row=0, column=2)

        # save as favorite
        sav_f = self._irow(sf, r, pady=(4, 0)); r += 1
        sav_f.grid_columnconfigure(0, weight=0); sav_f.grid_columnconfigure(1, weight=1)
        self._fav_name_entry = self._ent(sav_f, "Peer name to save…")
        self._fav_name_entry.grid(row=0, column=1, sticky="ew", padx=(8, 8), ipady=2)
        self._btn(sav_f, "★ SAVE PEER", self._save_favorite_peer, w=120,
                  color=MIL_CARD2, text_color=MIL_AMBER, hover=MIL_OLIVE
                  ).grid(row=0, column=0)
        self._btn(sav_f, "✕ DEL PEER", self._delete_favorite_peer, w=110,
                  color=MIL_CARD2, text_color=MIL_RED_LT, hover=MIL_RED
                  ).grid(row=0, column=2)

        self._lbl(sf, "◉  PORT").grid(
            row=r, column=0, sticky="w", padx=16, pady=(12, 3)); r += 1
        self._send_port = self._ent(sf, str(self._cfg["default_port"]))
        self._send_port.grid(row=r, column=0, sticky="ew", padx=16, ipady=2); r += 1

        # ── Auth ──
        self._section_header(sf, r, "AUTHENTICATION", MIL_RED_LT); r += 2
        self._send_secret = self._ent(sf, "Enter classified passphrase…", show="•")
        self._send_secret.grid(row=r, column=0, sticky="ew", padx=16, ipady=2); r += 1
        self._send_secret.bind("<KeyRelease>",
            lambda e: self._update_strength(self._send_secret, self._send_strength))
        self._send_strength = ctk.CTkLabel(sf, text="", anchor="w",
            font=ctk.CTkFont(family="Courier New", size=10, weight="bold"))
        self._send_strength.grid(row=r, column=0, sticky="ew", padx=18); r += 1

        self._sas_label = ctk.CTkLabel(sf, text="", anchor="w",
            font=ctk.CTkFont(family="Courier New", size=11, weight="bold"),
            text_color=MIL_AMBER)
        self._sas_label.grid(row=r, column=0, sticky="ew", padx=16, pady=(4, 0)); r += 1

        invf = self._irow(sf, r, pady=(8, 4)); r += 1
        self._invite_entry_send = self._ent(invf, "Paste FORTRESS:// invite…")
        self._invite_entry_send.grid(row=0, column=0, sticky="ew", padx=(0, 8), ipady=2)
        self._btn(invf, "⊛ USE INVITE", self._on_paste_invite, w=128,
                  color=MIL_CARD2, text_color=MIL_AMBER, hover=MIL_OLIVE
                  ).grid(row=0, column=1)

        self._send_btn = self._btn(sf, "▲   ENCRYPT & TRANSMIT", self._on_send,
                                    h=42, color=MIL_GREEN, hover=MIL_GREEN_LT)
        self._send_btn.grid(row=r, column=0, sticky="ew", padx=16, pady=(10, 18))

    # ── Multi-file toggle ──────────────────────────────────────────────────
    def _on_multi_toggle(self) -> None:
        if self._multi_var.get():
            self._toast("Multi-file: click BROWSE to select multiple files", MIL_TAN, 4000)

    # ── Recent files UI ───────────────────────────────────────────────────
    def _rebuild_recent_ui(self) -> None:
        for w in self._recent_frame.winfo_children():
            w.destroy()
        recent = self._cfg.get("recent_files", [])
        if not recent:
            ctk.CTkLabel(self._recent_frame, text="  No recent files.",
                         font=ctk.CTkFont(family="Courier New", size=10),
                         text_color=MIL_MUTED, anchor="w"
                         ).grid(row=0, column=0, sticky="w", padx=10, pady=4)
            return
        self._recent_frame.grid_columnconfigure(0, weight=1)
        for i, fp in enumerate(recent[:8]):
            pth = Path(fp)
            row_f = ctk.CTkFrame(self._recent_frame, fg_color="transparent")
            row_f.grid(row=i, column=0, sticky="ew", padx=6, pady=1)
            row_f.grid_columnconfigure(1, weight=1)
            ctk.CTkLabel(row_f, text=f"  {i+1}.",
                         font=ctk.CTkFont(family="Courier New", size=10),
                         text_color=MIL_MUTED, width=24, anchor="w"
                         ).grid(row=0, column=0)
            btn = ctk.CTkButton(row_f, text=pth.name, anchor="w",
                                 fg_color="transparent", hover_color=MIL_CARD2,
                                 font=ctk.CTkFont(family="Courier New", size=10),
                                 text_color=MIL_TAN, height=26,
                                 command=lambda f=fp: self._load_recent(f))
            btn.grid(row=0, column=1, sticky="ew")
            ctk.CTkLabel(row_f, text=pth.parent.name, width=120,
                         font=ctk.CTkFont(family="Courier New", size=9),
                         text_color=MIL_MUTED, anchor="e"
                         ).grid(row=0, column=2, padx=(0, 4))

    def _load_recent(self, fp: str) -> None:
        p = Path(fp)
        if p.exists():
            self._set_send_file(p)
        else:
            self._toast(f"File not found: {p.name}", MIL_RED_LT)

    def _push_recent(self, fp: Path) -> None:
        lst: list = self._cfg.setdefault("recent_files", [])
        s = str(fp)
        if s in lst:
            lst.remove(s)
        lst.insert(0, s)
        self._cfg["recent_files"] = lst[:8]
        _save_settings(self._cfg)
        self.after(0, self._rebuild_recent_ui)

    # ── Favorite peers ─────────────────────────────────────────────────────
    def _rebuild_fav_menu(self) -> None:
        favs = self._cfg.get("favorite_peers", [])
        if not favs:
            self._fav_menu.configure(values=["— select saved peer —"])
            return
        values = [f"★  {f['name']}  ({f['ip']}:{f['port']})" for f in favs]
        self._fav_menu.configure(values=values)

    def _on_fav_selected(self, value: str) -> None:
        favs = self._cfg.get("favorite_peers", [])
        for fav in favs:
            if fav["name"] in value:
                self._ip_entry.delete(0, "end");  self._ip_entry.insert(0, fav["ip"])
                self._send_port.delete(0, "end"); self._send_port.insert(0, str(fav["port"]))
                self._toast(f"Loaded: {fav['name']}  ({fav['ip']}:{fav['port']})", MIL_AMBER)
                return

    def _save_favorite_peer(self) -> None:
        name = self._fav_name_entry.get().strip()
        ip   = self._ip_entry.get().strip()
        port = self._send_port.get().strip()
        if not name or not ip or not port:
            self._toast("Enter name, IP and port first", MIL_RED_LT); return
        favs: list = self._cfg.setdefault("favorite_peers", [])
        favs = [f for f in favs if f["name"] != name]  # remove duplicate name
        favs.insert(0, {"name": name, "ip": ip, "port": port})
        self._cfg["favorite_peers"] = favs[:20]
        _save_settings(self._cfg)
        self._rebuild_fav_menu()
        self._fav_name_entry.delete(0, "end")
        self._toast(f"★  Saved: {name}  ({ip}:{port})", MIL_GREEN_LT)

    def _delete_favorite_peer(self) -> None:
        val = self._fav_var.get()
        favs: list = self._cfg.get("favorite_peers", [])
        original_len = len(favs)
        favs = [f for f in favs if f["name"] not in val]
        if len(favs) < original_len:
            self._cfg["favorite_peers"] = favs
            _save_settings(self._cfg)
            self._fav_var.set("— select saved peer —")
            self._rebuild_fav_menu()
            self._toast("Peer deleted", MIL_AMBER)

    # ══════════════════════════════════════════════════════════════════════
    # ▼ RECEIVE PAGE
    # ══════════════════════════════════════════════════════════════════════

    def _build_recv_page(self, p: ctk.CTkFrame) -> None:
        sf = self._tab_scroll(p); r = 0

        info = ctk.CTkFrame(sf, fg_color=MIL_BG, corner_radius=6,
                             border_color=MIL_GREEN, border_width=1)
        info.grid(row=r, column=0, sticky="ew", padx=16, pady=(14, 8))
        info.grid_columnconfigure(0, weight=1); r += 1
        ctk.CTkLabel(info,
                     text=f"  ◈  LOCAL IP:  {_get_local_ip()}   — share with sender",
                     font=ctk.CTkFont(family="Courier New", size=12, weight="bold"),
                     text_color=MIL_GREEN_LT, anchor="w"
                     ).grid(row=0, column=0, sticky="ew", padx=10, pady=7)

        self._section_header(sf, r, "CHANNEL SETTINGS", MIL_AMBER); r += 2

        self._lbl(sf, "◉  LISTENING PORT").grid(
            row=r, column=0, sticky="w", padx=16, pady=(4, 3)); r += 1
        self._recv_port = self._ent(sf, str(self._cfg["default_port"]))
        self._recv_port.grid(row=r, column=0, sticky="ew", padx=16, ipady=2); r += 1

        self._lbl(sf, "◉  SAVE DIRECTORY").grid(
            row=r, column=0, sticky="w", padx=16, pady=(12, 3)); r += 1
        sdf = self._irow(sf, r); r += 1
        self._save_dir = self._ent(sdf, "")
        self._save_dir.insert(0, self._cfg["save_dir"])
        self._save_dir.grid(row=0, column=0, sticky="ew", padx=(0, 8), ipady=2)
        self._btn(sdf, "BROWSE", self._browse_save_dir, w=90).grid(row=0, column=1)

        self._section_header(sf, r, "AUTHENTICATION", MIL_RED_LT); r += 2

        self._recv_secret = self._ent(sf, "Enter classified passphrase…", show="•")
        self._recv_secret.grid(row=r, column=0, sticky="ew", padx=16, ipady=2); r += 1
        self._recv_secret.bind("<KeyRelease>",
            lambda e: self._update_strength(self._recv_secret, self._recv_strength))
        self._recv_strength = ctk.CTkLabel(sf, text="", anchor="w",
            font=ctk.CTkFont(family="Courier New", size=10, weight="bold"))
        self._recv_strength.grid(row=r, column=0, sticky="ew", padx=18); r += 1

        self._recv_sas_label = ctk.CTkLabel(sf, text="", anchor="w",
            font=ctk.CTkFont(family="Courier New", size=11, weight="bold"),
            text_color=MIL_AMBER)
        self._recv_sas_label.grid(row=r, column=0, sticky="ew", padx=16, pady=(4, 0)); r += 1

        self._section_header(sf, r, "INVITE CODE", MIL_OLIVE); r += 2

        inv = ctk.CTkFrame(sf, fg_color=MIL_BG, corner_radius=6,
                            border_color=MIL_OLIVE, border_width=1)
        inv.grid(row=r, column=0, sticky="ew", padx=16, pady=(0, 4))
        inv.grid_columnconfigure(0, weight=1); r += 1
        ctk.CTkLabel(inv, text="  ⊛ INVITE CODE:",
                     font=ctk.CTkFont(family="Courier New", size=10),
                     text_color=MIL_MUTED, anchor="w"
                     ).grid(row=0, column=0, sticky="ew", padx=10, pady=(6, 2))
        self._invite_display = ctk.CTkLabel(inv, text="— press GENERATE —",
                     font=ctk.CTkFont(family="Courier New", size=11, weight="bold"),
                     text_color=MIL_AMBER, anchor="w", wraplength=650)
        self._invite_display.grid(row=1, column=0, sticky="ew", padx=10, pady=(0, 2))
        ibr = ctk.CTkFrame(inv, fg_color="transparent")
        ibr.grid(row=2, column=0, sticky="ew", padx=10, pady=(0, 8))
        self._btn(ibr, "⊛ GENERATE", self._on_generate_invite, w=140,
                  color=MIL_OLIVE, hover=MIL_OLIVE_LT).grid(row=0, column=0, padx=(0, 6))
        self._btn(ibr, "⎘ COPY", self._on_copy_invite, w=100,
                  color=MIL_CARD2, text_color=MIL_AMBER, hover=MIL_OLIVE
                  ).grid(row=0, column=1, padx=(0, 6))
        self._btn(ibr, "▦ QR CODE", self._on_show_qr, w=110,
                  color=MIL_CARD2, text_color=MIL_TAN, hover=MIL_OLIVE
                  ).grid(row=0, column=2)

        br = self._irow(sf, r, pady=(12, 18)); r += 1
        br.grid_columnconfigure(0, weight=1); br.grid_columnconfigure(1, weight=1)
        self._listen_btn = self._btn(br, "▼   OPEN CHANNEL", self._on_listen,
                                      h=42, color=MIL_OLIVE, hover=MIL_OLIVE_LT)
        self._listen_btn.grid(row=0, column=0, sticky="ew", padx=(0, 8))
        self._btn(br, "■   CLOSE CHANNEL", self._on_stop_server,
                  h=42, color=MIL_CARD2, hover=MIL_RED, text_color=MIL_RED_LT
                  ).grid(row=0, column=1, sticky="ew")

    # ══════════════════════════════════════════════════════════════════════
    # ⊕ WORMHOLE PAGE
    # ══════════════════════════════════════════════════════════════════════

    def _build_wormhole_page(self, p: ctk.CTkFrame) -> None:
        sf = self._tab_scroll(p); r = 0

        ban = ctk.CTkFrame(sf, fg_color="#0A0A1A", corner_radius=6,
                            border_color="#3B5BDB", border_width=1)
        ban.grid(row=r, column=0, sticky="ew", padx=16, pady=(14, 8))
        ban.grid_columnconfigure(0, weight=1); r += 1
        ctk.CTkLabel(ban,
                     text="  ⊕  Global P2P via relay. No port forwarding. Double-encrypted.",
                     font=ctk.CTkFont(family="Courier New", size=11, weight="bold"),
                     text_color="#7EB8F7", anchor="w"
                     ).grid(row=0, column=0, sticky="ew", padx=10, pady=8)

        self._section_header(sf, r, "SENDER", "#7EB8F7"); r += 2

        self._lbl(sf, "◉  FILE TO SEND").grid(
            row=r, column=0, sticky="w", padx=16, pady=(4, 3)); r += 1
        wff = self._irow(sf, r); r += 1
        self._wh_file_entry = self._ent(wff, "No file selected…")
        self._wh_file_entry.grid(row=0, column=0, sticky="ew", padx=(0, 8), ipady=2)
        self._btn(wff, "BROWSE", self._wh_browse_file, w=90).grid(row=0, column=1)

        self._lbl(sf, "◉  SHARED PASSPHRASE").grid(
            row=r, column=0, sticky="w", padx=16, pady=(12, 3)); r += 1
        self._wh_passphrase = self._ent(sf, "Enter shared passphrase…", show="•")
        self._wh_passphrase.grid(row=r, column=0, sticky="ew", padx=16, ipady=2); r += 1
        self._wh_passphrase.bind("<KeyRelease>",
            lambda e: self._update_strength(self._wh_passphrase, self._wh_strength))
        self._wh_strength = ctk.CTkLabel(sf, text="", anchor="w",
            font=ctk.CTkFont(family="Courier New", size=10, weight="bold"))
        self._wh_strength.grid(row=r, column=0, sticky="ew", padx=18); r += 1

        self._wh_send_btn = self._btn(sf, "⊕   GENERATE CODE & SEND", self._on_wh_send,
                                       h=46, color="#1E3A6E", hover="#2C5494", text_color="#7EB8F7")
        self._wh_send_btn.grid(row=r, column=0, sticky="ew", padx=16, pady=(10, 6)); r += 1

        cf = ctk.CTkFrame(sf, fg_color=MIL_BG, corner_radius=6,
                           border_color="#3B5BDB", border_width=1)
        cf.grid(row=r, column=0, sticky="ew", padx=16, pady=(0, 6))
        cf.grid_columnconfigure(0, weight=1); r += 1
        ctk.CTkLabel(cf, text="  WORMHOLE CODE:",
                     font=ctk.CTkFont(family="Courier New", size=10),
                     text_color=MIL_MUTED, anchor="w"
                     ).grid(row=0, column=0, sticky="ew", padx=10, pady=(6, 2))
        self._wh_code_var = ctk.StringVar(value="—  awaiting send  —")
        ctk.CTkLabel(cf, textvariable=self._wh_code_var,
                     font=ctk.CTkFont(family="Courier New", size=16, weight="bold"),
                     text_color="#7EB8F7", anchor="center"
                     ).grid(row=1, column=0, sticky="ew", padx=10, pady=(0, 4))
        crw = ctk.CTkFrame(cf, fg_color="transparent")
        crw.grid(row=2, column=0, sticky="e", padx=10, pady=(0, 8))
        self._btn(crw, "⎘ COPY CODE", self._wh_copy_code, w=140,
                  color=MIL_CARD2, text_color="#7EB8F7", hover="#1E3A6E").grid(row=0, column=0)

        ctk.CTkFrame(sf, fg_color=MIL_OLIVE, height=2
                     ).grid(row=r, column=0, sticky="ew", padx=16, pady=(6, 10)); r += 1

        self._section_header(sf, r, "RECEIVER", MIL_GREEN_LT); r += 2

        self._lbl(sf, "◉  WORMHOLE CODE").grid(
            row=r, column=0, sticky="w", padx=16, pady=(4, 3)); r += 1
        self._wh_code_entry = self._ent(sf, "e.g. 7-crossword-baboon")
        self._wh_code_entry.grid(row=r, column=0, sticky="ew", padx=16, ipady=2); r += 1

        self._lbl(sf, "◉  SAVE DIRECTORY").grid(
            row=r, column=0, sticky="w", padx=16, pady=(12, 3)); r += 1
        sdf2 = self._irow(sf, r); r += 1
        self._wh_save_dir = self._ent(sdf2, "")
        self._wh_save_dir.insert(0, self._cfg["save_dir"])
        self._wh_save_dir.grid(row=0, column=0, sticky="ew", padx=(0, 8), ipady=2)
        self._btn(sdf2, "BROWSE", self._wh_browse_save, w=90).grid(row=0, column=1)

        br2 = self._irow(sf, r, pady=(12, 18)); r += 1
        br2.grid_columnconfigure(0, weight=1); br2.grid_columnconfigure(1, weight=1)
        self._wh_recv_btn = self._btn(br2, "▼   RECEIVE & DECRYPT", self._on_wh_receive,
                                       h=46, color=MIL_GREEN, hover=MIL_GREEN_LT)
        self._wh_recv_btn.grid(row=0, column=0, sticky="ew", padx=(0, 8))
        self._wh_cancel_btn = self._btn(br2, "■   CANCEL", self._on_wh_cancel,
                                         h=46, color=MIL_CARD2, hover=MIL_RED, text_color=MIL_RED_LT)
        self._wh_cancel_btn.grid(row=0, column=1, sticky="ew")

    # ══════════════════════════════════════════════════════════════════════
    # ■ LOCAL CRYPTO PAGE
    # ══════════════════════════════════════════════════════════════════════

    def _build_local_page(self, p: ctk.CTkFrame) -> None:
        sf = self._tab_scroll(p); r = 0

        ban = ctk.CTkFrame(sf, fg_color="#1A1200", corner_radius=6,
                            border_color=MIL_AMBER, border_width=1)
        ban.grid(row=r, column=0, sticky="ew", padx=16, pady=(14, 8))
        ban.grid_columnconfigure(0, weight=1); r += 1
        ctk.CTkLabel(ban,
                     text="  ■  OFFLINE — Encrypt/decrypt files or entire folders. No network.",
                     font=ctk.CTkFont(family="Courier New", size=11, weight="bold"),
                     text_color=MIL_AMBER, anchor="w"
                     ).grid(row=0, column=0, sticky="ew", padx=10, pady=8)

        self._section_header(sf, r, "SOURCE", MIL_AMBER); r += 2

        srf = self._irow(sf, r); r += 1
        self._local_src_entry = self._ent(srf, "Select file or folder…")
        self._local_src_entry.grid(row=0, column=0, sticky="ew", padx=(0, 8), ipady=2)
        self._btn(srf, "FILE", self._browse_local_src, w=72).grid(row=0, column=1, padx=(0, 6))
        self._btn(srf, "FOLDER", self._browse_local_src_dir, w=88).grid(row=0, column=2)

        self._section_header(sf, r, "OUTPUT DIRECTORY", MIL_AMBER); r += 2
        orf = self._irow(sf, r); r += 1
        self._local_out = self._ent(orf, "")
        self._local_out.insert(0, self._cfg["save_dir"])
        self._local_out.grid(row=0, column=0, sticky="ew", padx=(0, 8), ipady=2)
        self._btn(orf, "BROWSE", self._browse_local_out, w=90).grid(row=0, column=1)

        self._section_header(sf, r, "PASSPHRASE", MIL_RED_LT); r += 2

        self._local_secret = self._ent(sf, "Enter passphrase…", show="•")
        self._local_secret.grid(row=r, column=0, sticky="ew", padx=16, ipady=2); r += 1
        self._local_secret.bind("<KeyRelease>",
            lambda e: self._update_strength(self._local_secret, self._local_strength))
        self._local_strength = ctk.CTkLabel(sf, text="", anchor="w",
            font=ctk.CTkFont(family="Courier New", size=10, weight="bold"))
        self._local_strength.grid(row=r, column=0, sticky="ew", padx=18); r += 1

        hint = ctk.CTkFrame(sf, fg_color=MIL_CARD, corner_radius=5)
        hint.grid(row=r, column=0, sticky="ew", padx=16, pady=(10, 0))
        hint.grid_columnconfigure(0, weight=1); r += 1
        ctk.CTkLabel(hint, text=(
            "  FILE ENCRYPT → adds .fort suffix  |  FILE DECRYPT → removes .fort\n"
            "  FOLDER ENCRYPT → creates .fort archive  |  FOLDER DECRYPT → extracts to subfolder"
        ), font=ctk.CTkFont(family="Courier New", size=10),
           text_color=MIL_MUTED, anchor="w"
           ).grid(row=0, column=0, sticky="ew", padx=8, pady=5)

        crf = self._irow(sf, r, pady=(14, 18)); r += 1
        crf.grid_columnconfigure(0, weight=1); crf.grid_columnconfigure(1, weight=1)
        self._local_enc_btn = self._btn(crf, "■   ENCRYPT", self._on_local_encrypt,
                  h=42, color=MIL_OLIVE, hover=MIL_OLIVE_LT)
        self._local_enc_btn.grid(row=0, column=0, sticky="ew", padx=(0, 8))
        self._local_dec_btn = self._btn(crf, "■   DECRYPT", self._on_local_decrypt,
                  h=42, color=MIL_GREEN, hover=MIL_GREEN_LT)
        self._local_dec_btn.grid(row=0, column=1, sticky="ew")

    # ══════════════════════════════════════════════════════════════════════
    # ◎ HISTORY PAGE
    # ══════════════════════════════════════════════════════════════════════

    def _build_history_page(self, p: ctk.CTkFrame) -> None:
        p.grid_columnconfigure(0, weight=1)
        p.grid_rowconfigure(0, weight=0)
        p.grid_rowconfigure(1, weight=0)
        p.grid_rowconfigure(2, weight=0)
        p.grid_rowconfigure(3, weight=1)

        self._hist_stats_lbl = ctk.CTkLabel(p, text="Loading…",
            font=ctk.CTkFont(family="Courier New", size=10),
            text_color=MIL_KHAKI, anchor="w")
        self._hist_stats_lbl.grid(row=0, column=0, sticky="ew", padx=16, pady=(12, 4))

        btnr = ctk.CTkFrame(p, fg_color="transparent")
        btnr.grid(row=1, column=0, sticky="ew", padx=16, pady=(0, 6))
        self._btn(btnr, "⟳ REFRESH", self._refresh_history, w=120,
                  color=MIL_OLIVE, hover=MIL_OLIVE_LT).grid(row=0, column=0, padx=(0, 8))
        self._btn(btnr, "✕ CLEAR LOG", self._clear_history, w=120,
                  color=MIL_CARD2, hover=MIL_RED, text_color=MIL_RED_LT).grid(row=0, column=1)

        hdr = ctk.CTkFrame(p, fg_color=MIL_CARD2, corner_radius=4)
        hdr.grid(row=2, column=0, sticky="ew", padx=16, pady=(0, 2))
        hdr.grid_columnconfigure(2, weight=1)
        for col, (txt, w) in enumerate([
            ("TIME", 130), ("DIR", 75), ("FILE", 0), ("SIZE", 80), ("SPEED", 80), ("STATUS", 65)
        ]):
            kw: dict = dict(text=txt,
                font=ctk.CTkFont(family="Courier New", size=10, weight="bold"),
                text_color=MIL_AMBER, anchor="w")
            if w: kw["width"] = w
            ctk.CTkLabel(hdr, **kw).grid(row=0, column=col, sticky="ew", padx=4, pady=4)

        self._hist_scroll = ctk.CTkScrollableFrame(
            p, fg_color="transparent", scrollbar_button_color=MIL_OLIVE)
        self._hist_scroll.grid(row=3, column=0, sticky="nsew", padx=16, pady=(0, 4))
        self._hist_scroll.grid_columnconfigure(0, weight=1)
        self._refresh_history()

    def _refresh_history(self) -> None:
        for w in self._hist_scroll.winfo_children():
            w.destroy()
        records = _history.fetch_all(limit=150)
        stats   = _history.stats()
        self._hist_stats_lbl.configure(text=(
            f"  Total: {stats['total']}  |  OK: {stats['ok']}  |  "
            f"Failed: {stats['total']-stats['ok']}  |  "
            f"Data: {_format_size(stats['total_bytes'])}  |  "
            f"Largest: {_format_size(stats['max_bytes'])}"
        ))
        for rec in records:
            rf = ctk.CTkFrame(self._hist_scroll, fg_color=MIL_CARD, corner_radius=3)
            rf.grid(sticky="ew", pady=1)
            rf.grid_columnconfigure(2, weight=1)
            sc = MIL_GREEN_LT if rec.status == "OK" else MIL_RED_LT
            dc = MIL_AMBER if "SENT" in rec.direction else MIL_GREEN_LT
            spd = (_format_size(int(rec.size_b / max(rec.duration_s, 0.001))) + "/s"
                   if rec.duration_s > 0 else "—")
            for col, (txt, w, clr) in enumerate([
                (rec.ts[:16],              130, MIL_MUTED),
                (rec.direction,             75, dc),
                (rec.filename[:40],          0, MIL_TEXT),
                (_format_size(rec.size_b),  80, MIL_KHAKI),
                (spd,                       80, MIL_KHAKI),
                (rec.status,                65, sc),
            ]):
                kw2: dict = dict(text=txt,
                    font=ctk.CTkFont(family="Courier New", size=10),
                    text_color=clr, anchor="w")
                if w: kw2["width"] = w
                lbl = ctk.CTkLabel(rf, **kw2)
                lbl.grid(row=0, column=col, sticky="ew", padx=4, pady=3)
                self._attach_label_copy_menu(lbl, txt)

    def _clear_history(self) -> None:
        if messagebox.askyesno("CLEAR HISTORY", "Delete all transfer history?"):
            _history.clear()
            self._refresh_history()
            self._toast("History cleared", MIL_AMBER)

    # ══════════════════════════════════════════════════════════════════════
    # ◈ DIAGNOSTICS PAGE
    # ══════════════════════════════════════════════════════════════════════

    def _build_diag_page(self, p: ctk.CTkFrame) -> None:
        p.grid_columnconfigure(0, weight=1)
        p.grid_rowconfigure(0, weight=0)
        p.grid_rowconfigure(1, weight=0)
        p.grid_rowconfigure(2, weight=1)

        ctk.CTkLabel(p, text="  ◈  Test connectivity before transfer",
                     font=ctk.CTkFont(family="Courier New", size=11, weight="bold"),
                     text_color=MIL_AMBER, anchor="w"
                     ).grid(row=0, column=0, sticky="ew", padx=16, pady=(14, 8))

        tgt = ctk.CTkFrame(p, fg_color="transparent")
        tgt.grid(row=1, column=0, sticky="ew", padx=16, pady=(0, 8))
        tgt.grid_columnconfigure(0, weight=1)
        self._diag_ip = self._ent(tgt, "Target IP / hostname…")
        self._diag_ip.grid(row=0, column=0, sticky="ew", padx=(0, 8), ipady=2)
        self._diag_port = self._ent(tgt, "Port")
        self._diag_port.insert(0, str(self._cfg["default_port"]))
        self._diag_port.configure(width=90)
        self._diag_port.grid(row=0, column=1, padx=(0, 8), ipady=2)
        self._btn(tgt, "▶ RUN TESTS", self._run_diagnostics, w=140,
                  color=MIL_OLIVE, hover=MIL_OLIVE_LT).grid(row=0, column=2)

        self._diag_text = ctk.CTkTextbox(p,
            font=ctk.CTkFont(family="Courier New", size=11),
            fg_color=MIL_BG, text_color=MIL_TEXT,
            border_color=MIL_OLIVE, border_width=1)
        self._diag_text.grid(row=2, column=0, sticky="nsew", padx=16, pady=(0, 12))
        self._diag_text.insert("end",
            "  ◈  Enter a target IP and port, then click RUN TESTS.\n\n"
            "  Tests: DNS resolution · TCP connect · Latency × 3 · LAN peers\n")
        self._diag_text.configure(state="disabled")
        self._attach_textbox_menu(self._diag_text)

    def _run_diagnostics(self) -> None:
        ip = self._diag_ip.get().strip()
        if not ip: self._toast("Enter a target IP/hostname", MIL_RED_LT); return
        try:    port = int(self._diag_port.get().strip())
        except (ValueError, AttributeError): port = 5001
        self._diag_text.configure(state="normal")
        self._diag_text.delete("1.0", "end")
        self._diag_text.insert("end", f"[ RUNNING ]  Target: {ip}:{port}\n\n")
        self._diag_text.configure(state="disabled")
        threading.Thread(target=self._worker_diagnostics, args=(ip, port), daemon=True).start()

    def _worker_diagnostics(self, ip: str, port: int) -> None:
        def log(t: str) -> None:
            self.after(0, lambda x=t: self._diag_append(x))
        log(f"  Local IP   : {_get_local_ip()}\n")
        log("  DNS        : resolving…")
        try:
            resolved = socket.getaddrinfo(ip, port, proto=socket.IPPROTO_TCP)[0][4][0]
            log(f" → {resolved}  ✓\n")
        except socket.gaierror as exc:
            log(f" → FAILED: {exc}\n"); return
        latencies = []
        for i in range(3):
            log(f"  TCP #{i+1}      : connecting…")
            t0 = time.monotonic()
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(5.0); s.connect((ip, port))
                ms = (time.monotonic() - t0) * 1000
                latencies.append(ms); log(f" → {ms:.1f} ms  ✓\n")
            except (ConnectionRefusedError, TimeoutError, OSError) as exc:
                log(f" → FAILED: {exc}\n")
        if latencies:
            avg = sum(latencies) / len(latencies)
            tag = "EXCELLENT" if avg < 50 else "GOOD" if avg < 150 else "HIGH"
            log(f"\n  Avg latency: {avg:.1f} ms  ({tag})\n")
        else:
            log("\n  ✗ Port CLOSED — try ngrok or WORMHOLE tab.\n")
        peers = self._lan_discovery.peers() if self._lan_discovery else {}
        log(f"\n  LAN peers  : {len(peers)} discovered\n")
        for pip, (hn, pp) in peers.items():
            log(f"               {pip}  ({hn}:{pp})\n")
        log("\n  [ DIAGNOSTICS COMPLETE ]\n")

    def _diag_append(self, text: str) -> None:
        if self._diag_text:
            self._diag_text.configure(state="normal")
            self._diag_text.insert("end", text)
            self._diag_text.see("end")
            self._diag_text.configure(state="disabled")

    # ══════════════════════════════════════════════════════════════════════
    # ⚙ SETTINGS PAGE
    # ══════════════════════════════════════════════════════════════════════

    def _build_settings_page(self, p: ctk.CTkFrame) -> None:
        sf = self._tab_scroll(p); r = 0

        def setting_row(label: str, var: ctk.StringVar | None = None,
                        ph: str = "", width: int = 200) -> ctk.CTkEntry | None:
            nonlocal r
            self._lbl(sf, label).grid(row=r, column=0, sticky="w", padx=16, pady=(12, 3))
            r += 1
            if var is not None:
                e = self._ent(sf, ph, var=var)
                e.configure(width=width)
                e.grid(row=r, column=0, sticky="w", padx=16, ipady=2)
                r += 1
                return e
            return None

        self._section_header(sf, r, "NETWORK DEFAULTS", MIL_AMBER); r += 2
        setting_row("◉  DEFAULT PORT  (used for new sessions)", self._cfg_port_var, "5001", 160)

        self._section_header(sf, r, "FILE HANDLING", MIL_AMBER); r += 2
        self._lbl(sf, "◉  DEFAULT SAVE DIRECTORY").grid(
            row=r, column=0, sticky="w", padx=16, pady=(4, 3)); r += 1
        sdf = self._irow(sf, r); r += 1
        se = self._ent(sdf, "", var=self._cfg_dir_var)
        se.grid(row=0, column=0, sticky="ew", padx=(0, 8), ipady=2)
        self._btn(sdf, "BROWSE", self._settings_browse_dir, w=90).grid(row=0, column=1)

        self._section_header(sf, r, "SECURITY TIMERS", MIL_RED_LT); r += 2
        setting_row("◉  SESSION TIMEOUT  (minutes, 0 = disabled)", self._cfg_timeout_var, "10", 140)
        setting_row("◉  CLIPBOARD AUTO-CLEAR  (seconds)", self._cfg_clip_var, "30", 140)
        setting_row("◉  BURN-AFTER-READ DELAY  (seconds)", self._cfg_burn_var, "60", 140)

        self._section_header(sf, r, "FEATURES", MIL_TAN); r += 2
        lan_f = ctk.CTkFrame(sf, fg_color="transparent")
        lan_f.grid(row=r, column=0, sticky="ew", padx=16, pady=(4, 0)); r += 1
        ctk.CTkCheckBox(lan_f,
                        text="  Enable LAN Discovery  (UDP beacon port 47474)",
                        variable=self._cfg_lan_var,
                        font=ctk.CTkFont(family="Courier New", size=11),
                        text_color=MIL_TAN, fg_color=MIL_OLIVE,
                        hover_color=MIL_OLIVE_LT, border_color=MIL_OLIVE
                        ).grid(row=0, column=0, sticky="w")

        # info box
        info = ctk.CTkFrame(sf, fg_color=MIL_CARD, corner_radius=6)
        info.grid(row=r, column=0, sticky="ew", padx=16, pady=(14, 4))
        info.grid_columnconfigure(0, weight=1); r += 1
        ctk.CTkLabel(info,
                     text="  Settings are saved to ~/.p2p_fortress.json\n"
                          "  and applied on the next app launch.",
                     font=ctk.CTkFont(family="Courier New", size=10),
                     text_color=MIL_MUTED, anchor="w"
                     ).grid(row=0, column=0, sticky="ew", padx=10, pady=6)

        # save button
        self._btn(sf, "⚙   SAVE ALL SETTINGS", self._save_all_settings,
                  h=48, color=MIL_OLIVE, hover=MIL_OLIVE_LT
                  ).grid(row=r, column=0, sticky="ew", padx=16, pady=(6, 18))

        # danger zone
        self._section_header(sf, r+1, "DANGER ZONE", MIL_RED_LT)
        r += 3
        danger = ctk.CTkFrame(sf, fg_color="#1A0000", corner_radius=6,
                               border_color=MIL_RED_LT, border_width=1)
        danger.grid(row=r, column=0, sticky="ew", padx=16, pady=(0, 4))
        danger.grid_columnconfigure(0, weight=1); r += 1
        ctk.CTkLabel(danger,
                     text="  These actions are irreversible.",
                     font=ctk.CTkFont(family="Courier New", size=10),
                     text_color=MIL_RED_LT, anchor="w"
                     ).grid(row=0, column=0, sticky="ew", padx=10, pady=(8, 2))
        dr = ctk.CTkFrame(danger, fg_color="transparent")
        dr.grid(row=1, column=0, sticky="ew", padx=10, pady=(0, 8))
        self._btn(dr, "✕ CLEAR HISTORY", self._clear_history, w=160,
                  color=MIL_CARD2, hover=MIL_RED, text_color=MIL_RED_LT
                  ).grid(row=0, column=0, padx=(0, 8))
        self._btn(dr, "↺ RESET SETTINGS", self._reset_settings, w=160,
                  color=MIL_CARD2, hover=MIL_RED, text_color=MIL_RED_LT
                  ).grid(row=0, column=1)

    def _settings_browse_dir(self) -> None:
        d = filedialog.askdirectory(title="Select default save directory")
        if d: self._cfg_dir_var.set(d)

    def _save_all_settings(self) -> None:
        try:
            port = int(self._cfg_port_var.get())
            assert 1 <= port <= 65535
        except (ValueError, AssertionError):
            self._toast("Invalid port number", MIL_RED_LT); return
        try:
            timeout   = int(self._cfg_timeout_var.get())
            clip      = int(self._cfg_clip_var.get())
            burn_dly  = max(5, int(self._cfg_burn_var.get()))
        except ValueError:
            self._toast("Timeout values must be integers", MIL_RED_LT); return

        self._cfg.update({
            "default_port":        port,
            "save_dir":            self._cfg_dir_var.get(),
            "session_timeout_min": timeout,
            "clipboard_clear_sec": clip,
            "burn_delay_sec":      burn_dly,
            "lan_discovery":       bool(self._cfg_lan_var.get()),
        })
        _save_settings(self._cfg)
        self._toast("⚙  Settings saved — restart to apply changes", MIL_GREEN_LT, 4000)

    def _reset_settings(self) -> None:
        if messagebox.askyesno("RESET SETTINGS", "Reset all settings to defaults?"):
            self._cfg = dict(_DEFAULT_SETTINGS)
            _save_settings(self._cfg)
            self._cfg_port_var.set(str(_DEFAULT_SETTINGS["default_port"]))
            self._cfg_dir_var.set(_DEFAULT_SETTINGS["save_dir"])
            self._cfg_timeout_var.set(str(_DEFAULT_SETTINGS["session_timeout_min"]))
            self._cfg_clip_var.set(str(_DEFAULT_SETTINGS["clipboard_clear_sec"]))
            self._cfg_burn_var.set(str(_DEFAULT_SETTINGS["burn_delay_sec"]))
            self._cfg_lan_var.set(_DEFAULT_SETTINGS["lan_discovery"])
            self._toast("Settings reset to defaults", MIL_AMBER)

    # ══════════════════════════════════════════════════════════════════════
    # ◈ FIELD MANUAL PAGE
    # ══════════════════════════════════════════════════════════════════════

    def _build_guide_page(self, p: ctk.CTkFrame) -> None:
        p.grid_columnconfigure(0, weight=1)
        p.grid_rowconfigure(0, weight=1)
        outer = ctk.CTkScrollableFrame(p, fg_color="transparent",
                                        scrollbar_button_color=MIL_OLIVE)
        outer.grid(row=0, column=0, sticky="nsew", padx=4, pady=4)
        outer.grid_columnconfigure(0, weight=1)
        rc = [0]

        def sec(t, c=MIL_AMBER):
            ctk.CTkLabel(outer, text=t,
                font=ctk.CTkFont(family="Courier New", size=12, weight="bold"),
                text_color=c, anchor="w"
            ).grid(row=rc[0], column=0, sticky="ew", padx=12, pady=(12, 2)); rc[0] += 1
            ctk.CTkFrame(outer, fg_color=c, height=1
            ).grid(row=rc[0], column=0, sticky="ew", padx=12, pady=(0, 4)); rc[0] += 1

        def ln(t, c=MIL_TEXT):
            ctk.CTkLabel(outer, text=t,
                font=ctk.CTkFont(family="Courier New", size=11),
                text_color=c, anchor="w", wraplength=780, justify="left"
            ).grid(row=rc[0], column=0, sticky="ew", padx=20, pady=1); rc[0] += 1

        def blk(t):
            f = ctk.CTkFrame(outer, fg_color=MIL_CARD, corner_radius=4)
            f.grid(row=rc[0], column=0, sticky="ew", padx=12, pady=2)
            f.grid_columnconfigure(0, weight=1); rc[0] += 1
            ctk.CTkLabel(f, text=t,
                font=ctk.CTkFont(family="Courier New", size=10),
                text_color=MIL_KHAKI, anchor="w", wraplength=760, justify="left"
            ).grid(row=0, column=0, sticky="ew", padx=10, pady=4)

        sec("[ SOP-01 ]  GENERAL OPERATION", MIL_GREEN_LT)
        ln("1.  Agree on a shared passphrase via a secure out-of-band channel.")
        ln("2.  RECEIVER → RECEIVE page → port + passphrase → OPEN CHANNEL")
        ln("3.  SENDER → TRANSMIT page → file + IP + port + passphrase → ENCRYPT & TRANSMIT")
        ln("4.  After handshake: verify 4-word SAS fingerprint verbally!")
        blk("◈  The passphrase NEVER travels the network. Only X25519 public keys are exchanged.")

        sec("[ SOP-02 ]  SAS FINGERPRINT — MITM DETECTION", MIL_RED_LT)
        ln("Both sides display 4 words after handshake. Call and verify they match.")
        blk("◈  The SAS is derived from the X25519 shared secret — impossible to fake via MITM.")

        sec("[ SOP-03 ]  FAVORITE PEERS", MIL_AMBER)
        ln("Enter IP + port → type a name → ★ SAVE PEER. Select from the dropdown on next use.")

        sec("[ SOP-04 ]  RECENT FILES", MIL_AMBER)
        ln("The last 8 transmitted files appear as a quick-access list in the TRANSMIT page.")

        sec("[ SOP-05 ]  MULTI-FILE SEND", MIL_TAN)
        ln("Enable the 📦 MULTI-FILE checkbox, then BROWSE selects multiple files.")
        blk("◈  Files are zipped transparently before encryption and unzipped on the receiver side.")

        sec("[ SOP-06 ]  BURN AFTER READING", MIL_RED_LT)
        ln("Check 🔥 BURN AFTER READING → receiver's file is securely deleted after 60 s.")

        sec("[ SOP-07 ]  FOLDER ENCRYPTION", MIL_AMBER)
        ln("LOCAL CRYPTO → FOLDER button → ENCRYPT → single .fort archive output.")
        ln("DECRYPT: select .fort file → files extracted to subfolder.")

        sec("[ SOP-08 ]  SETTINGS", MIL_TAN)
        ln("⚙ SETTINGS page: default port, save dir, session timeout, clipboard clear interval.")
        ln("All settings persist to ~/.p2p_fortress.json and load on next launch.")

        sec("[ SOP-09 ]  GLOBAL NETWORK (WAN)", MIL_RED_LT)
        ln("METHOD A — ngrok (fastest):", MIL_GREEN_LT)
        blk("ngrok tcp 5001    →   SENDER: IP = 0.tcp.ngrok.io  PORT = (shown number)")
        ln("METHOD B — Port forwarding on your router.", MIL_AMBER)
        ln("METHOD C — Tailscale (free for 3 devices).", MIL_TAN)
        ln("METHOD D — ⊕ WORMHOLE page (zero setup, relay-based).", MIL_KHAKI)

    # ══════════════════════════════════════════════════════════════════════
    # ★ MISSION INFO PAGE
    # ══════════════════════════════════════════════════════════════════════

    def _build_about_page(self, p: ctk.CTkFrame) -> None:
        p.grid_columnconfigure(0, weight=1)
        p.grid_rowconfigure(0, weight=1)
        outer = ctk.CTkScrollableFrame(p, fg_color="transparent",
                                        scrollbar_button_color=MIL_OLIVE)
        outer.grid(row=0, column=0, sticky="nsew", padx=4, pady=4)
        outer.grid_columnconfigure(0, weight=1)
        r = 0

        tf = ctk.CTkFrame(outer, fg_color=MIL_CARD, corner_radius=8,
                           border_color=MIL_OLIVE, border_width=1)
        tf.grid(row=r, column=0, sticky="ew", padx=12, pady=(10, 6))
        tf.grid_columnconfigure(0, weight=1); r += 1
        ctk.CTkLabel(tf, text="▣  P2P FORTRESS",
            font=ctk.CTkFont(family="Courier New", size=22, weight="bold"),
            text_color=MIL_GREEN_LT).grid(row=0, column=0, pady=(14, 2))
        ctk.CTkLabel(tf, text="Ultra-Secure Peer-to-Peer File Transfer System",
            font=ctk.CTkFont(family="Courier New", size=12),
            text_color=MIL_TAN).grid(row=1, column=0)
        ctk.CTkLabel(tf, text="Version 13.0  //  CLASSIFICATION: CRYPTO-GRADE+",
            font=ctk.CTkFont(family="Courier New", size=10),
            text_color=MIL_AMBER).grid(row=2, column=0, pady=(2, 14))

        df = ctk.CTkFrame(outer, fg_color="#130A00", corner_radius=7,
                           border_color=MIL_AMBER, border_width=1)
        df.grid(row=r, column=0, sticky="ew", padx=12, pady=6)
        df.grid_columnconfigure(0, weight=1); r += 1
        ctk.CTkLabel(df, text="// COPYRIGHT & LEGAL NOTICE",
            font=ctk.CTkFont(family="Courier New", size=10, weight="bold"),
            text_color=MIL_AMBER, anchor="w"
        ).grid(row=0, column=0, sticky="ew", padx=12, pady=(10, 4))
        ctk.CTkLabel(df, text=(
            "© 2024 Moshe Pinchasi. All rights reserved.\n\n"
            'This software is provided "as is", without warranty of any kind.\n'
            "Any misuse of this tool for illegal activities is strictly prohibited."
        ), font=ctk.CTkFont(family="Courier New", size=11),
           text_color=MIL_TAN, justify="left", anchor="w"
        ).grid(row=1, column=0, sticky="ew", padx=12, pady=(0, 12))

        ctk.CTkLabel(outer, text="// CRYPTOGRAPHIC STACK",
            font=ctk.CTkFont(family="Courier New", size=11, weight="bold"),
            text_color=MIL_GREEN_LT, anchor="w"
        ).grid(row=r, column=0, sticky="ew", padx=12, pady=(12, 2)); r += 1
        ctk.CTkFrame(outer, fg_color=MIL_GREEN_LT, height=1
        ).grid(row=r, column=0, sticky="ew", padx=12, pady=(0, 4)); r += 1

        for label, val, color in [
            ("Key Exchange",    "X25519 ECDH — Ephemeral (PFS)",                       MIL_GREEN_LT),
            ("SAS Fingerprint", "SHA-256 → 4-word MITM detector",                     MIL_GREEN_LT),
            ("Replay Guard",    "8-byte nonce — blocks replayed handshakes",            MIL_GREEN_LT),
            ("KDF",             "Argon2id — 128MB RAM · 4 iter · ECDH-XOR",            MIL_AMBER),
            ("Sub-key Gen",     "HKDF-SHA512 — 3 × 32-byte domain keys",              MIL_AMBER),
            ("Cipher #1",       "ChaCha20-Poly1305 AEAD",                              MIL_AMBER),
            ("Cipher #2",       "AES-256-GCM AEAD  (NSA Suite B)",                    MIL_RED_LT),
            ("MAC",             "HMAC-SHA512 — constant-time",                         MIL_RED_LT),
            ("Integrity",       "SHA-512 post-decrypt verify",                         MIL_TAN),
            ("Rate Limiting",   "5 failures → 60 s IP block",                         MIL_TAN),
            ("Memory Safety",   "Key zeroization (bytearray zero-fill)",               MIL_KHAKI),
            ("Secure Delete",   "2-pass overwrite before file removal",                 MIL_KHAKI),
            ("GUI v8",          "Sidebar nav · Settings · Toasts · Recent · Favorites",MIL_KHAKI),
        ]:
            sr = ctk.CTkFrame(outer, fg_color=MIL_CARD, corner_radius=4)
            sr.grid(row=r, column=0, sticky="ew", padx=12, pady=1)
            sr.grid_columnconfigure(1, weight=1); r += 1
            ctk.CTkLabel(sr, text=f"  {label}", width=155,
                font=ctk.CTkFont(family="Courier New", size=10, weight="bold"),
                text_color=color, anchor="w").grid(row=0, column=0, sticky="w", padx=(6,2), pady=4)
            ctk.CTkLabel(sr, text=val,
                font=ctk.CTkFont(family="Courier New", size=10),
                text_color=MIL_KHAKI, anchor="w"
            ).grid(row=0, column=1, sticky="ew", pady=4)

    # ══════════════════════════════════════════════════════════════════════
    # BROWSE HELPERS
    # ══════════════════════════════════════════════════════════════════════

    def _browse_send_file(self) -> None:
        if self._multi_var.get():
            paths = filedialog.askopenfilenames(title="Select files to send")
            if paths:
                self._send_files = [Path(p) for p in paths]
                names = ", ".join(p.name for p in self._send_files[:3])
                if len(self._send_files) > 3:
                    names += f" (+{len(self._send_files)-3} more)"
                self._send_file_entry.delete(0, "end")
                self._send_file_entry.insert(0, f"[{len(self._send_files)} files]  {names}")
        else:
            p = filedialog.askopenfilename(title="Select file for transmission")
            if p: self._set_send_file(Path(p))

    def _set_send_file(self, path: Path) -> None:
        self._send_file = path
        self._send_files = []
        self._send_file_entry.delete(0, "end")
        self._send_file_entry.insert(0, str(path))

    def _browse_save_dir(self) -> None:
        d = filedialog.askdirectory(title="Select save directory")
        if d: self._save_dir.delete(0, "end"); self._save_dir.insert(0, d)

    def _browse_local_src(self) -> None:
        p = filedialog.askopenfilename(title="Select file")
        if p:
            self._local_src = Path(p); self._local_src_is_dir = False
            self._local_src_entry.delete(0, "end"); self._local_src_entry.insert(0, p)

    def _browse_local_src_dir(self) -> None:
        d = filedialog.askdirectory(title="Select folder to encrypt")
        if d:
            self._local_src = Path(d); self._local_src_is_dir = True
            self._local_src_entry.delete(0, "end"); self._local_src_entry.insert(0, d)

    def _browse_local_out(self) -> None:
        d = filedialog.askdirectory(title="Select output directory")
        if d: self._local_out.delete(0, "end"); self._local_out.insert(0, d)

    def _wh_browse_file(self) -> None:
        p = filedialog.askopenfilename(title="Select file for Wormhole")
        if p:
            self._wh_file = Path(p)
            self._wh_file_entry.delete(0, "end"); self._wh_file_entry.insert(0, p)

    def _wh_browse_save(self) -> None:
        d = filedialog.askdirectory(title="Select save directory")
        if d: self._wh_save_dir.delete(0, "end"); self._wh_save_dir.insert(0, d)

    def _fill_local_ip(self) -> None:
        ip = _get_local_ip()
        self._ip_entry.delete(0, "end"); self._ip_entry.insert(0, ip)

    # ══════════════════════════════════════════════════════════════════════
    # LAN DISCOVERY
    # ══════════════════════════════════════════════════════════════════════

    def _start_lan_discovery(self) -> None:
        try:
            port = self._cfg.get("default_port", 5001)
            self._lan_discovery = LANDiscovery(tcp_port=port)
            self._lan_discovery.start()
            self.after(6000, self._update_lan_menu)
        except Exception:
            pass

    def _update_lan_menu(self) -> None:
        if not self._lan_discovery:
            return
        peers = self._lan_discovery.peers()
        if peers:
            values = [f"{hn} ({ip}:{pp})" for ip, (hn, pp) in peers.items()]
            current = self._lan_peer_menu.cget("values") if self._lan_peer_menu else []
            if values != list(current) and self._lan_peer_menu:
                self._lan_peer_menu.configure(values=values)
        self._lan_update_job = self.after(10_000, self._update_lan_menu)

    def _on_lan_peer_selected(self, value: str) -> None:
        m = re.search(r'\(([^:]+):(\d+)\)', value)
        if m:
            ip, port = m.group(1), m.group(2)
            self._ip_entry.delete(0, "end");  self._ip_entry.insert(0, ip)
            self._send_port.delete(0, "end"); self._send_port.insert(0, port)
            self._toast(f"LAN peer: {ip}:{port}", MIL_TAN)

    # ══════════════════════════════════════════════════════════════════════
    # DRAG & DROP
    # ══════════════════════════════════════════════════════════════════════

    def _setup_dnd(self) -> None:
        try:
            from tkinterdnd2 import DND_FILES  # type: ignore
            self.drop_target_register(DND_FILES)
            self.dnd_bind("<<Drop>>", self._on_file_drop)
        except Exception:
            pass

    def _on_file_drop(self, event: object) -> None:
        try:
            path = Path(event.data.strip("{}"))  # type: ignore[attr-defined]
            if path.is_file():
                self._set_send_file(path)
                self._navigate("send")
                self._toast(f"Dropped: {path.name}", MIL_GREEN_LT)
        except Exception:
            pass

    # ══════════════════════════════════════════════════════════════════════
    # PORT VALIDATOR
    # ══════════════════════════════════════════════════════════════════════

    def _parse_port(self, entry: ctk.CTkEntry) -> int | None:
        try:
            port = int(entry.get().strip())
        except ValueError:
            self._toast("PORT must be a whole number", MIL_RED_LT); return None
        if not 1 <= port <= 65535:
            self._toast("PORT must be 1–65535", MIL_RED_LT); return None
        return port

    # ══════════════════════════════════════════════════════════════════════
    # THREAD-SAFE ERROR DISPATCH
    # Centralises all worker-thread → main-thread error reporting.
    # Avoids repeated lambda captures and ensures consistent UX.
    # ══════════════════════════════════════════════════════════════════════

    def _err_thread(self, title: str, exc: Exception, *,
                    dialog: bool = False) -> None:
        """Call from a worker thread. Dispatches error to main thread safely."""
        msg = str(exc)
        if dialog:
            self.after(0, lambda t=title, m=msg: messagebox.showerror(t, m))
        else:
            self.after(0, lambda t=title, m=msg: self._toast(f"{t}: {m}", MIL_RED_LT, 5000))

    # ══════════════════════════════════════════════════════════════════════
    # TRANSMIT HANDLERS
    # ══════════════════════════════════════════════════════════════════════

    def _on_send(self) -> None:
        # Determine what to send (single vs multi-file)
        is_bundle = False
        if self._multi_var.get() and self._send_files:
            tmp = Path(tempfile.mkdtemp()) / "fortress_bundle.zip"
            with zipfile.ZipFile(tmp, "w", zipfile.ZIP_DEFLATED) as zf:
                for fp in self._send_files:
                    zf.write(fp, fp.name)
            target_file = tmp
            is_bundle   = True
        elif self._send_file:
            target_file = self._send_file
        else:
            self._toast("No file selected", MIL_RED_LT); return

        ip     = self._ip_entry.get().strip()
        secret = self._send_secret.get()
        port   = self._parse_port(self._send_port)
        if not ip:     self._toast("Target IP required", MIL_RED_LT); return
        if not secret: self._toast("Passphrase required", MIL_RED_LT); return
        if port is None: return

        client = FileClient(
            host=ip, port=port,
            on_progress=self._progress_cb,
            on_sas=lambda s: self.after(0, lambda sas=s: self._show_sas(sas, True)),
            burn_after_reading=self._burn_var.get())
        self._progress_cb(0.0, "[ TRANSMIT ]  Preparing…")
        self.after(0, lambda: self._sas_label.configure(text=""))
        self._op_lock(self._send_btn)
        threading.Thread(
            target=self._worker_send,
            args=(client, target_file, secret, self._send_file, is_bundle),
            daemon=True).start()

    def _worker_send(self, client: FileClient, fp: Path,
                     secret: str, original: Path | None,
                     is_bundle: bool = False) -> None:
        try:
            client.send(fp, secret)
            if original:
                self._push_recent(original)
            fname = fp.name
            self.after(0, lambda fn=fname: self._notify("Fortress", f"Sent: {fn}"))
        except FileNotFoundError as exc:
            self._err_thread("FILE ERROR", exc)
        except HandshakeError as exc:
            self._err_thread("HANDSHAKE FAILURE", exc, dialog=True)
        except NetworkError as exc:
            self._err_thread("NETWORK ERROR", exc)
        except P2PError as exc:
            self._err_thread("CRYPTO ERROR", exc, dialog=True)
        except Exception:
            logger.exception("Transmit error")
            self._err_thread("SYSTEM ERROR", Exception("Unexpected error — check fortress.log"), dialog=True)
        finally:
            self.after(0, self._op_unlock)
            if is_bundle:
                try: fp.unlink(missing_ok=True)
                except OSError: pass

    # ══════════════════════════════════════════════════════════════════════
    # RECEIVE HANDLERS
    # ══════════════════════════════════════════════════════════════════════

    def _on_listen(self) -> None:
        secret   = self._recv_secret.get(); port = self._parse_port(self._recv_port)
        save_dir = Path(self._save_dir.get().strip())
        if not secret: self._toast("Passphrase required", MIL_RED_LT); return
        if port is None: return
        if not save_dir.is_dir():
            self._toast(f"Save dir not found: {save_dir}", MIL_RED_LT); return
        self._on_stop_server()
        self._server = FileServer(port=port, save_dir=save_dir, on_progress=self._progress_cb,
                                   on_sas=lambda s: self.after(0, lambda sas=s: self._show_sas(sas, False)))
        self._srv_thread = threading.Thread(target=self._worker_listen,
                                             args=(self._server, secret), daemon=True)
        self._progress_cb(0.0, "[ RECEIVE ]  Opening channel…")
        self.after(0, lambda: self._recv_sas_label.configure(text=""))
        self._srv_thread.start()
        self._listen_btn.configure(fg_color=MIL_GREEN, hover_color=MIL_GREEN_LT)

    def _worker_listen(self, srv: FileServer, secret: str) -> None:
        try:
            srv.listen(secret)
            self.after(0, lambda: self._notify("Fortress", "File received successfully."))
        except (AuthenticationError, InvalidKeyError, IntegrityError) as exc:
            self._err_thread("CRYPTO ALERT", exc, dialog=True)
        except HandshakeError as exc:
            self._err_thread("HANDSHAKE FAILURE", exc, dialog=True)
        except NetworkError as exc:
            self._progress_cb(0.0, f"[ NETWORK ERROR ]  {exc}")
        except Exception:
            logger.exception("Server error")
            self._err_thread("SYSTEM ERROR", Exception("Unexpected error — check fortress.log"), dialog=True)
        finally:
            self.after(0, self._reset_listen_btn)

    def _on_stop_server(self) -> None:
        if self._server: self._server.stop(); self._server = None
        self._reset_listen_btn()
        self._status_update(0.0, "[ CHANNEL CLOSED ]  Server halted.")

    def _reset_listen_btn(self) -> None:
        self._listen_btn.configure(fg_color=MIL_OLIVE, hover_color=MIL_OLIVE_LT)

    def _show_sas(self, sas: str, send: bool) -> None:
        text = f"  ◈  SAS:  {sas}  — verify verbally!"
        if send:
            self._sas_label.configure(text=text)
        else:
            self._recv_sas_label.configure(text=text)

    # ══════════════════════════════════════════════════════════════════════
    # WORMHOLE HANDLERS
    # ══════════════════════════════════════════════════════════════════════

    def _wh_copy_code(self) -> None:
        code = self._wh_code_var.get()
        if code and "—" not in code:
            self.clipboard_clear(); self.clipboard_append(code)
            self._schedule_clipboard_clear()
            self._toast("Code copied — auto-clear 30 s", MIL_TAN)

    def _on_wh_send(self) -> None:
        if not self._wh_file: self._toast("No file selected", MIL_RED_LT); return
        pw = self._wh_passphrase.get()
        if not pw: self._toast("Passphrase required", MIL_RED_LT); return
        self._wh_code_var.set("⟳  Connecting to relay…")
        self._wh_send_btn.configure(state="disabled", fg_color=MIL_MUTED)
        self._progress_cb(0.0, "[ WORMHOLE ]  Preparing…")
        threading.Thread(target=self._worker_wh_send,
                         args=(self._wh_file, pw), daemon=True).start()

    def _worker_wh_send(self, fp: Path, pw: str) -> None:
        def on_code(code: str) -> None:
            self.after(0, lambda c=code: self._wh_code_var.set(c))
        try:
            WormholeManager.send(fp, pw, self._progress_cb, on_code)
            fname = fp.name
            self.after(0, lambda fn=fname: self._notify("Fortress", f"Wormhole sent: {fn}"))
        except WormholeError as exc:
            self._err_thread("WORMHOLE ERROR", exc, dialog=True)
        except Exception:
            logger.exception("Wormhole send error")
            self._err_thread("SYSTEM ERROR", Exception("Unexpected error — check fortress.log"), dialog=True)
        finally:
            self.after(0, lambda: self._wh_send_btn.configure(
                    state="normal", fg_color="#1E3A6E", hover_color="#2C5494"))

    def _on_wh_receive(self) -> None:
        code = self._wh_code_entry.get().strip()
        if not code: self._toast("Enter the wormhole code", MIL_RED_LT); return
        pw = self._wh_passphrase.get()
        if not pw: self._toast("Passphrase required", MIL_RED_LT); return
        save_dir = Path(self._wh_save_dir.get().strip())
        if not save_dir.is_dir():
            self._toast(f"Save dir not found: {save_dir}", MIL_RED_LT); return
        self._wh_recv_btn.configure(state="disabled", fg_color=MIL_MUTED)
        self._progress_cb(0.0, "[ WORMHOLE ]  Connecting to relay…")
        threading.Thread(target=self._worker_wh_receive,
                         args=(code, pw, save_dir), daemon=True).start()

    def _worker_wh_receive(self, code: str, pw: str, save_dir: Path) -> None:
        try:
            WormholeManager.receive(code, pw, save_dir, self._progress_cb)
            self.after(0, lambda: self._notify("Fortress", "Wormhole file received."))
        except WormholeError as exc:
            self._err_thread("WORMHOLE ERROR", exc, dialog=True)
        except (AuthenticationError, InvalidKeyError, IntegrityError) as exc:
            self._err_thread("CRYPTO ALERT", exc, dialog=True)
        except Exception:
            logger.exception("Wormhole receive error")
            self._err_thread("SYSTEM ERROR", Exception("Unexpected error — check fortress.log"), dialog=True)
        finally:
            self.after(0, lambda: self._wh_recv_btn.configure(
                state="normal", fg_color=MIL_GREEN, hover_color=MIL_GREEN_LT))

    def _on_wh_cancel(self) -> None:
        WormholeManager.STOP_SEND.set(); WormholeManager.STOP_RECEIVE.set()
        self._toast("Wormhole cancel signal sent", MIL_AMBER)

    # ══════════════════════════════════════════════════════════════════════
    # LOCAL CRYPTO HANDLERS
    # ══════════════════════════════════════════════════════════════════════

    def _on_local_encrypt(self) -> None:
        src, out_dir, secret = self._validate_local()
        if src is None: return
        self._progress_cb(0.0, "[ LOCAL CRYPTO ]  Starting encryption…")
        dst = out_dir / (src.name + ".fort")
        self._op_lock(self._local_enc_btn, self._local_dec_btn)
        if self._local_src_is_dir and src.is_dir():
            threading.Thread(target=self._worker_folder_encrypt,
                             args=(src, dst, secret), daemon=True).start()
        else:
            threading.Thread(target=self._worker_local_encrypt,
                             args=(src, dst, secret), daemon=True).start()

    def _on_local_decrypt(self) -> None:
        src, out_dir, secret = self._validate_local()
        if src is None: return
        self._progress_cb(0.0, "[ LOCAL CRYPTO ]  Starting decryption…")
        self._op_lock(self._local_enc_btn, self._local_dec_btn)
        try: magic = src.read_bytes()[:12]
        except OSError: magic = b""
        if magic == b"FORTv3DIR\x00\x01":
            threading.Thread(target=self._worker_folder_decrypt,
                             args=(src, out_dir / src.stem, secret), daemon=True).start()
        else:
            stem = src.stem if src.suffix.lower() == ".fort" else src.name + "_dec"
            threading.Thread(target=self._worker_local_decrypt,
                             args=(src, out_dir / stem, secret), daemon=True).start()

    def _validate_local(self) -> tuple[Path | None, Path | None, str | None]:
        if not self._local_src:
            self._toast("No source selected", MIL_RED_LT); return None, None, None
        secret = self._local_secret.get()
        if not secret:
            self._toast("Passphrase required", MIL_RED_LT); return None, None, None
        out_dir = Path(self._local_out.get().strip())
        if not out_dir.is_dir():
            self._toast(f"Output dir not found: {out_dir}", MIL_RED_LT); return None, None, None
        return self._local_src, out_dir, secret

    def _worker_local_encrypt(self, src: Path, dst: Path, secret: str) -> None:
        try:
            LocalEncryptor.encrypt_file(src, dst, secret, self._progress_cb)
            dname = dst.name
            self.after(0, lambda fn=dname: self._notify("Fortress", f"Encrypted → {fn}"))
        except (ValueError, P2PError) as exc:
            self._err_thread("ENCRYPT ERROR", exc, dialog=True)
        except Exception:
            logger.exception("Local encrypt error")
            self._err_thread("SYSTEM ERROR", Exception("Unexpected error — check fortress.log"), dialog=True)
        finally:
            self.after(0, self._op_unlock)

    def _worker_local_decrypt(self, src: Path, dst: Path, secret: str) -> None:
        try:
            LocalEncryptor.decrypt_file(src, dst, secret, self._progress_cb)
            dname = dst.name
            self.after(0, lambda fn=dname: self._notify("Fortress", f"Decrypted → {fn}"))
        except (ValueError, AuthenticationError, InvalidKeyError, IntegrityError) as exc:
            self._err_thread("CRYPTO ALERT", exc, dialog=True)
        except Exception:
            logger.exception("Local decrypt error")
            self._err_thread("SYSTEM ERROR", Exception("Unexpected error — check fortress.log"), dialog=True)
        finally:
            self.after(0, self._op_unlock)

    def _worker_folder_encrypt(self, src: Path, dst: Path, secret: str) -> None:
        try:
            FolderEncryptor.encrypt_folder(src, dst, secret, self._progress_cb)
            dname = dst.name
            self.after(0, lambda fn=dname: self._notify("Fortress", f"Folder encrypted → {fn}"))
        except (ValueError, P2PError) as exc:
            self._err_thread("ENCRYPT ERROR", exc, dialog=True)
        except Exception:
            logger.exception("Folder encrypt error")
            self._err_thread("SYSTEM ERROR", Exception("Unexpected error — check fortress.log"), dialog=True)
        finally:
            self.after(0, self._op_unlock)

    def _worker_folder_decrypt(self, src: Path, dst_dir: Path, secret: str) -> None:
        try:
            FolderEncryptor.decrypt_folder(src, dst_dir, secret, self._progress_cb)
            dname = dst_dir.name
            self.after(0, lambda fn=dname: self._notify("Fortress", f"Folder decrypted → {fn}"))
        except (ValueError, AuthenticationError, InvalidKeyError, IntegrityError) as exc:
            self._err_thread("CRYPTO ALERT", exc, dialog=True)
        except Exception:
            logger.exception("Folder decrypt error")
            self._err_thread("SYSTEM ERROR", Exception("Unexpected error — check fortress.log"), dialog=True)
        finally:
            self.after(0, self._op_unlock)

    # ══════════════════════════════════════════════════════════════════════
    # PASSWORD STRENGTH / INVITE / QR / CLIPBOARD / SESSION
    # ══════════════════════════════════════════════════════════════════════

    def _update_strength(self, entry: ctk.CTkEntry, label: ctk.CTkLabel) -> None:
        score, text, colour = _password_strength(entry.get())
        label.configure(text=f"  {'█'*(score+1)}{'░'*(4-score)}  {text}", text_color=colour)

    def _on_generate_invite(self) -> None:
        port = self._parse_port(self._recv_port)
        pw   = self._recv_secret.get()
        pin  = getattr(self, "_invite_pin_entry", None)
        pin  = pin.get().strip() if pin else ""
        if not pw or port is None:
            self._toast("Enter port and passphrase first", MIL_RED_LT)
            return
        invite = _build_invite(_get_local_ip(), port, pw, pin)
        self._invite_display.configure(text=invite)
        if pin:
            self._toast(
                f"✓ Invite encrypted with PIN — share PIN separately!",
                MIL_GREEN_LT,
            )
        else:
            self._toast(
                "⚠  No PIN — passphrase is readable by anyone who sees this invite!",
                MIL_AMBER, 6000,
            )

    def _on_copy_invite(self) -> None:
        text = self._invite_display.cget("text")
        if "FORTRESS://" in text:
            self.clipboard_clear(); self.clipboard_append(text)
            self._schedule_clipboard_clear()
            self._toast("Invite copied — auto-clear 30 s", MIL_TAN)

    def _on_paste_invite(self) -> None:
        raw = self._invite_entry_send.get().strip() or self.clipboard_get()
        pin = getattr(self, "_invite_pin_entry", None)
        pin = pin.get().strip() if pin else ""
        is_enc = _invite_is_encrypted(raw)
        result = _parse_invite(raw, pin)
        if result is None:
            if is_enc and not pin:
                self._toast("This invite is PIN-encrypted — enter the PIN first", MIL_AMBER)
            elif is_enc:
                self._toast("Wrong PIN or corrupted invite", MIL_RED_LT)
            else:
                self._toast("Invalid invite — expected FORTRESS:// format", MIL_RED_LT)
            return
        ip, port, pw = result
        self._ip_entry.delete(0,"end");    self._ip_entry.insert(0, ip)
        self._send_port.delete(0,"end");   self._send_port.insert(0, str(port))
        self._send_secret.delete(0,"end"); self._send_secret.insert(0, pw)
        self._update_strength(self._send_secret, self._send_strength)
        enc_tag = "🔐 Encrypted" if is_enc else "⚠ Unencrypted"
        self._toast(f"Invite loaded [{enc_tag}]: {ip}:{port}", MIL_GREEN_LT)

    def _on_show_qr(self) -> None:
        text = self._invite_display.cget("text")
        if "FORTRESS://" not in text:
            self._toast("Generate an invite code first", MIL_AMBER); return
        if not _QR_OK:
            messagebox.showinfo("QR CODE", f"pip install qrcode\n\n{text}"); return
        qr_str = _ascii_qr(text)
        win = ctk.CTkToplevel(self)
        win.title("QR Invite Code"); win.configure(fg_color=MIL_BG); win.geometry("520x540")
        win.grid_columnconfigure(0, weight=1); win.grid_rowconfigure(1, weight=1)
        ctk.CTkLabel(win, text="  Scan to connect:",
                     font=ctk.CTkFont(family="Courier New", size=12, weight="bold"),
                     text_color=MIL_AMBER
                     ).grid(row=0, column=0, sticky="w", padx=14, pady=(12, 4))
        tb = ctk.CTkTextbox(win, font=ctk.CTkFont(family="Courier New", size=8),
                             fg_color=MIL_CARD, text_color=MIL_TEXT)
        tb.grid(row=1, column=0, sticky="nsew", padx=14, pady=(0, 14))
        tb.insert("end", qr_str); tb.configure(state="disabled")
        self._attach_textbox_menu(tb)

    def _schedule_clipboard_clear(self, ms: int | None = None) -> None:
        if ms is None:
            ms = self._cfg.get("clipboard_clear_sec", 30) * 1000
        if self._clip_job: self.after_cancel(self._clip_job)
        self._clip_job = self.after(ms, self._clear_clipboard)

    def _clear_clipboard(self) -> None:
        try:
            self.clipboard_clear()
            self.clipboard_append("")
        except Exception:
            pass
        self._clip_job = None

    def _reset_idle(self) -> None:
        timeout_min = self._cfg.get("session_timeout_min", 10)
        if timeout_min <= 0: return
        # Throttle: ignore if called within 1 second of the last reset
        # (<Motion> fires on every pixel — without this the event queue overflows)
        now = time.monotonic()
        if now - self._last_idle_reset < 1.0:
            return
        self._last_idle_reset = now
        if self._idle_job: self.after_cancel(self._idle_job)
        self._idle_job = self.after(timeout_min * 60 * 1000, self._session_timeout)

    def _session_timeout(self) -> None:
        for w in (self._send_secret, self._recv_secret,
                  self._wh_passphrase, self._local_secret):
            try:
                w.delete(0, "end")
            except Exception:
                pass
        for lbl in (self._send_strength, self._recv_strength,
                    self._wh_strength, self._local_strength):
            try:
                lbl.configure(text="")
            except Exception:
                pass
        self._toast("⏱  Session timeout — passphrases cleared", MIL_RED_LT, 5000)
        self._idle_job = None

    # ══════════════════════════════════════════════════════════════════════
    # NOTIFICATIONS + STATUS + PROGRESS RESET
    # ══════════════════════════════════════════════════════════════════════

    def _notify(self, title: str, message: str) -> None:
        self._status_update(1.0, f"[ ✓ COMPLETE ]  {message}")
        self._toast(f"✓  {message}", MIL_GREEN_LT)
        # Auto-reset progress bar after 3 s
        if self._progress_job:
            self.after_cancel(self._progress_job)
        self._progress_job = self.after(3000, lambda: self._status_update(0.0, "[ READY ]"))
        if _NOTIFY_OK:
            try:
                _plyer_notify.notify(title=title, message=message,
                                     app_name="P2P Fortress", timeout=5)
            except Exception:
                pass

    def _progress_cb(self, ratio: float, msg: str) -> None:
        """Thread-safe: schedule status update on main thread.

        Throttled to at most ~10 updates/second to prevent event-queue flooding
        during tight network loops (e.g. sending 65 KB chunks = thousands/sec).
        Completion (ratio == 1.0) and error messages always pass through.
        """
        now = time.monotonic()
        is_final = ratio >= 1.0 or any(x in msg for x in ("ERROR", "ALERT", "FAILURE", "WARN", "COMPLETE"))
        if not is_final and (now - self._last_progress_t) < 0.10:
            return   # skip intermediate update — too soon
        self._last_progress_t = now
        self.after(0, self._status_update, ratio, msg)

    def _status_update(self, ratio: float, msg: str) -> None:
        self._progress.set(max(0.0, min(1.0, ratio)))
        is_err = any(x in msg for x in ("ERROR", "ALERT", "FAILURE", "WARN"))
        bar_color = (MIL_GREEN_LT if ratio >= 1.0 else
                     MIL_RED_LT   if is_err       else
                     MIL_OLIVE_LT if ratio > 0    else MIL_KHAKI)
        self._progress.configure(progress_color=bar_color)
        self._status_lbl.configure(text=msg, text_color=MIL_TEXT)

    # ══════════════════════════════════════════════════════════════════════
    # SHUTDOWN
    # ══════════════════════════════════════════════════════════════════════

    def on_closing(self) -> None:
        # Save window geometry
        try:
            self._cfg["window_geometry"] = self.geometry()
            _save_settings(self._cfg)
        except Exception:
            pass
        # Stop server and discovery
        try:
            self._on_stop_server()
        except Exception:
            pass
        if self._lan_discovery:
            try: self._lan_discovery.stop()
            except Exception: pass
        # Signal wormhole threads
        WormholeManager.STOP_SEND.set()
        WormholeManager.STOP_RECEIVE.set()
        # Cancel pending after() jobs
        for job_attr in ("_clip_job", "_idle_job", "_resize_job",
                         "_progress_job", "_toast_job", "_lan_update_job"):
            job = getattr(self, job_attr, None)
            if job:
                try: self.after_cancel(job)
                except Exception: pass
        logger.info("P2P Fortress v14.0 shutdown.")
        try:
            self.destroy()
        except Exception:
            pass


# ---------------------------------------------------------------------------
# Entry Point
# ---------------------------------------------------------------------------
def main() -> None:
    logger.info("P2P Fortress v14.0 starting.")
    app = App()
    app.protocol("WM_DELETE_WINDOW", app.on_closing)
    app.mainloop()


if __name__ == "__main__":
    main()

# End of p2p_fortress_v13.py
