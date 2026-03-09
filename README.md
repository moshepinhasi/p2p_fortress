# p2p_fortress

Serverless P2P encrypted file transfer — AES-256-GCM, Argon2id, ECDH X25519, Tor support & certificate pinning. Built with Python & CustomTkinter.

## Quick Start

```bash
pip install customtkinter cryptography argon2-cffi
python p2p_fortress_v13.py
```

Optional extras:

```bash
pip install magic-wormhole pystray pillow plyer qrcode zeroconf
```

## Features

- **Double-AEAD encryption** — ChaCha20-Poly1305 + AES-256-GCM per transfer
- **Perfect Forward Secrecy** — ephemeral X25519 key exchange each session
- **Argon2id KDF** — 128 MB RAM / 4 iterations (OWASP 2023 max)
- **SAS fingerprint** — 4-word Short Authentication String for MITM detection
- **Burn After Reading** — secure auto-delete on receiver side
- **Multi-file send** — multiple files zipped, encrypted, and auto-extracted on receipt
- **Wormhole tab** — relay-assisted transfer via magic-wormhole
- **LAN Discovery** — automatic peer detection via UDP beacon
- **Transfer history** — SQLite log with speed & ETA stats
- **Local encryption** — encrypt/decrypt files & folders offline
- **Dark / Light theme** — toggle in the header bar
