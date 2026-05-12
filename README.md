# WireGuard Chat Client

A UDP-based encrypted chat client implementing the WireGuard handshake protocol (Noise_IKpsk2) with ChaCha20-Poly1305 encryption and BLAKE2s MACs.

---

## Requirements

- Python 3.8+
- A valid client private key (base64-encoded Curve25519)
- The server's public key (base64-encoded Curve25519)

---

## Setup

```bash
# 1. Create and activate a virtual environment
python3 -m venv venv
source venv/bin/activate   # Windows: venv\Scripts\activate

# 2. Install dependencies
pip install -r requirements.txt

# 3. Run the client
python3 client.py
```

---

## Usage

When you run `client.py` you will first be asked to choose a connection mode:

```
Please enter the number for the type of chat you would like to use:
(1) Encrypted Chat
(2) Extended Encrypted Chat
(3) Cleartext Chat
```

| Option | Description |
|--------|-------------|
| **1 — Encrypted Chat** | Standard WireGuard handshake on port 51820. Performs a single Noise_IK initiation/response exchange to derive symmetric transport keys. |
| **2 — Extended Encrypted Chat** | Cookie-based handshake on port 51821. The server first replies with a type-3 cookie packet (rate-limiting / DoS protection). The client decrypts the cookie, computes `mac2`, and retransmits the initiation before completing the normal handshake. |
| **3 — Cleartext Chat** | Plain UDP with no encryption. Useful for debugging. |

For options **1** and **2** you will then be prompted for:

```
Enter client private key (base64):
<paste your base64 private key>

Enter server public key (base64):
<paste the server's base64 public key>
```

---

## In-Chat Commands

Once connected you will be placed into the `team-chat` channel automatically.

| Command | Description |
|---------|-------------|
| `<message>` | Send a message to the current channel |
| `/dm <username> <message>` | Send a direct message to another user |
| `Ctrl+C` | Exit the client |

---

## Server Details

| Port | Purpose |
|------|---------|
| 51820 | Standard WireGuard encrypted chat |
| 51821 | Extended (cookie-based) encrypted chat |
| 51825 | Cleartext chat |

All ports are on `csc4026z.link`.

---

## Project Structure

```
.
├── client.py        # Chat client — connection, messaging, UI
├── encryption.py    # WireGuard crypto — handshake, transport session
└── requirements.txt
```

### `encryption.py` — Key components

- **`build_initiation`** — constructs the type-1 Noise_IK handshake packet
- **`parse_response`** — processes the type-2 server response and derives transport keys
- **`parse_response_extended`** — decrypts the type-3 cookie reply (XChaCha20-Poly1305)
- **`TransportSession`** — encrypts/decrypts type-4 data packets using the derived keys

### `client.py` — Key components

- **`EncryptedSocket`** — drop-in UDP socket wrapper that transparently encrypts/decrypts
- **`make_encrypted_socket`** — performs the standard handshake and returns an `EncryptedSocket`
- **`make_encrypted_socket_extended`** — performs the cookie handshake and returns an `EncryptedSocket`