import struct
import time
import os
import hashlib
import hmac as hmac_lib
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
import nacl.bindings
import nacl.public
import base64
import socket
import msgpack, random

#Crypto Handshake Implementation
CONSTRUCTION = b'Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s'
IDENTIFIER   = b'WireGuard v1 zx2c4 Jason@zx2c4.com'
LABEL_MAC1   = b'mac1----'

class TransportSession:
    """
    Manages a WireGuard transport session after a completed handshake.
    Wraps the existing msgpack/UDP chat logic.
    """

    def __init__(self, send_key: bytes, recv_key: bytes,
                 sender_index: int, receiver_index: int):
        self.send_key       = send_key
        self.recv_key       = recv_key
        self.sender_index   = sender_index
        self.receiver_index = receiver_index
        self.send_counter   = 0
        self.recv_counter   = -1   # last accepted counter

    def encrypt_message(self, plaintext: bytes) -> bytes:
        """
        Wrap a plaintext message in a WireGuard transport packet.
        Section 5.4.6 — type 4 message.
        """
        counter = self.send_counter

        # AEAD with empty auth data — the counter is authenticated via the nonce
        ciphertext = AEAD_encrypt(self.send_key, counter, plaintext, b'')

        self.send_counter += 1

        return (
            b'\x04'                               +  # message type
            b'\x00\x00\x00'                       +  # reserved
            struct.pack('<I', self.receiver_index) +  # who this is for
            struct.pack('<Q', counter)             +  # 8-byte counter
            ciphertext                                # encrypted payload + 16-byte tag
        )

    def decrypt_message(self, packet: bytes) -> bytes:
        """
        Unwrap a received WireGuard transport packet.
        """
        msg_type = packet[0]
        assert msg_type == 4, f"Expected data packet (type 4), got {msg_type}"

        counter    = struct.unpack('<Q', packet[8:16])[0]
        ciphertext = packet[16:]

        # Basic replay protection — reject anything at or behind the last counter
        # (A real implementation uses a 64-bit sliding window bitmap)
        assert counter > self.recv_counter, \
            f"Replayed or out-of-order packet: counter {counter} ≤ {self.recv_counter}"
        self.recv_counter = counter

        return AEAD_decrypt(self.recv_key, counter, ciphertext, b'')


# --- Core Crypto Primitives ---
def Hash(data: bytes) -> bytes:
    """BLAKE2s fingerprint of data (32 bytes output)"""
    return hashlib.blake2s(data).digest()

def MixHash(a: bytes, b: bytes) -> bytes:
    """Fingerprint of two concatenated byte strings"""
    return Hash(a + b)

def Mac(key: bytes, data: bytes) -> bytes:
    """
    Keyed MAC using BLAKE2s.
    The key is truncated/used as the 'person' parameter.
    Used for mac1/mac2 in the packet.
    """
    return hashlib.blake2s(data, key=key, digest_size=16).digest()

def Hmac(key: bytes, data: bytes) -> bytes:
    """Standard HMAC-BLAKE2s — used inside KDF"""
    return hmac_lib.new(key, data, digestmod=lambda: hashlib.blake2s()).digest()

def Kdf1(key: bytes, input: bytes) -> bytes:
    """Derive 1 key from a chaining key + input"""
    temp = Hmac(key, input)
    out1 = Hmac(temp, b'\x01')
    return out1

def Kdf2(key: bytes, input: bytes) -> tuple:
    """Derive 2 keys from a chaining key + input"""
    temp = Hmac(key, input)
    out1 = Hmac(temp, b'\x01')
    out2 = Hmac(temp, out1 + b'\x02')
    return out1, out2

def Kdf3(key: bytes, input: bytes) -> tuple:
    """Derive 3 keys from a chaining key + input"""
    temp = Hmac(key, input)
    out1 = Hmac(temp, b'\x01')
    out2 = Hmac(temp, out1 + b'\x02')
    out3 = Hmac(temp, out2 + b'\x03')
    return out1, out2, out3

def AEAD_encrypt(key: bytes, counter: int, plaintext: bytes, authtext: bytes) -> bytes:
    """
    ChaCha20-Poly1305 encryption.
    counter is an integer — encode it as 12 bytes (4 zero bytes + 8-byte little-endian)
    """
    nonce = b'\x00' * 4 + struct.pack('<Q', counter)
    return ChaCha20Poly1305(key).encrypt(nonce, plaintext, authtext)

def AEAD_decrypt(key: bytes, counter: int, ciphertext: bytes, authtext: bytes) -> bytes:
    """ChaCha20-Poly1305 decryption"""
    nonce = b'\x00' * 4 + struct.pack('<Q', counter)
    return ChaCha20Poly1305(key).decrypt(nonce, ciphertext, authtext)

def Timestamp() -> bytes:
    """
    TAI64N timestamp — 12 bytes.
    TAI64: seconds since 1970 + 2^62 offset, big-endian 8 bytes
    N: nanoseconds, big-endian 4 bytes
    """
    now = time.time()
    tai_offset = (1 << 62) + 10
    seconds = int(now) + tai_offset
    microseconds = int((now % 1) * 1e6)
    return struct.pack('>QI', seconds, microseconds)

def DH(private_key: bytes, public_key: bytes) -> bytes:
    """Diffie-Hellman on Curve25519 — the magic that creates a shared secret"""
    return nacl.bindings.crypto_scalarmult(n=private_key, p=public_key)

def DH_Generate():
    """Generate a fresh Curve25519 keypair"""
    private_key = nacl.public.PrivateKey.generate()
    priv_bytes = bytes(private_key)
    pub_bytes = bytes(private_key.public_key)
    return priv_bytes, pub_bytes


def build_initiation(
    sender_index: int,          # a random 32-bit integer you pick to identify this session
    client_static_priv: bytes,  # long-term private key
    client_static_pub:  bytes,  # long-term public key
    server_static_pub:  bytes,  # the server's long-term public key (pre-shared, from config)
    client_ephemeral_priv: bytes,  # fresh random key just for this handshake
    client_ephemeral_pub:  bytes,
) -> bytes:
    """
    Build the WireGuard handshake initiation packet.
    """

    # Start the shared handshake state using known constants and the server's
    # public key so both client and server build the same transcript
    chain_key = Hash(CONSTRUCTION)
    hash = MixHash(chain_key, IDENTIFIER)
    hash = MixHash(hash, server_static_pub)

    # Add the client's temporary public key into the handshake state
    chain_key = Kdf1(chain_key, client_ephemeral_pub)
    hash = MixHash(hash, client_ephemeral_pub)

    # Perform the first Diffie-Hellman exchange using the ephemeral private key
    # and the server's static public key to derive encryption material
    dh1 = DH(client_ephemeral_priv, server_static_pub)
    chain_key, aead_key = Kdf2(chain_key, dh1)

    # Encrypt the client's static public key to hide the client's identity from eavesdroppers
    encrypted_static = AEAD_encrypt(aead_key, 0, client_static_pub, hash)

    # Fold the ciphertext into the hash the server will do the same after decrypting
    hash = MixHash(hash, encrypted_static)

    # Perform a second Diffie-Hellman exchange to prove the client's identity
    dh2 = DH(client_static_priv, server_static_pub)
    chain_key, aead_key = Kdf2(chain_key, dh2)

    # Encrypt a timestamp to prevent replay attacks.
    timestamp = Timestamp()
    encrypted_timestamp = AEAD_encrypt(aead_key, 0, timestamp, hash)
    hash = MixHash(hash, encrypted_timestamp)   # fold into transcript

    # Generate a MAC over the packet so the server can cheaply verify the
    # handshake before performing expensive cryptographic operations.
    mac1_key = Hash(LABEL_MAC1 + server_static_pub)

    # Assemble the body (everything except the MACs)
    s_index      = struct.pack('<I', sender_index)

    body = (
        b'\x01'              +   # message type (1 byte)
        b'\x00\x00\x00'      +   # reserved (3 bytes)
        s_index              +   # sender index (4 bytes)
        client_ephemeral_pub +   # 32 bytes
        encrypted_static     +   # 48 bytes (32 key + 16 tag)
        encrypted_timestamp      # 28 bytes (12 timestamp + 16 tag)
    )

    mac1 = Mac(mac1_key, body)
    mac2 = b'\x00' * 16    # mac2 is only used with a cookie; zero for now

    return body + mac1 + mac2, chain_key, hash

def parse_response(
    packet: bytes,
    client_ephemeral_priv: bytes,
    client_static_priv:    bytes,
    server_static_pub:     bytes,
    preshared_key:         bytes,   # 32 zero bytes if not using PSK
    chain_key: bytes,   # the chain_key state at the END of build_initiation
    hash:  bytes,   # the hash state at the END of build_initiation
) -> tuple:
    """
    Parse a WireGuard handshake response packet.
    Returns (transport_key_send, transport_key_recv, receiver_index)
    """
    # Unpack message
    msg_type        = packet[0]
    receiver_index  = struct.unpack('<I', packet[4:8])[0]
    server_eph_pub  = packet[12:44]
    empty_encrypted = packet[44:60]

    assert msg_type == 2, f"Expected type 2, got {msg_type}"

    # chain_key = Kdf1(chain_key, E_R_pub)
    chain_key = Kdf1(chain_key, server_eph_pub)

    # hash = Hash(hash || E_R_pub)
    hash = MixHash(hash, server_eph_pub)

    # chain_key = Kdf1(chain_key, DH(E_I_priv, E_R_pub))  ← Kdf1
    dh3 = DH(client_ephemeral_priv, server_eph_pub)
    chain_key = Kdf1(chain_key, dh3)

    # chain_key = Kdf1(chain_key, DH(S_I_priv, E_R_pub))  ← Kdf1
    dh4 = DH(client_static_priv, server_eph_pub)
    chain_key = Kdf1(chain_key, dh4)

    # (chain_key, tau, key3) = Kdf3(chain_key, Q)  where Q = 0s (no PSK)
    chain_key, tau, key3 = Kdf3(chain_key, b'\x00' * 32)

    # hash = Hash(hash || tau)
    hash = MixHash(hash, tau)

    # decrypt empty payload — just verifies the handshake is valid
    plaintext = AEAD_decrypt(key3, 0, empty_encrypted, hash)
    assert plaintext == b'', f"Response verification failed: {plaintext!r}"

    # hash = Hash(hash || empty_encrypted)
    hash = MixHash(hash, empty_encrypted)

    # Derive TRANSPORT KEYS
    send_key, recv_key = Kdf2(chain_key, b'')

    return send_key, recv_key, receiver_index

def test_server_handshake(server_host, server_port, server_static_pub,
                          client_static_priv, client_static_pub):
    client_eph_priv, client_eph_pub = DH_Generate()
    sender_index = struct.unpack('<I', os.urandom(4))[0]

    # Build + send initiation
    packet, ck, h = build_initiation(
        sender_index, client_static_priv, client_static_pub,
        server_static_pub, client_eph_priv, client_eph_pub
    )

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(5.0)
    sock.sendto(packet, (server_host, server_port))
    print(f"→ initiation sent ({len(packet)} bytes)")

    # Receive + parse response
    response, _ = sock.recvfrom(65535)
    print(f"← response received ({len(response)} bytes)")

    send_key, recv_key, receiver_index = parse_response(
        response, client_eph_priv, client_static_priv,
        server_static_pub, b'\x00' * 32, ck, h
    )
    print("✓ handshake complete, transport keys derived")

    # Send one encrypted message
    session = TransportSession(send_key, recv_key, sender_index, receiver_index)
    request_handle = random.randint(0, 0xFFFFFFFF)
    payload = msgpack.packb({
        "request_type": 1,
        "request_handle": request_handle
    })
    sock.sendto(session.encrypt_message(payload), (server_host, server_port))
    print(f"→ sent encrypted: {payload}")

    reply, _ = sock.recvfrom(65535)
    print(f"← server replied: {session.decrypt_message(reply)}")
    sock.close()

def main():
    SERVER_HOST = "csc4026z.link"
    SERVER_PORT = 51820

    print('Enter client private key (base64): ')
    client_static_priv = base64.b64decode(input())
    client_static_pub  = bytes(nacl.public.PrivateKey(client_static_priv).public_key)
    print('Enter server public key (base64): ')
    SERVER_STATIC_PUB  = base64.b64decode(input())
    test_server_handshake(SERVER_HOST, SERVER_PORT, SERVER_STATIC_PUB,
                          client_static_priv, client_static_pub)

if __name__ == "__main__":
    main()