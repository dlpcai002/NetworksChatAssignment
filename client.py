import asyncio
import msgpack
import random  #generate request handles
import threading 
import time
from encryption import TransportSession, DH_Generate, build_initiation, parse_response, parse_response_extended, Mac
import nacl.public
import base64
import struct, os
import time

#server address and cleartext part
SERVER = ("csc4026z.link", 51825)
SERVER_WG = ("csc4026z.link", 51820)   # WireGuard encrypted port
SERVER_WGE = ("csc4026z.link", 51821)   # WireGuard extended encrypted port

class AsyncWireGuardProtocol(asyncio.DatagramProtocol):
    """
    Asynchronous UDP protocol handler that uses a queue to buffer incoming
    packets, allowing them to be awaited by the handshake or chat logic.
    """
    def __init__(self):
        self.queue = asyncio.Queue()
        self.transport = None

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, addr):
        self.queue.put_nowait((data, addr))

    def error_received(self, exc):
        print(f"UDP Error: {exc}")

class AsyncEncryptedSocket:
    """
    Asynchronous wrapper around the UDP transport and protocol.
    Automatically handles encryption/decryption via the TransportSession.
    """
    def __init__(self, session: TransportSession, transport, protocol, server_addr):
        self.session = session
        self.transport = transport
        self.protocol = protocol
        self.server_addr = server_addr

    async def sendto(self, data: bytes, addr=None):
        """Encrypt and send data."""
        if addr is None or addr == self.server_addr:
            target_addr = None
        else:
            target_addr = addr

        if self.session:
            encrypted_packet = self.session.encrypt_message(data)
            self.transport.sendto(encrypted_packet, target_addr)
        else:
            self.transport.sendto(data, target_addr)

    async def recvfrom(self):
        """Receive and decrypt data."""
        raw, addr = await self.protocol.queue.get()
        if self.session:
            try:
                plaintext = self.session.decrypt_message(raw)
                return plaintext, addr
            except Exception as e:
                print(f"Decryption error: {e}")
                return b"", addr
        return raw, addr

    def close(self):
        if self.transport:
            self.transport.close()

async def make_encrypted_socket():
    # Read client's long-term private key from user
    print('Enter client private key (base64): ')
    client_static_priv = base64.b64decode(input())
    # Generate matching public key from private key
    client_static_pub  = bytes(nacl.public.PrivateKey(client_static_priv).public_key)
    # Read server's public key
    print('Enter server public key (base64): ')
    server_static_pub  = base64.b64decode(input())

    # Generate temporary ephemeral DH keypair for handshake
    client_eph_priv, client_eph_pub = DH_Generate()

    # Random identifier for this client session
    sender_index = struct.unpack('<I', os.urandom(4))[0]

    # Create asynchronous UDP endpoint
    loop = asyncio.get_running_loop()
    transport, protocol = await loop.create_datagram_endpoint(
        lambda: AsyncWireGuardProtocol(),
        remote_addr=SERVER_WG
    )

    # ---------------- Handshake Phase ----------------
    
    # Build WireGuard-style initiation packet
    packet, ck, h = build_initiation(
        sender_index, client_static_priv, client_static_pub,
        server_static_pub, client_eph_priv, client_eph_pub, b'\x00' * 16
    )

    # Send handshake initiation to server
    transport.sendto(packet)

    # Receive handshake response from server (with 5.0s timeout simulation)
    try:
        response, _ = await asyncio.wait_for(protocol.queue.get(), timeout=5.0)
    except asyncio.TimeoutError:
        print("Handshake timed out.")
        transport.close()
        return None

    # Derive encryption/decryption session keys
    send_key, recv_key, receiver_index = parse_response(
        response, client_eph_priv, client_static_priv,
        server_static_pub, b'\x00' * 32, ck, h)

    # Create encrypted transport session
    session = TransportSession(send_key, recv_key, sender_index, receiver_index)

    print("✓ WireGuard handshake complete")

    # Return async encrypted socket wrapper
    return AsyncEncryptedSocket(session, transport, protocol, SERVER_WG)

async def make_encrypted_socket_extended():
    # Read client's long-term private key from user
    print('Enter client private key (base64): ')
    client_static_priv = base64.b64decode(input())
    # Generate matching public key from private key
    client_static_pub  = bytes(nacl.public.PrivateKey(client_static_priv).public_key)
    # Read server's public key
    print('Enter server public key (base64): ')
    server_static_pub  = base64.b64decode(input())

    # Generate temporary ephemeral DH keypair for handshake
    client_eph_priv, client_eph_pub = DH_Generate()

    # Random identifier for this client session
    sender_index = struct.unpack('<I', os.urandom(4))[0]

    # Create asynchronous UDP endpoint
    loop = asyncio.get_running_loop()
    transport, protocol = await loop.create_datagram_endpoint(
        lambda: AsyncWireGuardProtocol(),
        remote_addr=SERVER_WGE
    )

    # ---------------- Handshake Phase ----------------
    
    # Build WireGuard-style initiation packet
    packet, ck, h = build_initiation(
        sender_index, client_static_priv, client_static_pub,
        server_static_pub, client_eph_priv, client_eph_pub, b'\x00' * 16
    )

    # Send handshake initiation to server
    transport.sendto(packet)

    # Receive handshake response from server
    try:
        response, _ = await asyncio.wait_for(protocol.queue.get(), timeout=5.0)
    except asyncio.TimeoutError:
        print("Handshake initiation timed out.")
        transport.close()
        return None

    cookie, receiver_index = parse_response_extended(response, server_static_pub)

    mac2 = Mac(cookie, packet[:-16])

    # Replace the mac2 in the original initiation packet with the new calculated mac2
    final_packet = packet[:-16] + mac2
    print("✓ first handshake complete, calculated mac2")

    # Use the decrypted cookie to send a new type = 0x1 handshake message, including a calculated mac2
    # Build + send initiation 2
    transport.sendto(final_packet)
    print("✓ cookie applied, resent initiation with valid mac2")

    # Receive + parse response
    try:
        response, _ = await asyncio.wait_for(protocol.queue.get(), timeout=5.0)
    except asyncio.TimeoutError:
        print("Handshake response timed out.")
        transport.close()
        return None
        
    print(f"← response received ({len(response)} bytes)")

    send_key, recv_key, receiver_index = parse_response(
        response, client_eph_priv, client_static_priv,
        server_static_pub, b'\x00' * 32, ck, h
    )
    print("✓ second handshake complete, transport keys derived")

    # Create encrypted transport session
    session = TransportSession(send_key, recv_key, sender_index, receiver_index)

    print("✓ WireGuard handshake complete")

    # Return async encrypted socket wrapper
    return AsyncEncryptedSocket(session, transport, protocol, SERVER_WG)

#connection to chat server
async def connect(sock):
    
    #connect request
    request = {
    "request_type": 1,
    "request_handle": random.randrange(0, 2**32) & 0xFFFFFFFF # u32
    }
    
    #Encode, send request
    await sock.sendto(msgpack.packb(request))
    

#send ping, keep alive
async def ping(sock, session):
    
    #ping request
    request = {
        "request_type": 3,
        "session": int(session) & 0xFFFFFFFF, # u32
        "request_handle": random.randrange(0, 2**32) & 0xFFFFFFFF # u32
    }
    
    #encode, send ping
    await sock.sendto(msgpack.packb(request))
    

async def set_username(sock, session, username):
    # Rule: Usernames CANNOT contain the character ':'
    if ":" in username:
        print("Error: Username cannot contain ':'")
        return

    # Rule: Cleartext users MUST begin their usernames with 'clear-'
    # If sock.session is None, it's a cleartext socket.
    if sock.session is None and not username.startswith("clear-"):
        username = "clear-" + username
        print(f"Note: Prepending 'clear-' to username. New username: {username}")

    request = {
        "request_type": 13,                       
        "session": session,                   #current session ID
        "request_handle": random.randrange(0, 2**32),
        "username": username[:20]             # Max length 20
    }
    
    await sock.sendto(msgpack.packb(request))

async def list_users(sock, session, channel=None, offset=None):
    request = {
        "request_type": 14,
        "session": session,
        "request_handle": random.randrange(0, 2**32)
    }
    if channel:
        request["channel"] = channel[:20]
    if offset is not None:
        request["offset"] = int(offset) & 0xFFFF
    
    await sock.sendto(msgpack.packb(request))
    


async def list_channels(sock, session, offset=None):
    request = {
        "request_type": 5,
        "session": session,
        "request_handle": random.randrange(0, 2**32)
    }
    if offset is not None:
        request["offset"] = int(offset) & 0xFFFF
    
    await sock.sendto(msgpack.packb(request))
    

import re

def is_valid_channel_name(name):
    # Name can only contain letters, numbers, underscores, and dashes
    return bool(re.match(r'^[A-Za-z0-9_-]+$', name))

async def create_channel(sock, session, channel_name, description=""):
    if not is_valid_channel_name(channel_name):
        print(f"Error: Invalid channel name '{channel_name}'. Use only letters, numbers, underscores, and dashes.")
        return

    request = {
        "request_type": 4,
        "session": session,
        "request_handle": random.randrange(0, 2**32),
        "channel": channel_name[:20],
        "description": description[:100]
    }
    await sock.sendto(msgpack.packb(request))
    

async def join_channel(sock, session, channel_name):
    request = {
        "request_type": 7,
        "session": session,
        "request_handle": random.randrange(0, 2**32),
        "channel": channel_name[:20]
    }
    
    await sock.sendto(msgpack.packb(request))
   

async def get_channel_info(sock, session, channel_name):
    request = {
        "request_type": 6,
        "session": session,
        "request_handle": random.randrange(0, 2**32),
        "channel": channel_name[:20]
    }
    await sock.sendto(msgpack.packb(request))
   

async def leave_channel(sock, session, channel_name):
    request = {
        "request_type": 8,
        "session": session,
        "request_handle": random.randrange(0, 2**32),
        "channel": channel_name[:20]
    }
    await sock.sendto(msgpack.packb(request))

async def whoami(sock, session):
    request = {
        "request_type": 11,
        "session": session,
        "request_handle": random.randrange(0, 2**32)
    }
    await sock.sendto(msgpack.packb(request))

async def whois(sock, session, target_username):
    request = {
        "request_type": 10,
        "session": int(session) & 0xFFFFFFFF,
        "request_handle": random.randrange(0, 2**32),
        "username": target_username
    }
    await sock.sendto(msgpack.packb(request))
   

async def send_message(sock, session, channel_name, message_text):
    request = {
        "request_type": 9, 
        "session": int(session) & 0xFFFFFFFF, 
        "request_handle": random.randrange(0, 2**32),
        "channel": channel_name,
        "message": message_text
        
    }
    
    await sock.sendto(msgpack.packb(request))
    
async def send_direct_message(sock, session, recipient_username, message_text):
    request = {
        "request_type": 12,
        "session": int(session) & 0xFFFFFFFF,
        "request_handle": random.randrange(0, 2**32),
        "to_username": recipient_username,
        "message": message_text
    }
    await sock.sendto(msgpack.packb(request))
    

async def disconnect(sock, session):
    request = {
        "request_type": 2,
        "session": int(session) & 0xFFFFFFFF, 
        "request_handle": random.randrange(0, 2**32) & 0xFFFFFFFF
    }
    
    await sock.sendto(msgpack.packb(request))

# This interface defines all possible actions the app can take when it receives data from the server
class ResponseHandler:
    """Interface for handling server responses."""
    def handle_user_list(self, users, next_page): pass
    def handle_channel_list(self, channels, next_page): pass
    def handle_channel_info(self, channel, desc, members): pass
    def handle_channel_join(self, username, channel, desc): pass
    def handle_channel_leave(self, username, channel): pass
    def handle_username_change(self, old_name, new_name): pass
    def handle_whoami(self, username): pass
    def handle_whois(self, username, channels, transport, pubkey): pass
    def handle_dm(self, from_username, content): pass
    def handle_channel_message(self, sender, content, channel): pass
    def handle_error(self, error_msg): pass
    def handle_ok(self): pass
    def handle_disconnect(self, message): pass
    def handle_ping(self): pass
    def handle_broadcast(self, message): pass
    def handle_shutdown(self, message): pass

# This function looks at the 'response_type' number from the server and calls the correct function above
def process_response(data, handler: ResponseHandler):
    """Universal dispatcher for server responses."""
    if "response_type" not in data:
        return

    rtype = data["response_type"]
    # Map numeric server codes to the readable functions in the handler
    if rtype == 35: handler.handle_user_list(data.get("users", []), data.get("next_page", False))
    elif rtype == 26: handler.handle_channel_list(data.get("channels", []), data.get("next_page", False))
    elif rtype == 27: handler.handle_channel_info(data.get("channel", ""), data.get("description", ""), data.get("members", []))
    elif rtype == 28: handler.handle_channel_join(data.get("username", ""), data.get("channel", ""), data.get("description", ""))
    elif rtype == 29: handler.handle_channel_leave(data.get("username", ""), data.get("channel", ""))
    elif rtype == 34: handler.handle_username_change(data.get("old_username", ""), data.get("new_username", ""))
    elif rtype == 32: handler.handle_whoami(data.get("username", ""))
    elif rtype == 31: handler.handle_whois(data.get("username", ""), data.get("channels", []), data.get("transport", ""), data.get("wireguard_public_key", ""))
    elif rtype == 33: handler.handle_dm(data.get("from_username", ""), data.get("message", ""))
    elif rtype == 30: handler.handle_channel_message(data.get("username", ""), data.get("message", ""), data.get("channel", ""))
    elif rtype == 20: handler.handle_error(data.get("error", "Unknown error"))
    elif rtype == 21: handler.handle_ok()
    elif rtype == 23: handler.handle_disconnect(data.get("message", "Farewell!"))
    elif rtype == 24: handler.handle_ping()
    elif rtype == 36: handler.handle_broadcast(data.get("message", ""))
    elif rtype == 37: handler.handle_shutdown(data.get("message", ""))

async def receive_messages(sock, handler: ResponseHandler):
    """Background task to receive and dispatch messages."""
    while True:
        try:
            response, addr = await sock.recvfrom()
            if not response: continue
            data = msgpack.unpackb(response, raw=False)
            process_response(data, handler)
        except Exception as e:
            # Re-raise or handle if needed by the GUI
            raise e
            
        #print("\nIncoming messages:", data)


if __name__ == "__main__":
    print("This file is now a library for the GUI. Please run gui.py instead.")
   
    
    
