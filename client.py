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

##NOTES: 
# 1. Channel info request
# 2. Leave Channel
# 3. User message request

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
        # Use None as the target address if it matches the default server_addr
        # to avoid ValueError in connected asyncio transports.
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
                # Return empty bytes or handle appropriately
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
        "description": description[:100]  # Ensure it doesn't exceed 100 characters
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
        "session": session,
        "request_handle": random.randrange(0, 2**32),
        "username": target_username[:20]
    }
    await sock.sendto(msgpack.packb(request))
   

async def send_message(sock, session, channel_name, message_text):
    request = {
        "request_type": 9, 
        "session": session, 
        "request_handle": random.randrange(0, 2**32),
        "channel": channel_name[:20],
        "message": message_text[:500]
        
    }
    
    await sock.sendto(msgpack.packb(request))
    
async def send_direct_message(sock, session, recipient_username, message_text):
    request = {
        "request_type": 12,
        "session": session,
        "request_handle": random.randrange(0, 2**32),
        "to_username": recipient_username[:20],
        "message": message_text[:500]
    }
    await sock.sendto(msgpack.packb(request))
    

async def disconnect(sock, session):
    request = {
        "request_type": 2,
        "session": int(session) & 0xFFFFFFFF, 
        "request_handle": random.randrange(0, 2**32) & 0xFFFFFFFF
    }
    
    await sock.sendto(msgpack.packb(request))

async def receive_messages(sock):
    print("Listening for incoming messages...")
    while True:
        try:
            response, addr = await sock.recvfrom()
            if not response:
                continue
            data = msgpack.unpackb(response)
                 
            
            if "response_type" in data:
                response_type = data["response_type"]
                if response_type == 35:  # User list response
                    users = data.get("users", [])
                    next_page = data.get("next_page", False)
                    print("\nCurrent users:", ", ".join(users))
                    if next_page:
                        print("(More users available on next page)")
                    print("> ", end="")
                elif response_type == 26:  # Channel list response
                    channels = data.get("channels", [])
                    next_page = data.get("next_page", False)
                    print("\nAvailable channels:", ", ".join(channels))
                    if next_page:
                        print("(More channels available on next page)")
                    print("> ", end="")
                elif response_type == 27:  # Channel info response
                    channel = data.get("channel", "Unknown")
                    desc = data.get("description", "")
                    members = data.get("members", [])
                    print(f"\n--- Channel Info: {channel} ---")
                    print(f"Description: {desc}")
                    print(f"Members: {', '.join(members)}")
                    print("> ", end="")
                elif response_type == 28:  # Channel join response
                    username = data.get("username", "Unknown")
                    channel = data.get("channel", "Unknown")
                    desc = data.get("description", "")
                    print(f"\n[INFO] {username} joined channel: {channel}")
                    if desc:
                        print(f"Channel Description: {desc}")
                    print("> ", end="")
                elif response_type == 29:  # Channel leave response
                    username = data.get("username", "Unknown")
                    channel = data.get("channel", "Unknown")
                    print(f"\n[INFO] {username} has left channel: {channel}")
                    print("> ", end="")
                elif response_type == 34:  # Set username response
                    old_name = data.get("old_username", "Unknown")
                    new_name = data.get("new_username", "Unknown")
                    print(f"\n[INFO] Username change: {old_name} is now known as {new_name}")
                    print("> ", end="")
                elif response_type == 32:  # WHOAMI response
                    username = data.get("username", "Unknown")
                    print(f"\n[INFO] You are currently: {username}")
                    print("> ", end="")
                elif response_type == 31:  # WHOIS response
                    username = data.get("username", "Unknown")
                    channels = data.get("channels", [])
                    transport = data.get("transport", "Unknown")
                    pubkey = data.get("wireguard_public_key", "")
                    print(f"\n--- User Info: {username} ---")
                    print(f"Transport: {transport}")
                    if pubkey:
                        print(f"Public Key: {pubkey}")
                    print(f"Channels: {', '.join(channels)}")
                    print("> ", end="")
                elif response_type == 33:
                    from_username = data.get("from_username", "Unknown")
                    content = data.get("message", "")
                    print(f"\n[DM] {from_username}: {content}")
                elif response_type == 30:
                    sender = data.get("username", "Unknown")
                    content = data.get("message", "")
                    channel = data.get("channel", "Unknown")
                    print(f"\n[{channel}] {sender}: {content}")
                elif response_type == 20:
                    if "error" in data:
                        print("\nError:", data["error"])
                    else:
                        print("\nMessage delivered")
                    print("> ", end="")
                elif response_type == 21:  # OK response
                    # Silently acknowledge OK for most requests
                    pass
                elif response_type == 23:  # DISCONNECT response
                    print(f"\n[INFO] Disconnected: {data.get('message', 'Farewell!')}")
                    print("> ", end="")
                elif response_type == 24:  # PING response
                    # Silently acknowledge PING
                    pass
                elif response_type == 36:  # SERVER_MESSAGE (Broadcast)
                    print(f"\n[BROADCAST] {data.get('message', '')}")
                    print("> ", end="")
                elif response_type == 37:  # SERVER_SHUTDOWN
                    print(f"\n[SHUTDOWN] Server is going down: {data.get('message', '')}")
                    # Requirement: Destroy session state
                    if hasattr(sock, 'session'):
                        sock.session = None
                    print("> ", end="")
            
        except Exception as e:
            print(f"Error in receiver: {e}")
            break
            
        #print("\nIncoming messages:", data)


async def main():
    loop = asyncio.get_running_loop()
    #User chooses whether they would like to use the Cleartext, Encrypted or Extended Encrypted socket
    while(True):
        print('Please enter the number for the type of chat you would like to use:\n(1) Encrypted Chat' \
        '\n(2) Extended Encrypted Chat\n(3) Cleartext Chat')
        # Use run_in_executor for blocking input
        choice = await loop.run_in_executor(None, input)
        if(choice == '1'):
            #UDP socket creation for Encrypted Chat
            print('Starting Encrypted Chat...')
            sock = await make_encrypted_socket()
            if not sock: return
            break
        elif(choice == '2'):
            #UDP socket creation for Extended Encrypted Chat
            print('Starting Extended Encrypted Chat...')
            sock = await make_encrypted_socket_extended()
            if not sock: return
            break
        elif(choice == '3'):
            #UDP socket creation for Cleartext Chat
            print('Starting Cleartext Chat...')
            transport, protocol = await loop.create_datagram_endpoint(
                lambda: AsyncWireGuardProtocol(),
                remote_addr=SERVER
            )
            sock = AsyncEncryptedSocket(None, transport, protocol, SERVER)
            break
        else:
            print('ERROR - Please enter a valid number for your choice: 1, 2 or 3')
            await asyncio.sleep(2.0)


    #connect, store session
    await connect(sock)
    reponse, addr = await sock.recvfrom()
    data = msgpack.unpackb(reponse)
    session = data.get("session")
    welcome_msg = data.get("message", "")
    server_username = data.get("username", "Unknown")
    
    print(f"Connected! Session={session}")
    if welcome_msg:
        print(f"Server: {welcome_msg}")
    print(f"Assigned username: {server_username}")
    
    # Start background tasks early so we can see updates
    receiver_task = asyncio.create_task(receive_messages(sock))
    
    active_channel = None
    
    print("Commands: Type your message and hit Enter. (Ctrl+C to exit)")
    
    async def keep_alive():
        try:
            while True:
                await ping(sock, session)
                await asyncio.sleep(30)
        except asyncio.CancelledError:
            pass
            
    keep_alive_task = asyncio.create_task(keep_alive())
    
    #print("CHAT ACTIVE. Use '/dm username message' to send direct messages or just message in channel")
    
    try:
        while True:
            # Use run_in_executor for blocking input
            prompt = f"[{active_channel}] > " if active_channel else "> "
            message_text = await loop.run_in_executor(None, lambda: input(prompt))
            
            if not message_text:
                continue

            # Normalize input for command checking
            trimmed_text = message_text.strip()
            parts = trimmed_text.split(" ", 1)
            cmd = parts[0].lower()
            args = parts[1] if len(parts) > 1 else ""

            if cmd == "/exit":
                break
            
            if cmd == "/dm":
                if not args or " " not in args:
                    print("Usage: /dm username message")
                    continue
                recipient_username, dm_message = args.split(" ", 1)
                await send_direct_message(sock, session, recipient_username, dm_message)
            elif cmd == "/create":
                if not args:
                    print("Usage: /create channel_name [description]")
                    continue
                create_parts = args.split(" ", 1)
                new_chan = create_parts[0]
                new_desc = create_parts[1] if len(create_parts) > 1 else ""
                await create_channel(sock, session, new_chan, new_desc)
                active_channel = new_chan
            elif cmd == "/join":
                if not args:
                    print("Usage: /join channel_name")
                    continue
                target_channel = args
                await join_channel(sock, session, target_channel)
                active_channel = target_channel
            elif cmd == "/switch":
                if not args:
                    active_channel = None
                    print("Active channel cleared. Use /join or /switch <channel> to set a new one.")
                else:
                    active_channel = args
                    print(f"Switched active channel to: {active_channel}")
            elif cmd == "/info":
                if not args:
                    print("Usage: /info channel_name")
                    continue
                await get_channel_info(sock, session, args)
            elif cmd == "/leave":
                if not args:
                    print("Usage: /leave channel_name")
                    continue
                target_channel = args
                await leave_channel(sock, session, target_channel)
                if active_channel == target_channel:
                    active_channel = None
                    print("Active channel cleared.")
            elif cmd == "/whoami":
                await whoami(sock, session)
            elif cmd == "/whois":
                if not args:
                    print("Usage: /whois username")
                    continue
                await whois(sock, session, args)
            elif cmd == "/users":
                channel = None
                offset = None
                user_parts = args.split(" ") if args else []
                if len(user_parts) > 0 and user_parts[0]:
                    channel = user_parts[0]
                if len(user_parts) > 1:
                    try:
                        offset = int(user_parts[1])
                    except ValueError:
                        print("Offset must be an integer")
                        continue
                await list_users(sock, session, channel, offset)
            elif cmd == "/channels":
                offset = None
                if args:
                    try:
                        offset = int(args)
                    except ValueError:
                        print("Offset must be an integer")
                        continue
                await list_channels(sock, session, offset)
            elif cmd == "/set_username":
                if not args:
                    print("Usage: /set_username new_username")
                    continue
                await set_username(sock, session, args)
            elif message_text.startswith("/"):
                print(f"Unknown command: {cmd}")
            else:
                if active_channel:
                    await send_message(sock, session, active_channel, message_text)
                else:
                    print("Error: No active channel. Use /join <channel> or /switch <channel> first.")
                
    except (KeyboardInterrupt, asyncio.CancelledError, EOFError):
        print("\nExiting...")
    finally:
        keep_alive_task.cancel()
        receiver_task.cancel()
        sock.close()
        print("Goodbye!")
    
if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
   
    
    
