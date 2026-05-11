import socket
import msgpack
import random  #generate request handles
import threading 
import time

from encryption import TransportSession, DH_Generate, build_initiation, parse_response, Hash
import nacl.public
import base64
import struct, os

##NOTES: 
# 1. Channel info request
# 2. Leave Channel
# 3. User message request

#server address and cleartext part
SERVER = ("csc4026z.link", 51825)
SERVER_WG = ("csc4026z.link", 51820)   # WireGuard port

class EncryptedSocket:
    """
    Wrapper around a normal UDP socket that automatically encrypts
    outgoing packets and decrypts incoming packets using the
    TransportSession object from encryption.py.

    This allows the rest of the chat client to use sendto() and
    recvfrom() normally without needing to manually handle
    encryption logic every time a message is sent or received.
    """
    def __init__(self, session: TransportSession, sock, server_addr):
        # Active encrypted transport session containing symmetric keys
        self.session = session
        # Underlying UDP socket used for network communication
        self.sock = sock
        # Address of the encrypted WireGuard-style server
        self.server_addr = server_addr

    def sendto(self, data: bytes, addr):
        """
        Encrypt outgoing plaintext data before sending it
        through the UDP socket.
        """
        # Encrypt plaintext message using session send key
        encrypted_packet = self.session.encrypt_message(data)
        # Send encrypted packet to server
        self.sock.sendto(encrypted_packet, self.server_addr)

    def recvfrom(self, bufsize):
        """
        Receive encrypted data from the UDP socket and decrypt it
        before returning it to the application.
        """
        # Receive encrypted packet from network
        raw, addr = self.sock.recvfrom(bufsize)
        # Decrypt packet using session receive key
        plaintext = self.session.decrypt_message(raw)
        # Return decrypted data in normal socket format
        return plaintext, addr

def make_encrypted_socket():
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

    # Create UDP socket used for encrypted communication
    raw_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    raw_sock.settimeout(5.0)

    # ---------------- Handshake Phase ----------------
    
    # Build WireGuard-style initiation packet
    packet, ck, h = build_initiation(
        sender_index, client_static_priv, client_static_pub,
        server_static_pub, client_eph_priv, client_eph_pub
    )

    # Send handshake initiation to server
    raw_sock.sendto(packet, SERVER_WG)

    # Receive handshake response from server
    response, _ = raw_sock.recvfrom(65535)

    # Derive encryption/decryption session keys
    send_key, recv_key, receiver_index = parse_response(
        response, client_eph_priv, client_static_priv,
        server_static_pub, b'\x00' * 32, ck, h)

    # Create encrypted transport session
    session = TransportSession(send_key, recv_key, sender_index, receiver_index)

    print("✓ WireGuard handshake complete")

    # Remove timeout after successful handshake
    raw_sock.settimeout(None)

    # Return encrypted socket wrapper
    return EncryptedSocket(session, raw_sock, SERVER_WG)

#connection to chat server
def connect(sock):
    
    #connect request
    request = {
    "request_type": 1,
    "request_handle": random.randrange(0, 2**32) #unique request ID
    }
    
    #Encode, send request
    sock.sendto(msgpack.packb(request), SERVER)
    

#send ping, keep alive
def ping(sock, session):
    
    #ping request
    request = {
        "request_type": 3,
        "session": session,
        "request_handle": random.randrange(0, 2**32)
    }
    
    #encode, send ping
    sock.sendto(msgpack.packb(request), SERVER)
    

def set_username(sock, session, username):
    request = {
        "request_type": 13,                       
        "session": session,                   #current session ID
        "request_handle": random.randrange(0, 2**32),
        "username": username                  # must start with clear-
    }
    
    sock.sendto(msgpack.packb(request), SERVER)

def list_users(sock, session):
    request = {
        "request_type": 14,
        "session": session,
        "request_handle": random.randrange(0, 2**32)
    }
    
    sock.sendto(msgpack.packb(request), SERVER)
    


def list_channels(sock, session):
    request = {
        "request_type": 5,
        "session": session,
        "request_handle": random.randrange(0, 2**32)
    }
    
    sock.sendto(msgpack.packb(request), SERVER)
    

def create_channel(sock, session, channel_name):
    request = {
        "request_type": 4,
        "session": session,
        "request_handle": random.randrange(0, 2**32),
        "channel": channel_name
    }
    sock.sendto(msgpack.packb(request), SERVER)
    

def join_channel(sock, session, channel_name):
    request = {
        "request_type": 7,
        "session": session,
        "request_handle": random.randrange(0, 2**32),
        "channel": channel_name
    }
    
    sock.sendto(msgpack.packb(request), SERVER)
   

def send_message(sock, session, channel_name, message_text):
    request = {
        "request_type": 9, 
        "session": session, 
        "request_handle": random.randrange(0, 2**32),
        "channel": channel_name,
        "message": message_text
        
    }
    
    sock.sendto(msgpack.packb(request), SERVER)
    
def send_direct_message(sock, session, recipient_username, message_text):
    request = {
        "request_type": 12,
        "session": session,
        "request_handle": random.randrange(0, 2**32),
        "to_username": recipient_username,
        "message": message_text
    }
    sock.sendto(msgpack.packb(request), SERVER)
    

def disconnect(sock, session):
    request = {
        "request_type": 2,
        "session": session, 
        "request_handle": random.randrange(0, 2**32)
    }
    
    sock.sendto(msgpack.packb(request), SERVER)

def receive_messages(sock):
    print("Listening for incoming messages...")
    while True:
        try:
            response, addr = sock.recvfrom(4096)
            data = msgpack.unpackb(response)
                 
            
            if "response_type" in data:
                response_type = data["response_type"]
                if response_type == 35:  # User list response
                    users = data.get("users", [])
                    print("\nCurrent users in channel:", ", ".join(users))
                    print("> ", end="")
                elif response_type == 26:  # Channel list response
                    channels = data.get("channels", [])
                    print("\nAvailable channels:", ", ".join(channels))
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
            
        except Exception as e:
            print(f"Error in receiver: {e}")
            break
            
        #print("\nIncoming messages:", data)


def main():
    #User chooses whether they would like to use the Cleartext socket or Encrypted socket
    print('Would you like use encrypted chat? (Respond with Y/N)')
    choice = input()

    if(choice == 'Y' or choice == 'y'):
        #UDP socket creation for Encrypted Chat
        print('Starting Encrypted Chat...')
        sock = make_encrypted_socket()
    elif(choice == 'N' or choice == 'n'):
        #UDP socket creation for Cleartext Chat
        print('Starting Cleartext Chat...')
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    channel_name = "team-chat"

    #connect, store session
    connect(sock)
    reponse, addr = sock.recvfrom(4096)
    data = msgpack.unpackb(reponse)
    session = data["session"]
    print("Connected. Session= ", session)
    
    #Set user and join channel
    my_username = "clear-david"
    set_username(sock, session, my_username)
    time.sleep(0.3)
    sock.recvfrom(4096)  # Consume username set response
    
    #NB!!!!!!!!!!: comment this out if someone else already created the channel
    create_channel(sock, session, channel_name)

    join_channel(sock, session, channel_name)
    time.sleep(0.3)
    join_resp, _ = sock.recvfrom(4096)  # Consume join channel response
    join_data = msgpack.unpackb(join_resp)
    print("Join response:", join_data) 
    
    list_users(sock, session)
    
    print("Registering with server...")
    time.sleep(1)
    
    print("Commands: Type your message and hit Enter. (Ctrl+C to exit)")
    
    def keep_alive():
        while True:
            ping(sock, session)
            time.sleep(30)  # Ping every 30 seconds
            
    receiver = threading.Thread(target=receive_messages, args=(sock,), daemon=True)
    receiver.start()      
    threading.Thread(target=keep_alive, daemon=True).start()
    
    print("CHAT ACTIVE. Use '/dm username message' to send direct messages or just message in channel")
    
    try:
        while True:
            message_text = input("> ")
            if message_text.startswith("/dm "):
                parts = message_text.split(" ", 2)
                if len(parts) < 3:
                    print("Usage: /dm username message")
                    continue
                recipient_username = parts[1]
                dm_message = parts[2]
                send_direct_message(sock, session, recipient_username, dm_message)
            else:
                send_message(sock, session, channel_name, message_text)
                
            if message_text.lower() == "/exit":
                break
            
    except KeyboardInterrupt:
        print("\nExiting...")
           
    #disconnect_response = disconnect(sock, session)
    #print("Disconnect response:", disconnect_response)
    
    #sock.close()
    #print("Socket closed successfully")
    
if __name__ == "__main__":
    main()
   
    
    
