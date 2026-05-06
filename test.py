import socket
import msgpack
import random
import time

# Server details
SERVER = ('csc4026z.link', 51825) 
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.settimeout(5.0) 

def send_request(request_dict):
    """Helper to pack and send a dictionary"""
    packet = msgpack.packb(request_dict)
    sock.sendto(packet, SERVER)

def get_response():
    """Helper to receive and unpack a dictionary"""
    try:
        data, addr = sock.recvfrom(4096)
        return msgpack.unpackb(data)
    except socket.timeout:
        print("!! Timeout: No response from server.")
        return None

def connect():
    print("--- Connecting ---")
    req = {
        'request_type': 1, 
        'request_handle': random.randint(0, 2**32 - 1)
    }
    send_request(req)
    res = get_response()
    if res and 'session' in res:
        print(f"Logged in! Session: {res['session']}")
        return res['session']
    return None

def ping(session_id):
    print("--- Sending Ping (Keep-Alive) ---")
    req = {
        'request_type': 3, 
        'session': session_id,
        'request_handle': random.randint(0, 2**32 - 1)
    }
    send_request(req)
    res = get_response()
    print("Ping Response:", res)

def disconnect(session_id):
    print("--- Disconnecting ---")
    req = {
        'request_type': 2,
        'session': session_id,
        'request_handle': random.randint(0, 2**32 - 1)
    }
    send_request(req)
    res = get_response()
    print("Disconnect Response:", res)


session = connect()

if session:
    # 1. Wait a moment to simulate activity
    time.sleep(2)
    
    # 2. Keep the session alive
    ping(session)
    
    # 3. Tell the group: "Now I'll log out properly"
    disconnect(session)
