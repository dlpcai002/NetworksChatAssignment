import socket
import msgpack
import random  #generate request handles
import threading 
import time

##NOTES: 
# 1. Channel info request
# 2. Leave Channel
# 3. User message request

#server address and cleartext part
SERVER = ("csc4026z.link", 51825)

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
    
    channel_name = "team-chat"
    
    #UDP socket creation
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    
    #connect, store session
    connect(sock)
    reponse, addr = sock.recvfrom(4096)
    data = msgpack.unpackb(reponse)
    session = data["session"]
    print("Connected. Session= ", session)
    
    #Set user and join channel
    my_username = "clear-caitlin"
    set_username(sock, session, my_username)
    time.sleep(0.3)
    sock.recvfrom(4096)  # Consume username set response
    
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
   
    
    
