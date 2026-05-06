import socket
import msgpack
import random  #generate request handles

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
    
    #Wait for response
    response, addr = sock.recvfrom(4096)
    
    #Decode response
    data = msgpack.unpackb(response)
    
    #return session ID from server
    return data["session"]

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
    
    #wait server response
    response, addr = sock.recvfrom(4096)
    
    #return decoded response
    return msgpack.unpackb(response)

def set_username(sock, session, username):
    request = {
        "request_type": 13,                       
        "session": session,                   #current session ID
        "request_handle": random.randrange(0, 2**32),
        "username": username                  # must start with clear-
    }
    
    sock.sendto(msgpack.packb(request), SERVER)
    response, addr = sock.recvfrom(4096)
    return msgpack.unpackb(response)

def list_users(sock, session):
    request = {
        "request_type": 14,
        "session": session,
        "request_handle": random.randrange(0, 2**32)
    }
    
    sock.sendto(msgpack.packb(request), SERVER)
    response, addr = sock.recvfrom(4096)
    return msgpack.unpackb(response)


def list_channels(sock, session):
    request = {
        "request_type": 5,
        "session": session,
        "request_handle": random.randrange(0, 2**32)
    }
    
    sock.sendto(msgpack.packb(request), SERVER)
    response, addr = sock.recvfrom(4096)
    return msgpack.unpackb(response)

def create_channel(sock, session, channel_name):
    request = {
        "request_type": 4,
        "session": session,
        "request_handle": random.randrange(0, 2**32),
        "channel": channel_name
    }
    sock.sendto(msgpack.packb(request), SERVER)
    response, addr = sock.recvfrom(4096)
    return msgpack.unpackb(response)

def join_channel(sock, session, channel_name):
    request = {
        "request_type": 7,
        "session": session,
        "request_handle": random.randrange(0, 2**32),
        "channel": channel_name
    }
    
    sock.sendto(msgpack.packb(request), SERVER)
    response, addr = sock.recvfrom(4096)
    return msgpack.unpackb(response)

def send_message(sock, session, channel_name, message_text):
    request = {
        "request_type": 9, 
        "session": session, 
        "request_handle": random.randrange(0, 2**32),
        "channel": channel_name,
        "message": message_text
        
    }
    
    sock.sendto(msgpack.packb(request), SERVER)
    
    response, addr = sock.recvfrom(4096)
    return msgpack.unpackb(response)

def disconnect(sock, session):
    request = {
        "request_type": 2,
        "session": session, 
        "request_handle": random.randrange(0, 2**32)
    }
    
    sock.sendto(msgpack.packb(request), SERVER)
    response, addr = sock.recvfrom(4096)
    return msgpack.unpackb(response)


def main():
    
    channel_name = "diyal-test-1"
    
    #UDP socket creation
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    
    #connect, store session
    session = connect(sock)
    print("Connected. Session= ", session)
    
    #test ping
    response = ping(sock, session)
    print("Ping response: ", response)
    
    username_response = set_username(sock, session, "clear-diyal")
    print("Username response:", username_response)
    
    users_response = list_users(sock, session)
    print("Users response: ", users_response)
    
    channel_response = create_channel(sock, session, channel_name)
    print("Create channel response:", channel_response)
    
    channel_response = list_channels(sock, session)
    print("Channels response: ", channel_response)
    
    join_response = join_channel(sock, session, channel_name)
    print("Join channel response:", join_response) 
    
    message_response = send_message(
        sock,
        session,
        channel_name,
        "Hello from python client!!!"
    )
    
    print("Channel message response:", message_response)
    
    disconnect_response = disconnect(sock, session)
    print("Disconnect response:", disconnect_response)
    
    sock.close()
    print("Socket closed successfully")
    
if __name__ == "__main__":
    main()
   
    
    
