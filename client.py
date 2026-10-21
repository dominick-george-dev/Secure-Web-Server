# client.py 
import socket 
from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import unpad

# get local machine name 
#host = socket.gethostname()
host = '127.0.0.1'

port = 9999

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    # ------------------ CONNECTION ------------------
    s.connect((host, port)) 

    # ------------------ RECEIVE DATA ------------------
    tm = s.recv(1024)
    print(f"Received from server: {tm.decode('ascii')}")

    # ------------------ SEND DATA ------------------
    # Send encrypted data to the server.
    message = "Hello, Server! This is the client."
    s.sendall(message.encode('ascii'))


s.close() 
