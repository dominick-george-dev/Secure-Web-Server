# server.py 
import socket 
import time

# get local machine name 
host = '127.0.0.1'

port = 9999

# AF_INET = IPv4, SOCK_STREAM = TCP
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
    # ------------------ SERVER SETUP ------------------
    # Let us restart the server straight away without "Address already in use"
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((host, port)) # claim the address and port
    server.listen(5) # queue up to 5 waiting connections
    print(f"Listening on {host}:{port}")


    # ------------------ SERVER LOOP ------------------
    while True:
        conn, addr = server.accept() # wait for a client; returns a NEW socket
        with conn: # closes conn automatically
            print(f"Got a connection from {addr}")

            #------------------ ENCRYPTION ---------------------------

            # message variable
            message = time.ctime() + "\r\n"
            #------------------ SEND DATA TO CLIENT ------------------
            # ToDo: Send encrypted data to the client.
            conn.sendall(message.encode('ascii'))


            #------------------ RECEIVE DATA FROM CLIENT ------------------
            # decrypt receieved client data

            data = conn.recv(1024)
            print(f"Received from client: {data.decode('ascii')}")
