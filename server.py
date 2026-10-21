# server.py (Alice)
import socket
import time
from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import unpad, pad
from utils import is_prime, is_primitive_root, generate_private_key, \
    generate_public_key, compute_shared_secret, derive_aes_key

# get local machine name
host = '127.0.0.1'

port = 9999

# ------------------ PUBLIC DH PARAMETERS ------------------
# Alice and Bob publicly agree on modulus p and base g
P = 7919
G = 7      # primitive root modulo 7919

# Validate the parameters before using them
assert is_prime(P), "p must be prime"
assert is_primitive_root(G, P), "g must be a primitive root modulo p"

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

            # ------------------ DIFFIE-HELLMAN (ALICE) ------------------
            # Step 2: Alice chooses a secret integer a (never sent over the network)
            a = generate_private_key(P)
            # Alice computes her public value A = g^a mod p
            A = generate_public_key(G, a, P)
            # DEBUG: Print the secret a <------- Don't leave in prod
            print(f"SERVER: p={P}, g={G}, a(secret)={a}, A={A}")

            # Step 4: Send p, g and A to Bob in the clear (all public values)
            conn.sendall(f"{P},{G},{A}".encode())

            # Receive Bob's public value B
            B = int(conn.recv(1024).decode())
            print(f"SERVER: Received B={B}")

            # Step 5: Alice computes the shared secret s = B^a mod p
            s = compute_shared_secret(B, a, P)
            # Turn the shared secret into a 16-byte AES key
            key = derive_aes_key(s)
            # DEBUG: Print the shared secret and key <------- Don't leave in prod
            print(f"SERVER: Shared secret s={s}, AES key (hex)={key.hex()}")


            #------------------ ENCRYPTION ---------------------------
            # message variable
            message = time.ctime() + "\r\n"

            padded = pad(message.encode('ascii'), AES.block_size) # Pad the input data to match the block size of AES
            print("SERVER: Plaintext:", repr(message))
            print("SERVER: Padded (%d bytes, %d blocks): %s" % (len(padded), len(padded)//16, padded))

            cipher = AES.new(key, AES.MODE_ECB) # Create a AES cipher object with the DH-derived key using the mode ECB
            ciphered_message = cipher.encrypt(padded) # Encrypt the padded data


            #------------------ SEND DATA TO CLIENT ------------------
            # Send encrypted data to the client.
            print("SERVER: Sending ciphertext (%d bytes): %s" % (len(ciphered_message), ciphered_message.hex()))
            conn.sendall(ciphered_message)


            #------------------ RECEIVE DATA FROM CLIENT ------------------
            # decrypt receieved client data
            data = conn.recv(1024)
            print("SERVER: Received ciphertext (%d bytes): %s" % (len(data), data.hex()))
            decrypted = cipher.decrypt(data)
            print("SERVER: Decrypted, still padded:", decrypted)
            reply = unpad(decrypted, AES.block_size)
            print("SERVER: Received from client:", reply.decode('ascii'))
