# client.py (Bob)
import socket
from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import unpad, pad
from utils import is_prime, is_primitive_root, generate_private_key, \
    generate_public_key, compute_shared_secret, derive_aes_key

# get local machine name
#host = socket.gethostname()
host = '127.0.0.1'

port = 9999

# Socket is named sock so it doesn't clash with the shared secret s
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
    # connection to hostname on the port.
    sock.connect((host, port))

    # ------------------ DIFFIE-HELLMAN (BOB) ------------------
    # Receive the public values p, g and Alice's A
    p, g, A = map(int, sock.recv(1024).decode().split(","))
    print(f"CLIENT: Received p={p}, g={g}, A={A}")

    # Check p is prime and g is a primitive root
    if not is_prime(p) or not is_primitive_root(g, p):
        raise ValueError("Invalid DH parameters received from server")

    # Bob chooses a secret integer b (never sent over the network)
    b = generate_private_key(p)
    # Bob computes his public value B = g^b mod p
    B = generate_public_key(g, b, p)

    # Step 4: Send B to Alice in the clear (public value)
    sock.sendall(str(B).encode())
    # DEBUG: Print the secret b <------- Don't leave in prod
    print(f"CLIENT: b(secret)={b}, sent B={B}")

    # Step 6: Bob computes the shared secret s = A^b mod p
    shared = compute_shared_secret(A, b, p)
    # Turn the shared secret into a 16-byte AES key (same as Alice's)
    key = derive_aes_key(shared)
    # DEBUG: Print the shared secret and key <------- Don't leave in prod
    print(f"CLIENT: Shared secret s={shared}, AES key (hex)={key.hex()}")

    # Setup cipher with the DH-derived key
    cipher = AES.new(key, AES.MODE_ECB)


    # ------------------ RECEIVE DATA ------------------
    # Receive encrypted data from the server and decrypt it.
    tm = sock.recv(1024)
    print("CLIENT: Received ciphertext (%d bytes): %s" % (len(tm), tm.hex()))
    decrypted = cipher.decrypt(tm)
    # DEBUG: Print the decrypted message with padding <------- Don't leave in prod
    print("CLIENT: Decrypted, still padded:", decrypted)
    # Get the original message without padding
    original_time = unpad(decrypted, AES.block_size)
    # Print what time the server sent us, after decrypting and unpadding the message
    print("The time got from the server is %s" % original_time.decode('ascii'))


    # ------------------ SEND DATA ------------------
    # Send encrypted data to the server.
    # Message to be sent
    reply = b"Hello server, message received"
    # Encrypt the reply message and send it to the server
    reply_ct = cipher.encrypt(pad(reply, AES.block_size))
    # DEBUG: Print the original message to compare
    print("CLIENT: Reply plaintext:", reply)
    # DEBUG: Print the encrypted message <------- Don't leave in prod
    print("CLIENT: Sending encrypted reply (%d bytes): %s" % (len(reply_ct), reply_ct.hex()))
    sock.sendall(reply_ct)
