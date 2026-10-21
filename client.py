# client.py 
import socket 
from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import unpad, pad

# get local machine name 
#host = socket.gethostname()
host = '127.0.0.1'

port = 9999

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    # connection to hostname on the port.
    s.connect((host, port))

    # Wait for the server's encrypted data first, so key.txt and ct.txt are written before we read them
    tm = s.recv(1024)
    print("CLIENT: Received ciphertext (%d bytes): %s" % (len(tm), tm.hex()))

    # -------------------- ENCRYPTION ---------------------------
    # Key File Location
    input_file1 = r"C:\Users\domin\OneDrive\Desktop\Cyber Security Reports\Client_Server_Lab\key.txt"

    # Read the data from the file
    # Open The File
    file_in = open(input_file1, 'rb')
    # Read Key Bytes
    key = file_in.read(16)
    # Close File
    file_in.close()
    # DEBUG: Print the key in hex format <------- Don't leave in prod
    print("CLIENT: KEY read from key.txt (hex):", key.hex())
    # Input file for ciphertext message
    input_file2 = r"C:\Users\domin\OneDrive\Desktop\Cyber Security Reports\Client_Server_Lab\ct.txt"
    # Open the file to read bytes
    file_in = open(input_file2, 'rb')
    # Read the rest of the data
    ciphered_message = file_in.read()
    # Close File
    file_in.close()
    # DEBUG: Print the ciphertext in hex format matches message sent <------- Don't leave in prod
    print("CLIENT: ct.txt matches received ciphertext:",  ciphered_message == tm)
    # Setup cipher
    cipher = AES.new(key, AES.MODE_ECB)


    # ------------------ RECEIVE DATA ------------------
    # Receive encrypted data from the server and decrypt it.
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
    s.sendall(reply_ct)


s.close() 
