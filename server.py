# server.py 
import socket 
import time
from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import unpad, pad
from Cryptodome.Random import get_random_bytes

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
             #ToDo: Make encryption to the existing server infrastructure. Use the AES-ECB mode to encrypt the message before sending it to the client. The key should be read from a file, and the message should be padded to match the block size of AES. After sending the encrypted message, wait for a response from the client, decrypt it, and print it to the console.
            key_location = r"C:\Users\domin\OneDrive\Desktop\Cyber Security Reports\Client_Server_Lab\key.txt"
            key = get_random_bytes(16)

            # message variable
            message = time.ctime() + "\r\n"


            file_out = open(key_location, "wb") # wb = write bytes
            file_out.write(key)
            file_out.close()
            print("SERVER: Key written to key.text (hex):", key.hex())

            padded = pad(message.encode('ascii'), AES.block_size) # Pad the input data to match the block size of AES
            print("SERVER: Plaintext:", repr(message))
            print("SERVER: Padded (%d bytes, %d blocks): %s" % (len(padded), len(padded)//16, padded))

            cipher = AES.new(key, AES.MODE_ECB) # Create a AES cipher object with the key using the mode ECB
            ciphered_message = cipher.encrypt(pad(message.encode('ascii'), AES.block_size)) # Pad the input data and then encrypt
            output_file = r"C:\Users\domin\OneDrive\Desktop\Cyber Security Reports\Client_Server_Lab\ct.txt" # Output file
            file_out = open(output_file, "wb") # Open file to write bytes
            file_out.write(ciphered_message) # Write the varying length cipher text to the file (this is the encrypted data)
            file_out.close()
            print("key (bytes):")
            print(key)
            key1 = int.from_bytes(key, "big") #converting key from bytes to int,
            #If byteorder is "big", the most significant byte is at the beginning of the byte array.
            #If byteorder is "little", the most significant byte is at the end of the byte array.
            print("key (int):")
            print(key1)
            print("ciphertext (bytes):")
            print(ciphered_message)

            #------------------ SEND DATA TO CLIENT ------------------
            # ToDo: Send encrypted data to the client.
            print("SERVER: Sending ciphertext (%d bytes): %s" % (len(ciphered_message), ciphered_message.hex()))
            conn.sendall(ciphered_message)


            #------------------ RECEIVE DATA FROM CLIENT ------------------
            # decrypt receieved client data

            data = conn.recv(1024)
            #print(f"Received from client: {cipher.decrypt(data)}")
            print("SERVER: Received ciphertext (%d bytes): %s" % (len(data), data.hex()))
            decrypted = cipher.decrypt(data)
            print("SERVER: Decrypted, still padded:", decrypted)
            reply = unpad(decrypted, AES.block_size)
            print("SERVER: Received from client:", reply.decode('ascii'))
