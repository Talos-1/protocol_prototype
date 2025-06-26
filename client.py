import os
import socket
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization, hashes
from dotenv import load_dotenv

load_dotenv()

def encrypt_message(message: str, key: bytes) -> bytes:
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    encrypted = aesgcm.encrypt(nonce, message.encode('utf-8'), None)
    return nonce + encrypted

def main():
    IP = os.getenv("IP_ADDRESS")
    PORT = os.getenv("PORT")

    #connect to the server
    with socket.create_connection((IP, PORT)) as tcp_socket:
        print("Connected to server.")
        
        #Receive RSA PK from server
        public_key_bytes = tcp_socket.recv(2048)
        public_key = serialization.load_pem_public_key(public_key_bytes)
        
        #Generate random AES key and encrypt using RSA PK
        aes_key = os.urandom(32)
        encrypted_key = public_key.encrypt(aes_key,
                                           padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                                        algorithm=hashes.SHA256(),
                                                        label=None,
                                                        )
                                           )
        tcp_socket.sendall(encrypted_key)
        print("Sent public AES key to server.")
        
        #Send encrypted messages
        try:
            while True:
                message = input("> ").strip()
                if message.lower() == "/quit":
                    print("Quiting...")
                    break
                if message:
                    encrypted = encrypt_message(message, aes_key)
                    tcp_socket.sendall(encrypted)
        finally:
            print("Closing socket")

if __name__ == "__main__":
    main()
    #TODO - Check when to use EC - Just use RSA (forward-secrecy = meh)
    #TODO - Write code to perform user authentication (log-in) - concensus. Use UN+PW (salt+hash)?
    #TODO - Add group messaging - Multicast equivalent of routing algorithm.
    #TODO - User authorisation - Header stored and attached from DB
    #TODO - Write code to connect clients together based on header details
    
    
    
    #Functionality:
        # generate public-private key using RSA-2048
        # encrypt messages using AES256-GCM.
        # has a header tag <T> that is used to check integrity (using Galois Field).