import socket
import os
import base64
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from datetime import datetime
from dotenv import load_dotenv
import pytz

load_dotenv()

def decrypt_message(encrypted_data: bytes, key: bytes) -> str:
    nonce = encrypted_data[:12]
    ciphertext = encrypted_data[12:]
    aesgcm = AESGCM(key)
    plaintext = aesgcm.decrypt(nonce, ciphertext, None)
    return plaintext.decode('utf-8')

def generatePPK():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()

    # Save private key
    with open("private_key.pem", "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ))

    # Save public key
    with open("public_key.pem", "wb") as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ))

def main(generate_public_private_keys=False):
    IP = os.getenv("IP_ADDRESS")
    PORT = int(os.getenv("PORT"))
    timezone = pytz.timezone("Australia/Adelaide") #Change TZ based on user location?

    if generate_public_private_keys:
        generatePPK()

    with open("private_key.pem", "rb") as f:
        private_key = serialization.load_pem_private_key(f.read(), password=None)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as tcp_socket:
        tcp_socket.bind((IP, PORT))
        tcp_socket.listen(1)
        print(f"Socket bound to {PORT} and listening...")

        while True:
            print("Waiting for connection")
            conn, client = tcp_socket.accept()
            with conn:
                print(f"Connected to client IP: {client}")

                #Send PK to client
                with open("public_key.pem", "rb") as f:
                    public_key_bytes = f.read()
                conn.sendall(public_key_bytes)
                print("Sent public key to client")

                #Receive encrypted AES from client
                encrypted_aes_key = conn.recv(256)
                if not encrypted_aes_key:
                    print("No AES key received, closing connection.")
                    continue #check if correct

                #decrypt AES key
                aes_key = private_key.decrypt(encrypted_aes_key,
                                              padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                                           algorithm=hashes.SHA256(),
                                                           label=None,
                                                           )
                                              )
                print("Decrypted AES key successfully")

                while True:
                    data = conn.recv(1024)
                    if not data:
                        break

                    cur_time = timezone.localize(datetime.now())
                    try:
                        decrypted = decrypt_message(data, aes_key)
                        print(f"{cur_time}: {decrypted}")
                    except Exception as e:
                        print(f"{cur_time}: Decryption failed: {e}")
               
                    try:
                        conn.sendall("message received")
                    except Exception as e:
                        print(f"{cur_time}: acknowledgement failed: {e}")
            print("Connection has closed")

if __name__ == "__main__":
    import sys
    generate_keys = "--gen-keys" in sys.argv
    main(generate_public_private_keys=generate_keys)
