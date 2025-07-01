import os
import socket
import threading
import json
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

def decrypt_message(encrypted: bytes, key: bytes) -> str:
    nonce = encrypted[:12]
    ciphertext = encrypted[12:]
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext, None).decode('utf-8')

def receive_thread(conn, aes_key):
    try:
        while True:
            data = conn.recv(4096)
            if data:
                try:
                    msg = decrypt_message(data, aes_key)
                    print(f"\n📩 {msg}")
                except Exception as e:
                    print(f"[!] Decryption error: {e}")
    except:
        print("[!] Connection closed.")

def main():
    IP = os.getenv("IP_ADDRESS")
    PORT = int(os.getenv("PORT"))
    username = input("Enter your username: ")

    with socket.create_connection((IP, PORT)) as tcp_socket:
        print("Connected to server.")

        # RSA PK from server
        public_key_bytes = tcp_socket.recv(2048)
        public_key = serialization.load_pem_public_key(public_key_bytes)

        # Generate AES key and send it encrypted
        aes_key = os.urandom(32)
        encrypted_key = public_key.encrypt(aes_key, padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
        tcp_socket.sendall(encrypted_key)

        # Send username
        tcp_socket.sendall(username.encode('utf-8'))

        # Start thread to receive messages
        threading.Thread(target=receive_thread, args=(tcp_socket, aes_key), daemon=True).start()

        # Send messages
        while True:
            target = input("To (username): ").strip()
            msg = input("Message: ").strip()
            if msg.lower() == "/quit":
                break
            payload = json.dumps({
                "from": username,
                "to": target,
                "msg": msg
            })
            encrypted = encrypt_message(payload, aes_key)
            tcp_socket.sendall(encrypted)

if __name__ == "__main__":
    main()
