import socket
import threading
import json
import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from dotenv import load_dotenv

load_dotenv()

clients = {}  # {username: (conn, aes_key)}

def decrypt_message(encrypted_data: bytes, key: bytes) -> str:
    nonce = encrypted_data[:12]
    ciphertext = encrypted_data[12:]
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext, None).decode()

def encrypt_message(message: str, key: bytes) -> bytes:
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    return nonce + aesgcm.encrypt(nonce, message.encode(), None)

def broadcast_user_list():
    usernames = list(clients.keys())
    for user, (conn, key) in clients.items():
        try:
            payload = json.dumps({"type": "user_list", "users": usernames})
            encrypted = encrypt_message(payload, key)
            conn.sendall(encrypted)
        except:
            continue

def handle_client(conn, addr, private_key):
    try:
        encrypted_aes_key = conn.recv(256)
        aes_key = private_key.decrypt(
            encrypted_aes_key,
            padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
        )

        username = conn.recv(1024).decode().strip()
        clients[username] = (conn, aes_key)
        broadcast_user_list()

        while True:
            data = conn.recv(4096)
            if not data:
                break
            try:
                decrypted = decrypt_message(data, aes_key)
                payload = json.loads(decrypted)

                to_user = payload.get("to")
                if to_user in clients:
                    dest_conn, dest_key = clients[to_user]
                    encrypted = encrypt_message(json.dumps(payload), dest_key)
                    dest_conn.sendall(encrypted)
            except Exception as e:
                print(f"Decryption error: {e}")

    finally:
        if username in clients:
            del clients[username]
        broadcast_user_list()
        conn.close()

def generate_keys():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()

    with open("private_key.pem", "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ))
    with open("public_key.pem", "wb") as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ))

def main(generate_keys_flag=False):
    if generate_keys_flag:
        generate_keys()

    with open("private_key.pem", "rb") as f:
        private_key = serialization.load_pem_private_key(f.read(), password=None)

    IP = os.getenv("IP_ADDRESS")
    PORT = int(os.getenv("PORT"))
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((IP, PORT))
    server.listen(5)
    print(f"Server started on {IP}:{PORT}")

    while True:
        conn, addr = server.accept()
        with open("public_key.pem", "rb") as f:
            public_key = f.read()
        conn.sendall(public_key)
        threading.Thread(target=handle_client, args=(conn, addr, private_key), daemon=True).start()

if __name__ == "__main__":
    import sys
    main("--gen-keys" in sys.argv)
