import tkinter as tk
from tkinter import simpledialog, END
import threading
import socket
import os
import json
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization, hashes
from dotenv import load_dotenv

load_dotenv()

class ChatClient:
    def __init__(self, username, on_message_received):
        self.username = username
        self.aes_key = None
        self.conn = None
        self.on_message_received = on_message_received
        self.connect()

    def connect(self):
        IP = os.getenv("IP_ADDRESS")
        PORT = int(os.getenv("PORT"))
        self.conn = socket.create_connection((IP, PORT))

        public_key_bytes = self.conn.recv(2048)
        public_key = serialization.load_pem_public_key(public_key_bytes)

        self.aes_key = os.urandom(32)
        encrypted_key = public_key.encrypt(
            self.aes_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        self.conn.sendall(encrypted_key)
        self.conn.sendall(self.username.encode())

        threading.Thread(target=self.receive_loop, daemon=True).start()

    def receive_loop(self):
        while True:
            try:
                data = self.conn.recv(4096)
                if data:
                    decrypted = self.decrypt_message(data)
                    payload = json.loads(decrypted)

                    if payload.get("type") == "user_list":
                        user_list = payload.get("users", [])
                        self.on_user_list(user_list)
                    else:
                        sender = payload.get("from")
                        message = payload.get("msg")
                        self.on_message_received(sender, message)
            except Exception as e:
                print("Error in receive loop:", e)
                break


    def send(self, to_user, message):
        payload = json.dumps({
            "type": "chat",
            "from": self.username,
            "to": to_user,
            "msg": message
        })
        encrypted = self.encrypt_message(payload)
        self.conn.sendall(encrypted)


    def encrypt_message(self, message: str) -> bytes:
        aesgcm = AESGCM(self.aes_key)
        nonce = os.urandom(12)
        return nonce + aesgcm.encrypt(nonce, message.encode(), None)

    def decrypt_message(self, encrypted: bytes) -> str:
        nonce = encrypted[:12]
        ciphertext = encrypted[12:]
        aesgcm = AESGCM(self.aes_key)
        return aesgcm.decrypt(nonce, ciphertext, None).decode()


class ChatGUI:
    def __init__(self):
        self.window = tk.Tk()
        self.window.title("Secure Chat App")
        self.window.geometry("900x600")
        self.chat_histories = {}
        self.active_user = None

        self.username = simpledialog.askstring("Login", "Enter your username")
        if not self.username:
            exit()

        self.client = ChatClient(self.username, self.on_message_received)
        self.client.on_user_list = self.update_user_list
        #self.client = ChatClient(self.username, self.on_message_received)
        self.setup_widgets()

    def setup_widgets(self):
        # Left panel: User list
        self.user_list_frame = tk.Frame(self.window, width=200, bg="#2c3e50")
        self.user_list_frame.pack(side=tk.LEFT, fill=tk.Y)

        self.user_listbox = tk.Listbox(self.user_list_frame, bg="#2c3e50", fg="white")
        self.user_listbox.pack(fill=tk.BOTH, expand=True)
        self.user_listbox.bind("<<ListboxSelect>>", self.switch_user)

        # Right panel: Chat display and message input
        self.chat_display = tk.Text(self.window, bg="#1c1c1c", fg="white", state=tk.DISABLED)
        self.chat_display.pack(fill=tk.BOTH, expand=True)

        self.entry_field = tk.Entry(self.window, bg="#2c3e50", fg="white", font=("Helvetica", 12))
        self.entry_field.pack(fill=tk.X, padx=5, pady=5, side=tk.LEFT, expand=True)

        self.send_button = tk.Button(self.window, text="Send", command=self.send_message)
        self.send_button.pack(padx=5, pady=5, side=tk.RIGHT)

    def on_message_received(self, from_user, message):
        if from_user not in self.chat_histories:
            self.chat_histories[from_user] = []
            self.user_listbox.insert(END, from_user)

        self.chat_histories[from_user].append(f"{from_user}: {message}")

        if from_user == self.active_user:
            self.update_chat_display()

    def switch_user(self, event):
        selection = event.widget.curselection()
        if not selection:
            return
        selected_index = selection[0]
        self.active_user = self.user_listbox.get(selected_index)
        self.update_chat_display()

    def send_message(self):
        if not self.active_user:
            return
        message = self.entry_field.get().strip()
        if message:
            self.client.send(self.active_user, message)
            self.chat_histories.setdefault(self.active_user, []).append(f"You: {message}")
            self.update_chat_display()
            self.entry_field.delete(0, END)

    def update_chat_display(self):
        self.chat_display.config(state=tk.NORMAL)
        self.chat_display.delete(1.0, END)
        for line in self.chat_histories.get(self.active_user, []):
            self.chat_display.insert(END, line + "\n")
        self.chat_display.config(state=tk.DISABLED)
    
    def update_user_list(self, user_list):
        self.user_listbox.delete(0, END)
        for user in sorted(user_list):
            if user != self.username:
                self.user_listbox.insert(END, user)


    def run(self):
        self.window.mainloop()


if __name__ == "__main__":
    app = ChatGUI()
    app.run()
