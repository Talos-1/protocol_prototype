# protocol_prototype
This is a simple client-server program prototyped in Python to show how a single client and server can communicate securely using AES-GCM.

## Environment Setup:
1. Clone the repository
2. Create a venv using the following conda command: `conda create --name ENV_NAME python`
3. Activate the venv: `conda activate ENV_NAME`
4. Install requirements: `pip install -r requirements.txt`

## Running the program:
1. Key exchange is required every time you start the program (will fix) and this is done with: `python3 server.py --gen-keys`
2. This should begin running the server. In another terminal, run the client with: `python3 client.py`
3: The connection should be established with the client and server along with key exchange. The client can then send and the server will receive. This is indicated with ">" in the client terminal.

```
User A                User B
  |                      |
  | 1. Send Message       | 6. Receive Message
  V                      V
+---------+            +---------+
| ChatGUI |            | ChatGUI |
+---------+            +---------+
     | 2. Input             ^ 5. Display
     V                      |
+-------------------------------+
| AES Encrypt + Socket Send     |
+-------------------------------+
     | 3. Encrypted Msg
     V
+-------------------------------+
|         Server.py             |
| - Public Key Exchange         |
| - AES Key Decrypt             |
| - User Routing (To: field)    |
+-------------------------------+
     | 4. Forward Encrypted Msg
     V
+-------------------------------+
| AES Decrypt + Display         |
+-------------------------------+
     ^                      |
     |                      |
  <--------------------------
       Encrypted Message Flow
```
