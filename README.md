# protocol_prototype

Clone this repository and run the below steps:

#Environment setup:
Create a venv using the following conda command: `conda create --name ENV_NAME python`
Activate the venv: `conda activate ENV_NAME`
Install requirements: `pip install -r requirements.txt`

#Running the program:
Key exchange is required every time you start the program (will fix) and this is done with `python3 server.py --gen-keys`
This should begin running the server. In another terminal, run the client with: `python3 client.py`
The connection should be established with the client and server along with key exchange. The client can then send and the server will receive.