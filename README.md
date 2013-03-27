transwarp
=========

a socks tunnel agent

sock5 -> client -> tunnel -> server -> dest

sock5 interface authentication is not implemented yet.

from client to server use key to authenticate and encrypt with AES

dependency
-----------
pycrypto

usage
-----------
server-side :   python server.py start 
client-side:  

in config_client.py , configuration your address and port to listen as a sock5 server

python client.py start
