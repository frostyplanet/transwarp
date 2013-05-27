transwarp
=========

a socks tunnel agent

browser --[sock5]--> client --[tunnel]--> server -> website

Sock5 interface authentication supports no_auth and basic (user/password)

From client to server use key to authenticate and do encryption with AES. 

It has been efficient enough for watching Youtube in HD.

dependency
-----------
pycrypto


usage
-----------

server-side : 

in config_server.py , add your client keys, configure your server port.

python server.py start 

client-side:  

in config_client.py , configure your address and port to listen as a sock5 server.

python client.py start
