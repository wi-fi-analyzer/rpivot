RPIVOT - reverse socks4 proxy for penetration tests
===================


RPIVOT allows to tunnel traffic into internal network via socks4. It works like ssh dynamic port forwarding but in the opposite direction. 


----------


Description
-------------

This tool is written in Python 2.7 and has no dependencies beyond the standard library. It has client-server architecture. Just run the client on the machine you want to tunnel the traffic through. Server should be started on pentester's machine and listen to incoming connections from the client.

Tested on Kali Linux, Windows 7, Mac OS X El Capitan.

Static client binaries for linux_x64 and windows compiled with pyinstaller are also available.

Usage example
-------------

Start server listener on port 9999, which creates a socks4 proxy on 127.0.0.1:1080 upon connection from client:

python server.py --server-port 9999 --server-ip 0.0.0.0 --proxy-ip 127.0.0.1 --proxy-port 1080

Connect to the server:

python client.py --server-ip <server_ip> --server-port 9999 

Author
------

Artem Kondratenko https://twitter.com/artkond