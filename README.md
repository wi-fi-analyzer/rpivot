RPIVOT - reverse socks4 proxy for penetration tests
===================


RPIVOT allows to tunnel traffic into internal network via socks4. It works like ssh dynamic port forwarding but in the opposite direction. 


----------


Description
-------------

This tools is written in Python and has no dependencies beyond the standard library. It has client-server architecture. Just run the client on the machine you want to tunnel the traffic through. Server should be started on pentester's machine and listen to incoming connections from the client.

Tested on Kali Linux, Windows 7, Mac OS X El Capitan.

Binaries compiled with pyinstaller are also available.