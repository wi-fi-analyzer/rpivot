import time


buffer_size = 4096
delay = 0.0001
socks_server_reply_success = '\x00\x5a\xff\xff\xff\xff\xff\xff'
socks_server_reply_fail = '\x00\x5b\xff\xff\xff\xff\xff\xff'

COMMAND_CHANNEL = 0
CHANNEL_CLOSE_CMD = '\xcc'
CHANNEL_OPEN_CMD = '\xdd'
FORWARD_CONNECTION_SUCCESS = '\xee'
FORWARD_CONNECTION_FAILURE = '\xff'
CLOSE_RELAY = '\xc4'

class ClosedSocket(Exception):
    pass

class RelayError(Exception):
    pass


def recvall(sock, data_len):
    buf = ''
    sock.setblocking(0)
    while True:
        buf += sock.recv(data_len - len(buf))
        if len(buf) == data_len:
            break
        time.sleep(delay)
    assert(data_len == len(buf))
    return buf