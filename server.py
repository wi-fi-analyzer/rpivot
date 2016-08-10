import logging
import logging.handlers
import SocketServer
import socket
import select
import sys
import time
from struct import pack, unpack
import struct
import random
import errno
import argparse



socks_server_reply_success = '\x00\x5a\xff\xff\xff\xff\xff\xff'
socks_server_reply_fail = '\x00\x5b\xff\xff\xff\xff\xff\xff'

LOG_FILENAME = 'logging_server.out'

control_port = 99999
socks_port = 1080

eof_marker = '1c87114debc9bb3e6e89ef51be42d13597abb994404ebe688cb07b03e88'
tlv_header_size = 3
buffer_size = 4096
delay = 0.0001
forward_to = ('78.46.223.0', 123)





def chunks(l, n):
    """Yield successive n-sized chunks from l."""
    for i in range(0, len(l), n):
        yield l[i:i+n]

'''
class Channel:
    def __init__():
        return

    def send(self, data):
        retu

    def recv(self):
        return

class ChannelMng:
    def __init__(self, sock):
        self.sock = sock
        return

    def create_channel(self):
        return

    def delete_channel(self):
        return

    def recv(self, channel_num):
        return

    def send(self, channel_num, data):
        payload_size = buffer_size - tlv_header_size
        for data_chunk in chunks(data, payload_size):
            data_chunk_len = len(data_chunk)
            tlv_header = pack('<BH', channel_num, data_chunk_len)
            self.sock.send(tlv_header + data_chunk)


def channel_usage_example():
    sock = socket.socket()

    chnMng = ChannelMng(sock)

    channel_1 = ChannelMng.create_channel()

    channel_2 = ChannelMng.create_channel()

    channel_1.send('ololo')
    t = channel_1.recv()
    print t


class Forward:
    def __init__(self, socket_with_server):
        self.forward = socket_with_server

    def start(self, host, port):
        try:
            #self.forward.connect((host, port))
            return self.forward
        except Exception, e:
            print e
            return False
'''


class ClosedSocket(Exception):
    pass

class RelayError(Exception):
    pass


class TheServer:
    input_list = []
    channel = {}

    def __init__(self, host, port, socket_with_server):
        self.COMMAND_CHANNEL = 0
        self.CHANNEL_CLOSE_CMD = '\xcc'
        self.CHANNEL_OPEN_CMD = '\xdd'
        self.FORWARD_CONNECTION_SUCCESS = '\xee'
        self.FORWARD_CONNECTION_FAILURE = '\xff'
        self.channel = {}
        self.id_by_socket = {}
        self.socket_with_server = socket_with_server
        self.input_list.append(self.socket_with_server)
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server.bind((host, port))
        self.server.listen(200)
        self.socks_client_socket = None

    def main_loop(self):
        self.input_list.append(self.server)
        while True:
            time.sleep(delay)
            try:
                #print self.input_list
                logger.debug("Trying select")
                logger.debug("Channels: {}".format(self.channel.keys()))
                inputready, outputready, exceptready = select.select(self.input_list, [], [])
            except socket.error as (code, msg):
                logger.debug('Socket error on select. Errno: {} Msg: {}'.format(errno.errorcode[code], msg))

                return
            for self.selected_input_socket in inputready:
                if self.selected_input_socket == self.server:
                    self.on_accept()
                    break

                if self.selected_input_socket == self.socket_with_server:
                    try:
                        self.manage_remote_socket(self.selected_input_socket)
                    except ClosedSocket:
                        break
                elif self.selected_input_socket in self.id_by_socket:
                    self.manage_socks_client_socket(self.selected_input_socket)
                else:
                    logger.debug("Active socket {} does not belong to channel. Closing it".format(self.selected_input_socket))
                    self.selected_input_socket.close()


    def parse_socks_header(self, data):
        logger.debug('Parsing socks header. Data contents : {}'.format(repr(data)))
        try:
            (vn, cd, dstport, dstip) = unpack('>BBHI', data[:8])
        except struct.error:
            logger.debug('Invalid socks header! Got data: {}'.format(repr(data)))
            raise RelayError
        if vn != 4:
            logger.debug('Invalid socks header! Got data: {}'.format(repr(data)))
            raise RelayError
        str_ip = socket.inet_ntoa(pack(">L", dstip))
        logger.debug('Socks version: {} Socks command: {} Dstport: {} Dstip: {}'.format(vn, cd, dstport, str_ip))
        return str_ip, dstport

    def get_channel_data(self, sock):
        # receive tlv header: 1 byte channel id, 2byte length
        tlv_header = sock.recv(4)
        if len(tlv_header) == 0:
            raise ClosedSocket('Remote side closed connection')
        tlv_header_len = len(tlv_header)
        if tlv_header_len != 4:
            logger.debug('Unable to receive tlv header. Exiting. Data contents: {}'.format(tlv_header))
            sys.exit(1)
        channel_id, tlv_data_len = unpack('<HH', tlv_header)
        data = ''
        fail_counter = 0
        while len(data) < tlv_data_len:
            if fail_counter == 10:
                logger.debug('Failed to get tlv data after 10 tries. Exiting.')
                sys.exit()
            chunk = sock.recv(tlv_data_len - len(data))
            data += chunk
            fail_counter += 1
        return channel_id, data

    def manage_remote_socket(self, sock):
        channel_id = None
        data = None
        try:
            channel_id, data = self.get_channel_data(sock)
        except ClosedSocket:
            logger.debug('Remote side closed connection. Unbinding socks port')
            self.close_remote_client_connection()
            raise ClosedSocket

        if channel_id == self.COMMAND_CHANNEL:
            self.handle_remote_cmd(data)
        elif channel_id in self.channel:
            relay_to_sock = self.channel[channel_id]
            self.relay(data, relay_to_sock)
        else:
            logger.debug('Relay from socket {} with channel {} not possible. Channel does not exist'.format(sock, channel_id))
            return

    def manage_socks_client_socket(self, sock):
        #logger.debug('Got data from socket {} with channel id {}'.format(sock, self.id_by_socket[sock]))
        try:
            data = sock.recv(buffer_size)
        except socket.error as (code, msg):
            logger.debug('Exception on reading socket {} with channel id {}'.format(sock, self.id_by_socket[sock]))
            logger.debug('Details: {}, {}'.format(errno.errorcode[code], msg))
            self.close_socks_connection(sock)
            return
        data_len = len(data)
        if data_len == 0:
            self.close_socks_connection(sock)
            return
        else:
            channel_id = self.id_by_socket[sock]
            tlv_header = pack('<HH', channel_id, len(data))
            self.relay(tlv_header + data, self.socket_with_server)

    def handle_remote_cmd(self, data):
        cmd = data[0]
        logger.debug('Received cmd data: {}'.format(repr(data)))
        if cmd == self.CHANNEL_CLOSE_CMD:
            channel_id = unpack('<H', data[1:3])[0]
            logger.debug('Channel close request with id: {}'.format(channel_id))
            if channel_id not in self.channel:
                logger.debug('Channel {} already close'.format(channel_id))
                return
            else:
                sock_to_close = self.channel[channel_id]
                self.input_list.remove(sock_to_close)
                self.unset_channel(channel_id)
                logger.debug('Closing socket {}  with id: {}'.format(sock_to_close, channel_id))
                sock_to_close.close()
        elif cmd == self.FORWARD_CONNECTION_SUCCESS:
            channel_id = unpack('<H', data[1:3])[0]
            logger.debug('Forward connection successful with id: {}'.format(channel_id))
            sock = self.channel[channel_id]
            sock.send(socks_server_reply_success)
        elif cmd == self.FORWARD_CONNECTION_FAILURE:
            channel_id = unpack('<H', data[1:3])[0]
            logger.debug('Forward connection failed with id: {}'.format(channel_id))
            sock = self.channel[channel_id]
            sock.send(socks_server_reply_fail)
            self.input_list.remove(sock)
            self.unset_channel(channel_id)
            sock.close()

    def send_remote_cmd(self, sock, cmd, *args):
        logger.debug('Sending cmd to remote side. Cmd: {}'.format(repr(cmd)))
        if cmd == self.CHANNEL_CLOSE_CMD:
            cmd_buffer = cmd + pack('<H', args[0])
            tlv_header = pack('<HH', self.COMMAND_CHANNEL, len(cmd_buffer))
            sock.send(tlv_header + cmd_buffer)
        elif cmd == self.CHANNEL_OPEN_CMD:
            channel_id, ip, port = args
            cmd_buffer = cmd + pack('<H',  channel_id) + socket.inet_aton(ip) + pack('<H', port)
            tlv_header = pack('<HH', self.COMMAND_CHANNEL, len(cmd_buffer))
            sock.send(tlv_header + cmd_buffer)
        else:
            logger.debug('Unknown cmd: {}'.format(cmd))
            sys.exit(1)

    def on_accept(self):
        socks_client_socket, clientaddr = self.server.accept()
        logger.debug("Socks client {} has connected".format(clientaddr))
        try:
            ip, port = self.handle_new_socks_connection(socks_client_socket)
        except RelayError:
            logger.debug("Closing socks client socket {}".format(socks_client_socket))
            socks_client_socket.close()
            return
        self.input_list.append(socks_client_socket)
        new_channel_id = self.set_channel(socks_client_socket)
        logger.debug("Sending command to open channel {}".format(new_channel_id))
        self.send_remote_cmd(self.socket_with_server, self.CHANNEL_OPEN_CMD, new_channel_id, ip, port)

    def handle_new_socks_connection(self, sock):
        try:
            data = sock.recv(buffer_size)
        except socket.error as (code, msg):
            logger.debug('Error receiving socks header {} {}'.format(errno.errorcode[code], msg))
            raise RelayError
        if len(data) == 0:
            logger.debug('Socks client prematurely ended connection')
            raise RelayError
        return self.parse_socks_header(data)

    def set_channel(self, sock):
        new_channel_id = self.generate_new_channel_id()
        self.channel[new_channel_id] = sock
        self.id_by_socket[sock] = new_channel_id
        return new_channel_id

    def unset_channel(self, channel_id):
        sock = self.channel[channel_id]
        del self.id_by_socket[sock]
        del self.channel[channel_id]

    def generate_new_channel_id(self):
        channel_ids = self.channel.keys()
        while True:
            rint = random.randint(1, 65535)
            if rint not in channel_ids:
                return rint

    def on_close(self):
        print self.s.getpeername(), "has disconnected"
        self.input_list.remove(self.s)
        self.s.close()

    def close_socks_connection(self, sock):
        channel_id = self.id_by_socket[sock]
        logger.debug('Closing socks client socket {} with id {}'.format(sock, channel_id))
        logger.debug('Notifying remote side')
        self.unset_channel(channel_id)
        self.input_list.remove(sock)
        sock.close()
        self.send_remote_cmd(self.socket_with_server, self.CHANNEL_CLOSE_CMD, channel_id)


    '''
    def close_socks_connection(self, send_eof=True):
        # delete socks connection endpoint on channel
        self.input_list.remove(self.socks_client_socket)
        self.socks_client_socket.close()
        logger.debug('Closing socks client socket')
        self.socks_client_socket = None
        if send_eof:
            logger.debug('Sending eof marker to remote side')
            self.socket_with_server.send(eof_marker + 'A' * (buffer_size - len(eof_marker)))
    '''

    def close_client_sockets(self):
        channel_copy = self.channel.items()
        for channel_id, sock in channel_copy:
            sock.close()
            del self.channel[channel_id]
            self.input_list.remove(sock)

    def close_remote_client_connection(self):
        print 'Closing remote client connection'

        self.input_list.remove(self.socket_with_server)
        self.socket_with_server.close()
        self.socket_with_server = None
        logger.debug('Closing socket with remote client')

        try:
            #self.input_list.remove(self.socks_client_socket)
            self.close_client_sockets()
            #self.socks_client_socket.close()
            #self.socks_client_socket = None
        except ValueError:
            pass
        self.input_list.remove(self.server)
        self.server.close()
        logger.debug('Closing sock bind socket')
        self.server = None


    def on_recv(self):
        data = self.data
        # here we can parse and/or modify the data before send forward
        #print data
        self.channel[self.s].send(data)

    def relay(self, data, to_socket):
        logger.debug('Got data to relay to {}. Data length: {}'.format(to_socket, len(data)))
        logger.debug('remote side socket at {}'.format(self.socket_with_server))
        if to_socket is None:
            return
        try:
            to_socket.send(data)
        except socket.error as (code, msg):
            logger.debug('Exception on relaying data to socket {}'.format(to_socket))
            logger.debug('Errno: {} Msg: {}'.format(errno.errorcode[code], msg))
            logger.debug('Closing socket')
            to_socket.close()
            self.input_list.remove(to_socket)
            if to_socket != self.socket_with_server:
                channel_id = self.id_by_socket[to_socket]
                self.unset_channel(channel_id)
                self.send_remote_cmd(self.socket_with_server, self.CHANNEL_CLOSE_CMD, channel_id)




class MyTCPHandler(SocketServer.BaseRequestHandler):
    """
    The request handler class for our server.

    It is instantiated once per connection to the server, and must
    override the handle() method to implement communication to the
    client.
    """
    allow_reuse_address = True

    def handle(self):
        # self.request is the TCP socket connected to the client
        #self.data = self.request.recv(1024).strip()
        #print "{} wrote:".format(self.client_address[0])
        #print self.data
        # just send back the same data, but upper-cased
        #self.request.sendall(self.data.upper())
        server = TheServer(cmd_options.proxy_ip, cmd_options.proxy_port, self.request)
        try:
            print 'before server loop'
            server.main_loop()
            print 'exited server loop'
        except KeyboardInterrupt:
            print "Ctrl C - Stopping server"
            sys.exit(1)

if __name__ == "__main__":
    global logger
    global cmd_options
    parser = argparse.ArgumentParser(description='Reverse socks server')

    parser.add_argument('--server_ip', action="store", dest='server_ip', default='0.0.0.0')
    parser.add_argument('--server_port', action="store", dest='server_port', default=9999)
    parser.add_argument('--proxy_ip', action="store", dest='proxy_ip', default='127.0.0.1')
    parser.add_argument('--proxy_port', action="store", dest='proxy_port', default=1080)


    cmd_options = parser.parse_args()

    logger = logging.getLogger('root')
    logger.setLevel(logging.DEBUG)
    ch = logging.StreamHandler()
    ch.setLevel(logging.DEBUG)
    logger.addHandler(ch)



    # Create the server, binding to localhost on port 9999
    SocketServer.TCPServer.allow_reuse_address = True
    server = SocketServer.TCPServer((cmd_options.server_ip, cmd_options.server_port), MyTCPHandler)

    # Activate the server; this will keep running until you
    # interrupt the program with Ctrl-C
    server.serve_forever()



