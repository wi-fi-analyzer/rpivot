import logging
import logging.handlers
import SocketServer
import socket
import select
import sys
import time
from struct import pack, unpack
import random

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
        self.id_by_socket =  {}
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
                print 'before select'
                print 'input list:'
                print self.input_list
                inputready, outputready, exceptready = select.select(self.input_list, [], [])
            except socket.error, e:
                print 'Socket error', e
                print 'exiting main loop'
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
                    logger.debug("Active socket {} does not belong to channel. Exiting".format(self.selected_input_socket))
                    sys.exit(1)

    def parse_socks_header(self, data):
        (vn, cd, dstport, dstip) = unpack('>BBHI', data[:8])
        if vn != 4:
            logger.debug('Invalid socks header! Got data: {}'.format(repr(data)))
        logger.debug('Parsing socks header. Data contents : {}'.format(repr(data)))
        str_ip = socket.inet_ntoa(pack(">L", dstip))
        logger.debug('Socks version: {} Socks command: {} Dstport: {} Dstip: {}'.format(vn, cd, dstport, str_ip))
        return str_ip, dstport

    def get_channel_data(self, sock):
        # receive tlv header: 1 byte channel id, 2byte length
        tlv_header = sock.recv(3)
        if tlv_header == 0:
            raise ClosedSocket('Remote side close connection')
        tlv_header_len = len(tlv_header)
        if tlv_header_len != 3:
            logger.debug('Unable to receive tlv header. Exiting. Data contents: {}'.format(tlv_header))
            sys.exit(1)
        channel_id, tlv_data_len = unpack('<BH', tlv_header)
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
        else:
            relay_to_sock = self.channel[channel_id]
            self.relay(data, relay_to_sock)

    def manage_socks_client_socket(self, sock):
        logger.debug('Got data from socket {} with channel id {}'.format(sock, self.id_by_socket[sock]))
        data = sock.recv(buffer_size)
        data_len = len(data)
        if data_len == 0:
            self.close_socks_connection(sock)
            return
        else:
            channel_id = self.id_by_socket[sock]
            tlv_header = pack('<BH', channel_id, len(data))
            self.relay(tlv_header + data, self.socket_with_server)

    def handle_remote_cmd(self, data):
        cmd = data[0]
        logger.debug('Received cmd data: {}'.format(repr(data)))
        if cmd == self.CHANNEL_CLOSE_CMD:
            channel_id = unpack('B', data[1])[0]
            sock_to_close = self.channel[channel_id]
            self.unset_channel(channel_id)
            logger.debug('Closing socket with id: {}'.format(channel_id))
            sock_to_close.close()
        elif cmd == self.FORWARD_CONNECTION_SUCCESS:
            channel_id = unpack('B', data[1])[0]
            logger.debug('Forward connection successful with id: {}'.format(channel_id))
            sock = self.channel[channel_id]
            sock.send(socks_server_reply_success)
        elif cmd == self.FORWARD_CONNECTION_FAILURE:
            channel_id = unpack('B', data[1])[0]
            logger.debug('Forward connection failed with id: {}'.format(channel_id))
            sock = self.channel[channel_id]
            sock.send(socks_server_reply_fail)
            self.input_list.remove(sock)
            self.unset_channel(channel_id)
            sock.close()

    def send_remote_cmd(self, sock, cmd, *args):
        logger.debug('Sending cmd to remote side. Cmd: {}'.format(repr(cmd)))
        if cmd == self.CHANNEL_CLOSE_CMD:
            cmd_buffer = cmd + pack('B', args[0])
            tlv_header = pack('<BH', self.COMMAND_CHANNEL, len(cmd_buffer))
            sock.send(tlv_header + cmd_buffer)
        elif cmd == self.CHANNEL_OPEN_CMD:
            channel_id, ip, port = args
            cmd_buffer = cmd + pack('B',  channel_id) + socket.inet_aton(ip) + pack('<H', port)
            tlv_header = pack('<BH', self.COMMAND_CHANNEL, len(cmd_buffer))
            sock.send(tlv_header + cmd_buffer)
        else:
            logger.debug('Unknown cmd: {}'.format(cmd))
            sys.exit(1)

    def on_accept(self):
        socks_client_socket, clientaddr = self.server.accept()
        logger.debug("{} has connected".format(clientaddr))
        ip, port = self.handle_new_socks_connection(socks_client_socket)
        self.input_list.append(socks_client_socket)
        new_channel_id = self.set_channel(socks_client_socket)
        logger.debug("Sending command to open channel {}".format(new_channel_id))
        self.send_remote_cmd(self.socket_with_server, self.CHANNEL_OPEN_CMD, new_channel_id, ip, port)


    def handle_new_socks_connection(self, sock):
        data = sock.recv(buffer_size)
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
            rint = random.randint(1, 255)
            if rint not in channel_ids:
                return rint

    def on_close(self):
        print self.s.getpeername(), "has disconnected"
        self.input_list.remove(self.s)
        self.s.close()

    def close_socks_connection(self, sock):
        channel_id = self.id_by_socket[sock]
        logger.debug('Closing socks client socket {} with id {}\n Notifying remote side'.format(sock, channel_id))
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
        for channel_id, sock in self.channel.iteritems():
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
        #logger.debug('Got data to relay. Relaying data: {}\nData length: {}'.format(self.data, len(self.data)))
        if to_socket is None:
            return
        to_socket.send(data)




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
        server = TheServer('', 1080, self.request)
        try:
            print 'before server loop'
            server.main_loop()
            print 'exited server loop'
        except KeyboardInterrupt:
            print "Ctrl C - Stopping server"
            sys.exit(1)

if __name__ == "__main__":
    global logger
    logger = logging.getLogger('root')
    logger.setLevel(logging.DEBUG)
    ch = logging.StreamHandler()
    ch.setLevel(logging.DEBUG)
    logger.addHandler(ch)

    HOST, PORT = "0.0.0.0", 9999

    # Create the server, binding to localhost on port 9999
    SocketServer.TCPServer.allow_reuse_address = True
    server = SocketServer.TCPServer((HOST, PORT), MyTCPHandler)

    # Activate the server; this will keep running until you
    # interrupt the program with Ctrl-C
    server.serve_forever()



