import logging
import logging.handlers
import socket
import sys
import time
from struct import pack, unpack
import select
import errno


LOG_FILENAME = 'logging_client.out'

logger = None

control_port = 99999
socks_port = 1080
eof_marker = '1c87114debc9bb3e6e89ef51be42d13597abb994404ebe688cb07b03e88'
buffer_size = 4096
delay = 0.0001


class ClosedSocket(Exception):
    pass


class SocksRelay:

    STATUS_SUCCESS = 0
    STATUS_REFUSED = 1
    STATUS_TIMEOUT = 2
    socks_server_reply_success = '\x00\x5a\xff\xff\xff\xff\xff\xff'
    socks_server_reply_fail = '\x00\x5b\xff\xff\xff\xff\xff\xff'

    def __init__(self, bc_sock):
        self.COMMAND_CHANNEL = 0
        self.CHANNEL_CLOSE_CMD = '\xcc'
        self.CHANNEL_OPEN_CMD = '\xdd'
        self.FORWARD_CONNECTION_SUCCESS = '\xee'
        self.FORWARD_CONNECTION_FAILURE = '\xff'
        self.channel = {}
        self.id_by_socket = {}
        self.bc_sock = bc_sock
        self.input_list = [self.bc_sock]
        self.establishing_dict = {}
        self.forward_socket = None
        self.data = None

    def run(self):
        while True:
            time.sleep(delay)
            inputready, outputready, exceptready = select.select(self.input_list, self.establishing_dict.keys(), [])

            for sock in outputready:
                channel_id = self.establishing_dict[sock]
                logger.debug('Establishing connection with channel id {}'.format(channel_id))
                try:
                    sock.recv(0)
                except socket.error as (code, err_msg):
                    if code == errno.ECONNREFUSED or code == errno.ETIMEDOUT:
                        logger.debug('Connection {}'.format(errno.errorcode[code]))

                        if sock in inputready:
                            inputready.remove(sock)
                        del self.establishing_dict[sock]

                        logger.debug('Establishing connection with channel id {}'.format(channel_id))
                        self.send_remote_cmd(self.bc_sock, self.FORWARD_CONNECTION_FAILURE, self.establishing_dict[sock])
                        sock.close()

                        continue
                    elif code == errno.EAGAIN:
                        # all good just no data to receive
                        pass
                    else:
                        raise
                # connection successful
                sock.setblocking(1)

                self.send_remote_cmd(self.bc_sock, self.FORWARD_CONNECTION_SUCCESS, self.establishing_dict[sock])
                del self.establishing_dict[sock]
                self.input_list.append(sock)
                self.set_channel(sock, channel_id)


            for self.selected_input_socket in inputready:
                #self.data = self.selected_input_socket.recv(buffer_size)
                #data_len = len(self.data)

                if self.selected_input_socket == self.bc_sock:
                    logger.debug('Remote side socket active')
                    try:
                        self.manage_remote_socket(self.bc_sock)
                    except ClosedSocket:
                        logger.debug('Remote side closed socket')
                    '''
                    assert(self.selected_input_socket == self.bc_sock)
                    assert(data_len != 0)
                    (host, port) = self.parse_socks_header()
                    connection_status = self.establish_forward_socket(host, port)

                    if connection_status == SocksRelay.STATUS_SUCCESS:
                        self.on_socks_success()
                    elif connection_status == SocksRelay.STATUS_REFUSED:
                        self.on_socks_fail()

                    elif connection_status == SocksRelay.STATUS_TIMEOUT:
                        self.on_socks_fail()
                    '''

                else:
                    #logger.debug('Forward socket {} active with channel id {}'.format(self.selected_input_socket, self.id_by_socket[self.selected_input_socket]))
                    self.manage_forward_socket(self.selected_input_socket)
                '''
                elif self.input_list == [self.bc_sock, self.forward_socket]:
                    if self.selected_input_socket == self.bc_sock:
                        if data_len == 0:
                            logger.debug('Server side closed socket. Exiting program')
                            sys.exit(1)
                        elif self.data.startswith(eof_marker):
                            logger.debug('Got eof market. Server side notified us to close current socks connection\n Full data contents: {}\n Length: {}'.format(repr(self.data), len(self.data)))
                            self.on_server_socks_close()
                        else:
                            # generic data - relay it
                            self.relay(self.forward_socket)

                    elif self.selected_input_socket == self.forward_socket:
                        if data_len == 0:
                            logger.debug('Forward connection terminated')
                            self.on_client_socks_close()
                        else:
                            # generic data - relay it
                            self.relay(self.bc_sock)

                else:
                    logger.debug('Invalid socket input list! Exiting...')
                    sys.exit(1)
                '''

    def handle_remote_cmd(self, data):
        cmd = data[0]
        logger.debug('Received cmd data: {}'.format(repr(data)))
        if cmd == self.CHANNEL_CLOSE_CMD:
            channel_id = unpack('B', data[1])[0]
            logger.debug('Channel close request with id: {}'.format(channel_id))
            sock_to_close = self.channel[channel_id]
            self.unset_channel(channel_id)
            logger.debug('Closing socket with id: {}'.format(channel_id))
            sock_to_close.close()
            self.input_list.remove(sock_to_close)
        elif cmd == self.CHANNEL_OPEN_CMD:
            channel_id, packed_ip, port = unpack('<BIH', data[1:8])
            ip = socket.inet_ntoa(data[2:6])
            logger.debug('Got new channel request with id {} . Opening new forward connection to host {} port {}'.format(channel_id, ip, port))
            self.establish_forward_socket(channel_id, ip, port)
        else:
            logger.debug('Received unknown cmd: {}'.format(cmd))
            sys.exit(1)

    def get_channel_data(self, sock):
        # receive tlv header: 1 byte channel id, 2byte length
        tlv_header = sock.recv(3)
        if len(tlv_header) == 0:
            logger.debug('No data from remote side')
            raise ClosedSocket('Remote side close connection')
        tlv_header_len = len(tlv_header)
        if tlv_header_len != 3:
            logger.debug('Unable to receive tlv header. Exiting. Data contents: {}. Data len: {}'.format(tlv_header, len(tlv_header)))
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
            (channel_id, data) = self.get_channel_data(sock)
        except ClosedSocket:
            logger.debug('Remote side closed connection.')
            self.close_remote_connection(sock)
            raise ClosedSocket

        if channel_id == self.COMMAND_CHANNEL:
            self.handle_remote_cmd(data)
        else:
            relay_to_sock = self.channel[channel_id]
            self.relay(data, relay_to_sock)

    def close_remote_connection(self, sock):
        sock.close()
        self.input_list.remove(sock)

    def manage_forward_socket(self, sock):
        logger.debug('Got data from socket {} with channel id {}'.format(sock, self.id_by_socket[sock]))
        data = sock.recv(buffer_size)
        data_len = len(data)
        if data_len == 0:
            self.close_forward_connection(sock)
            return
        else:
            channel_id = self.id_by_socket[sock]
            tlv_header = pack('<BH', channel_id, len(data))
            self.relay(tlv_header + data, self.bc_sock)

    def close_forward_connection(self, sock):
        channel_id = self.id_by_socket[sock]
        logger.debug('Closing forward socket {} with id {}\n Notifying remote side'.format(sock, channel_id))
        self.unset_channel(channel_id)
        self.input_list.remove(sock)
        sock.close()
        self.send_remote_cmd(sock, self.CHANNEL_CLOSE_CMD, channel_id)

    def send_remote_cmd(self, sock, cmd, *args):
        if cmd == self.CHANNEL_CLOSE_CMD:
            cmd_buffer = cmd + pack('B', args[0])
            tlv_header = pack('<BH', self.COMMAND_CHANNEL, len(cmd_buffer))
            sock.send(tlv_header + cmd_buffer)
        elif cmd == self.FORWARD_CONNECTION_SUCCESS:
            cmd_buffer = cmd + pack('B', args[0])
            tlv_header = pack('<BH', self.COMMAND_CHANNEL, len(cmd_buffer))
            sock.send(tlv_header + cmd_buffer)
        elif cmd == self.FORWARD_CONNECTION_FAILURE:
            cmd_buffer = cmd + pack('B', args[0])
            tlv_header = pack('<BH', self.COMMAND_CHANNEL, len(cmd_buffer))
            sock.send(tlv_header + cmd_buffer)
        else:
            logger.debug('qUnknown cmd: {}'.format(repr(cmd)))
            sys.exit(1)


    def set_channel(self, sock, channel_id):
        #new_channel_id = self.generate_new_channel_id()
        self.channel[channel_id] = sock
        self.id_by_socket[sock] = channel_id

    def unset_channel(self, channel_id):
        sock = self.channel[channel_id]
        del self.id_by_socket[sock]
        del self.channel[channel_id]


    def on_socks_fail(self):
        self.bc_sock.send(self.socks_server_reply_fail)

    def on_socks_success(self):
        self.bc_sock.send(self.socks_server_reply_success)
        self.input_list.append(self.forward_socket)

    def on_server_socks_close(self):
        self.input_list.remove(self.forward_socket)
        self.forward_socket.close()
        logger.debug('Closed forward socket')

    def on_client_socks_close(self):
        self.input_list.remove(self.forward_socket)
        self.forward_socket.close()
        logger.debug('Closed forward socket. Sending eof marker to server side')
        self.bc_sock.send(eof_marker + 'A' * (buffer_size - len(eof_marker)))

    def establish_forward_socket(self, channel_id, host, port):
        sock = None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.setblocking(0)
            sock.connect_ex((host, port))
            #return SocksRelay.STATUS_SUCCESS
        except socket.error, exc:
            print "Caught exception socket.error : %s" % exc
            return SocksRelay.STATUS_REFUSED
        logger.debug('Establishing new forward connection with channel id {} and socket {}'.format(channel_id, sock))
        self.establishing_dict[sock] = channel_id

        #self.channel[channel_id] = sock
        #self.id_by_socket[sock] = channel_id
        #self.input_list.append(sock)

    def parse_socks_header(self):
        (vn, cd, dstport, dstip) = unpack('>BBHI', self.data[:8])
        logger.debug('Parsing socks header. Data contents : {}'.format(repr(self.data)))
        str_ip = socket.inet_ntoa(pack(">L", dstip))
        logger.debug('Socks version: {} Socks command: {} Dstport: {} Dstip: {}'.format(vn, cd, dstport, str_ip))
        return str_ip, dstport

    def relay(self, data, to_socket):
        #logger.debug('Got data to relay. Relaying data: {}\nData length: {}'.format(self.data, len(self.data)))
        if to_socket is None:
            return
        to_socket.send(data)


def main():

    # Add the log message handler to the logger
    global logger
    logger = logging.getLogger('root')
    logger.setLevel(logging.DEBUG)
    ch = logging.StreamHandler()
    ch.setLevel(logging.DEBUG)
    logger.addHandler(ch)

    backconnect_host = '127.0.0.1'
    backconnect_port = 9999
    bc_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    bc_sock.connect((backconnect_host, backconnect_port))
    logger.debug('Backconnecting to server')
    socks_relayer = SocksRelay(bc_sock)
    socks_relayer.run()


if __name__ == '__main__':

    main()

'''
def main():
    HOST, PORT = "localhost", 9999
    data = "ololo data"

    # Create a socket (SOCK_STREAM means a TCP socket)
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    try:
        # Connect to server and send data
        sock.connect((HOST, PORT))
        sock.sendall(data + "\n")

        # Receive data from the server and shut down
        received = sock.recv(1024)
    finally:
        sock.close()

    print "Sent:     {}".format(data)
    print "Received: {}".format(received)
'''
