import logging
import logging.handlers
import socket
import sys
import time
from struct import pack, unpack
import struct
import select
import argparse
import errno
import relay


logger = None







def key_by_value(my_dict, value):
    for k, v in my_dict.iteritems():
        if v == value:
            return k
    return None





class SocksRelay:

    STATUS_SUCCESS = 0
    STATUS_REFUSED = 1
    STATUS_TIMEOUT = 2


    def __init__(self, bc_sock):

        self.channel = {}
        self.id_by_socket = {}
        self.bc_sock = bc_sock
        self.input_list = [self.bc_sock]
        self.establishing_dict = {}
        self.forward_socket = None
        self.data = None

    def run(self):
        while True:
            time.sleep(relay.delay)
            logger.debug('Trying select')
            logger.debug("Number of channels {} channels: {}. Pending Channels {}".format(len(self.channel.keys()), self.channel.keys(), self.establishing_dict.values()))
            try:
                inputready, outputready, exceptready = select.select(self.input_list, self.establishing_dict.keys(), [])
            except KeyboardInterrupt:
                logger.info('SIGINT received. Closing relay and exiting')
                self.send_remote_cmd(self.bc_sock, relay.CLOSE_RELAY)
                self.bc_sock.close()
                sys.exit(1)
            except select.error as (code, msg):
                logger.debug('Socket error on select. Errno: {} Msg: {}'.format(errno.errorcode[code], msg))
                sys.exit(1)
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

                        #logger.debug('Establishing connection with channel id {}'.format(channel_id))
                        self.send_remote_cmd(self.bc_sock, relay.FORWARD_CONNECTION_FAILURE, channel_id)
                        sock.close()

                        continue
                    elif code == errno.EAGAIN:
                        logger.debug('Recv(0) return errno.EAGAIN for socket {} on channel {}'.format(sock, channel_id))
                        # all good just no data to receive
                    elif code == 10035:
                        logger.debug('Recv(0) raised windows-specific exception 10035. Probably all ok :)')
                    else:
                        raise
                # connection successful
                logger.debug('Connection established on channel {}'.format(channel_id))
                sock.setblocking(1)

                self.send_remote_cmd(self.bc_sock, relay.FORWARD_CONNECTION_SUCCESS, self.establishing_dict[sock])
                del self.establishing_dict[sock]
                self.input_list.append(sock)
                self.set_channel(sock, channel_id)


            for self.selected_input_socket in inputready:
                #self.data = self.selected_input_socket.recv(relay.buffer_size)
                #data_len = len(self.data)

                if self.selected_input_socket == self.bc_sock:
                    #logger.debug('Remote side socket active')
                    try:
                        self.manage_remote_socket(self.bc_sock)
                    except relay.ClosedSocket:
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
        if cmd == relay.CHANNEL_CLOSE_CMD:
            channel_id = unpack('<H', data[1:3])[0]
            logger.debug('Channel close request with id: {}'.format(channel_id))
            establishing_sock = key_by_value(self.establishing_dict, channel_id)
            if establishing_sock is not None:
                logger.debug('Closing establishing socket with id: {}'.format(channel_id))
                del self.establishing_dict[establishing_sock]
            elif channel_id not in self.channel:
                logger.debug('Channel {} non existent'.format(channel_id))
                return
            else:
                sock_to_close = self.channel[channel_id]
                self.unset_channel(channel_id)
                logger.debug('Closing socket with id: {}'.format(channel_id))
                sock_to_close.close()
                self.input_list.remove(sock_to_close)
        elif cmd == relay.CHANNEL_OPEN_CMD:
            channel_id, packed_ip, port = unpack('<HIH', data[1:9])
            ip = socket.inet_ntoa(data[3:7])
            logger.debug('Got new channel request with id {} . Opening new forward connection to host {} port {}'.format(channel_id, ip, port))
            self.establish_forward_socket(channel_id, ip, port)
        elif cmd == relay.CLOSE_RELAY:
            logger.info('Got command to close relay. Closing socket and exiting.')
            self.bc_sock.close()
            sys.exit(1)
        else:
            logger.debug('Received unknown cmd: {}'.format(cmd))
            sys.exit(1)

    def get_channel_data(self, sock):
        # receive tlv header: 2 byte channel id, 2byte length
        #tlv_header_len = 4

        try:
            #tlv_header = sock.recv(4, socket.MSG_WAITALL)
            tlv_header = relay.recvall(sock, 4)
        except socket.error as (code, msg):
            logger.debug('Exception on receiving tlv_header from remote side. Exiting')
            logger.debug('Errno: {} Msg: {}'.format(errno.errorcode[code], msg))
            sock.close()
            sys.exit(1)
        if len(tlv_header) == 0:
            logger.debug('Recv on tlv header return no data => remote side unexpectedly closed connection')
            raise relay.ClosedSocket('Exception: remote side unexpectedly closed connection')

        tlv_header_len = len(tlv_header)
        if tlv_header_len != 4:
            logger.debug('Unable to receive tlv header. Exiting. Data contents: "{}" Data len: {}'.format(tlv_header, len(tlv_header)))
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
            (channel_id, data) = self.get_channel_data(sock)
        except relay.ClosedSocket:
            logger.debug('Exiting!')
            self.close_remote_connection(sock)

            sys.exit(1)

        if channel_id == relay.COMMAND_CHANNEL:
            self.handle_remote_cmd(data)
        elif channel_id in self.channel:
            relay_to_sock = self.channel[channel_id]
            self.relay(data, relay_to_sock)
        else:
                logger.debug('Relay from socket {} with channel {} not possible. Channel does not exist'.format(sock, channel_id))
                return

    def close_remote_connection(self, sock):
        sock.close()
        self.input_list.remove(sock)

    def manage_forward_socket(self, sock):
        if sock not in self.id_by_socket:
            logger.debug('Channel corresponding to remote socket {} already closed. Closing forward socket'.format(sock))
            return
        channel_id = self.id_by_socket[sock]
        logger.debug('Readable socket {} with channel id {}'.format(sock, channel_id))
        try:
            data = sock.recv(relay.buffer_size)
        except socket.error as (code, msg):
            logger.debug('Exception on receiving data from socket {} with channel id {}'.format(sock, channel_id))
            logger.debug('Errno: {} Msg: {}'.format(errno.errorcode[code], msg))
            logger.debug('Closing socket {} with channel id {}'.format(sock, channel_id))
            self.close_forward_connection(sock)
            return
        data_len = len(data)
        if data_len == 0:
            self.close_forward_connection(sock)
            return
        else:
            channel_id = self.id_by_socket[sock]
            tlv_header = pack('<HH', channel_id, len(data))
            self.relay(tlv_header + data, self.bc_sock)

    def close_forward_connection(self, sock):
        channel_id = self.id_by_socket[sock]
        logger.debug('Closing forward socket {} with id {}'.format(sock, channel_id))
        logger.debug('Current remote side socket: {}'.format(self.bc_sock))
        logger.debug('Notifying remote side')
        self.unset_channel(channel_id)
        self.input_list.remove(sock)
        sock.close()
        self.send_remote_cmd(self.bc_sock, relay.CHANNEL_CLOSE_CMD, channel_id)

    def send_remote_cmd(self, sock, cmd, *args):
        if cmd == relay.CHANNEL_CLOSE_CMD:
            cmd_buffer = cmd + pack('<H', args[0])
            tlv_header = pack('<HH', relay.COMMAND_CHANNEL, len(cmd_buffer))
            sock.send(tlv_header + cmd_buffer)
        elif cmd == relay.FORWARD_CONNECTION_SUCCESS:
            cmd_buffer = cmd + pack('<H', args[0])
            tlv_header = pack('<HH', relay.COMMAND_CHANNEL, len(cmd_buffer))
            sock.send(tlv_header + cmd_buffer)
        elif cmd == relay.FORWARD_CONNECTION_FAILURE:
            cmd_buffer = cmd + pack('<H', args[0])
            tlv_header = pack('<HH', relay.COMMAND_CHANNEL, len(cmd_buffer))
            sock.send(tlv_header + cmd_buffer)
        elif cmd == relay.CLOSE_RELAY:
            cmd_buffer = cmd
            tlv_header = pack('<HH', relay.COMMAND_CHANNEL, len(cmd_buffer))
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
        logger.debug('Adding new pending forward connection with channel id {} and socket {}'.format(channel_id, sock))
        self.establishing_dict[sock] = channel_id


    def relay(self, data, to_socket):
        logger.debug('Got data to relay. Data length: {}'.format(len(data)))
        if to_socket is None:
            return
        to_socket.send(data)


def main():

    # Add the log message handler to the logger
    global logger

    parser = argparse.ArgumentParser(description='Reverse socks client')

    parser.add_argument('--server_ip', required=True, action="store", dest='server_ip')
    parser.add_argument('--server_port', action="store", dest='server_port', default='9999')
    cmd_options = parser.parse_args()

    logger = logging.getLogger('root')
    logger.setLevel(logging.DEBUG)
    ch = logging.StreamHandler()
    ch.setLevel(logging.DEBUG)
    logger.addHandler(ch)

    backconnect_host = cmd_options.server_ip
    backconnect_port = int(cmd_options.server_port)
    bc_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        bc_sock.connect((backconnect_host, backconnect_port))
    except socket.error as (code, msg):
        logger.info('Unable to connect to {} port: {}'.format(cmd_options.server_ip, msg))
        sys.exit(1)
    logger.info('Backconnecting to server {} port {}'.format(cmd_options.server_ip, cmd_options.server_port))
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
