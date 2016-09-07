import logging
import logging.handlers
import socket
import sys
import time
from struct import pack, unpack
import select
import argparse
import errno
import relay
import threading

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
        self.last_ping_time = time.time()

        logger.debug('Starting ping thread')


        self.ping_thread = threading.Thread(target=self.ping_worker)

        self.ping_thread.start()
        self.remote_side_down = False

    def ping_worker(self):
        while True:
            time.sleep(10)
            current_time = time.time()
            logger.debug('In ping worker')
            if self.remote_side_down:
                logger.debug('Remote side down. Exiting ping worker')
                return
            if current_time - self.last_ping_time > relay.relay_timeout:
                logger.info('No response from remote side for {} seconds. Restarting relay'.format(relay.relay_timeout))
                self.bc_sock.close()
                return

    def shutdown(self):
        self.remote_side_down = True
        relay.close_sockets(self.input_list)
        sys.exit(1)

    def run(self):
        inputready = None
        outputready = None
        exceptready = None
        while True:

            try:
                time.sleep(relay.delay)
                logger.debug("Active channels: {}. Pending Channels {}".format(self.channel.keys(), self.establishing_dict.values()))
                inputready, outputready, exceptready = select.select(self.input_list, self.establishing_dict.keys(), [], 15)
            except KeyboardInterrupt:
                logger.info('SIGINT received. Closing relay and exiting')
                self.send_remote_cmd(self.bc_sock, relay.CLOSE_RELAY)
                self.shutdown()
            except select.error as (code, msg):
                logger.debug('Select error on select. Errno: {} Msg: {}'.format(errno.errorcode[code], msg))
                self.shutdown()
            except socket.error as (code, msg):
                logger.debug('Socket error on select. Errno: {} Msg: {}'.format(errno.errorcode[code], msg))
                self.shutdown()

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

                        self.send_remote_cmd(self.bc_sock, relay.FORWARD_CONNECTION_FAILURE, channel_id)
                        sock.close()
                        continue
                    elif code == errno.EAGAIN:
                        logger.debug('Recv(0) return errno.EAGAIN for socket {} on channel {}. Connection established.'.format(sock, channel_id))
                    elif code == 10035:
                        logger.debug('Recv(0) raised windows-specific exception 10035. Connection established.')
                    else:
                        raise

                logger.debug('Connection established on channel {}'.format(channel_id))
                sock.setblocking(1)

                self.send_remote_cmd(self.bc_sock, relay.FORWARD_CONNECTION_SUCCESS, self.establishing_dict[sock])
                del self.establishing_dict[sock]
                self.input_list.append(sock)
                self.set_channel(sock, channel_id)

            for self.selected_input_socket in inputready:
                if self.selected_input_socket == self.bc_sock:
                    try:
                        self.manage_remote_socket(self.bc_sock)
                    except relay.RelayError:
                        logger.debug('Remote side closed socket')
                        relay.close_sockets(self.input_list)
                        return
                else:
                    self.manage_forward_socket(self.selected_input_socket)

    def handle_remote_cmd(self, data):
        cmd = data[0]
        logger.debug('Received cmd data from remote side. Cmd: {}'.format(relay.cmd_names[cmd]))
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
            self.shutdown()
        elif cmd == relay.PING_CMD:
            self.last_ping_time = time.time()
            self.send_remote_cmd(self.bc_sock, relay.PING_CMD)
        else:
            logger.debug('Received unknown cmd: {}'.format(cmd))

    def get_channel_data(self, sock):
        try:
            tlv_header = relay.recvall(sock, 4)
            channel_id, tlv_data_len = unpack('<HH', tlv_header)
            data = relay.recvall(sock, tlv_data_len)
        except socket.error as (code, msg):
            logger.debug('Exception on receiving tlv message from remote side. Exiting')
            logger.debug('Errno: {} Msg: {}'.format(errno.errorcode[code], msg))
            raise relay.RelayError

        return channel_id, data

    def manage_remote_socket(self, sock):
        try:
            (channel_id, data) = self.get_channel_data(sock)
        except relay.RelayError:
            logger.debug('Exiting!')
            self.close_remote_connection(sock)
            raise relay.RelayError

        if channel_id == relay.COMMAND_CHANNEL:
            self.handle_remote_cmd(data)
        elif channel_id in self.channel:
            relay_to_sock = self.channel[channel_id]
            logger.debug('Got data to relay from remote side. Channel id {}. Data length: {}'.format(channel_id, len(data)))
            logger.debug('Data contents: {}'.format(data.encode('hex')))
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
        #logger.debug('Readable socket {} with channel id {}'.format(sock, channel_id))
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
            logger.debug('Got data to relay from app side. Channel id {}. Data length: {}'.format(channel_id, len(data)))
            logger.debug('Preparing tlv header: {}'.format(tlv_header.encode('hex')))
            logger.debug('Data contents: {}'.format(data.encode('hex')))
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
        logger.debug('Sending cmd to remote side. Cmd: {}'.format(relay.cmd_names[cmd]))
        if cmd == relay.CHANNEL_CLOSE_CMD:
            cmd_buffer = cmd + pack('<H', args[0])
            tlv_header = pack('<HH', relay.COMMAND_CHANNEL, len(cmd_buffer))
        elif cmd == relay.FORWARD_CONNECTION_SUCCESS:
            cmd_buffer = cmd + pack('<H', args[0])
            tlv_header = pack('<HH', relay.COMMAND_CHANNEL, len(cmd_buffer))
        elif cmd == relay.FORWARD_CONNECTION_FAILURE:
            cmd_buffer = cmd + pack('<H', args[0])
            tlv_header = pack('<HH', relay.COMMAND_CHANNEL, len(cmd_buffer))
        else:
            cmd_buffer = cmd
            tlv_header = pack('<HH', relay.COMMAND_CHANNEL, len(cmd_buffer))
        try:
            sock.send(tlv_header + cmd_buffer)
        except socket.error as (code, cmd):
            logger.error('Socket error on sending command to remote side. Code {}. Msg {}'.format(code, cmd))

    def set_channel(self, sock, channel_id):
        self.channel[channel_id] = sock
        self.id_by_socket[sock] = channel_id

    def unset_channel(self, channel_id):
        sock = self.channel[channel_id]
        del self.id_by_socket[sock]
        del self.channel[channel_id]

    def establish_forward_socket(self, channel_id, host, port):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.setblocking(0)
            sock.connect_ex((host, port))
        except socket.error as (code, msg):
            logger.debug("Caught exception socket.error during establishing forward connection. Code {}. Msg {}".format(code, msg))
            self.send_remote_cmd(self.bc_sock, relay.FORWARD_CONNECTION_FAILURE, channel_id)
            return
        logger.debug('Adding new pending forward connection with channel id {} and socket {}'.format(channel_id, sock))
        self.establishing_dict[sock] = channel_id

    def relay(self, data, to_socket):
        if to_socket is None:
            return
        try:
            to_socket.send(data)
        except socket.error as (code, msg):
            logger.debug('Exception on relaying data to socket {}'.format(to_socket))
            logger.debug('Errno: {} Msg: {}'.format(errno.errorcode[code], msg))
            if to_socket == self.bc_sock:
                raise relay.RelayError
            else:
                logger.debug('Closing socket')
                to_socket.close()
                self.input_list.remove(to_socket)
                channel_id = self.id_by_socket[to_socket]
                self.unset_channel(channel_id)
                self.send_remote_cmd(self.socket_with_server, relay.CHANNEL_CLOSE_CMD, channel_id)


def main():
    global logger

    parser = argparse.ArgumentParser(description='Reverse socks client')
    parser.add_argument('--server-ip', required=True, action="store", dest='server_ip')
    parser.add_argument('--server-port', action="store", dest='server_port', default='9999')
    parser.add_argument('--verbose', action="store_true", dest="verbose", default=False)
    parser.add_argument('--logfile', action="store", dest="logfile", default=None)
    cmd_options = parser.parse_args()

    logger = logging.getLogger('root')
    logger.setLevel(logging.DEBUG)

    if cmd_options.logfile is None:
        ch = logging.StreamHandler()
    else:
        ch = logging.FileHandler(cmd_options.logfile)

    if cmd_options.verbose:
        ch.setLevel(logging.DEBUG)
    else:
        ch.setLevel(logging.INFO)
    logger.addHandler(ch)
    logger.addHandler(ch)
    while True:
        logger.info('Backconnecting to server {} port {}'.format(cmd_options.server_ip, cmd_options.server_port))
        backconnect_host = cmd_options.server_ip
        backconnect_port = int(cmd_options.server_port)
        bc_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        while True:

            try:
                bc_sock.connect((backconnect_host, backconnect_port))
                break
            except socket.error as (code, msg):
                logger.info('Unable to connect to {} port: {}'.format(cmd_options.server_ip, msg))
                logger.info('Retrying')
                time.sleep(5)

        socks_relayer = SocksRelay(bc_sock)
        socks_relayer.run()
        time.sleep(10)

if __name__ == '__main__':
    main()
