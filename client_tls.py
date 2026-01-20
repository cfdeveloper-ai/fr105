#!/usr/bin/env python3

import logging
import socket
import sys
import time
from struct import pack, unpack
import select
import optparse
import errno
import relay
import threading
import ssl
import base64

logger = None


def decode_connection_string(cstring):
    """Decode connection string to get IP, port, and SNI."""
    if not cstring.startswith('R105_'):
        raise ValueError('Invalid connection string format')
    encoded = cstring[5:]
    obfuscated = base64.b64decode(encoded)
    key = 0x5A
    plain = bytes([b ^ key for b in obfuscated]).decode()
    parts = plain.split(':')
    if len(parts) == 3:
        return parts[0], int(parts[1]), parts[2]
    elif len(parts) == 2:
        return parts[0], int(parts[1]), 'www.microsoft.com'
    raise ValueError('Invalid connection string data')


class TLSSocket:
    def __init__(self, sock, host, sni='www.microsoft.com', verify=False):
        self._sock = sock
        self.host = host
        self.sni = sni
        self.ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        if not verify:
            self.ctx.check_hostname = False
            self.ctx.verify_mode = ssl.CERT_NONE
        self.ctx.set_ciphers('ECDHE+AESGCM:DHE+AESGCM:ECDHE+CHACHA20:!aNULL:!MD5')
        try:
            self.ctx.set_alpn_protocols(['h2', 'http/1.1'])
        except:
            pass
        self.tls = None
    
    def connect(self, address):
        self._sock.settimeout(30)
        self._sock.connect(address)
        relay.set_keepalive(self._sock)
        self.tls = self.ctx.wrap_socket(self._sock, server_hostname=self.sni)
        self.tls.settimeout(None)
        return self.tls
    
    def send(self, data):
        return relay.safe_send(self.tls, data)
    
    def recv(self, size):
        while True:
            try:
                return self.tls.recv(size)
            except ssl.SSLWantReadError:
                time.sleep(relay.delay)
            except ssl.SSLWantWriteError:
                time.sleep(relay.delay)
    
    def close(self):
        try:
            if self.tls:
                self.tls.close()
        except:
            pass
        try:
            self._sock.close()
        except:
            pass
    
    def fileno(self):
        return self.tls.fileno() if self.tls else self._sock.fileno()
    
    def setblocking(self, flag):
        if self.tls:
            self.tls.setblocking(flag)
    
    def settimeout(self, timeout):
        if self.tls:
            self.tls.settimeout(timeout)
    
    def __getattr__(self, name):
        return getattr(self.tls if self.tls else self._sock, name)


class SocksRelay:
    def __init__(self, sock):
        self.channel = {}
        self.id_by_socket = {}
        self.sock = sock
        self.input_list = [sock]
        self.establishing = {}
        self.last_ping = time.time()
        self.last_pong = time.time()
        self.down = False
        self.lock = threading.Lock()
        threading.Thread(target=self.ping_worker, daemon=True).start()

    def ping_worker(self):
        while not self.down:
            time.sleep(relay.ping_interval)
            if self.down:
                return
            
            now = time.time()
            if now - self.last_pong > relay.relay_timeout:
                logger.warning(f'No PONG received for {relay.relay_timeout}s, reconnecting...')
                try:
                    self.sock.close()
                except:
                    pass
                return
            
            try:
                with self.lock:
                    self.send_cmd(relay.PING_CMD)
                logger.debug('PING sent')
            except Exception as e:
                logger.debug(f'Failed to send PING: {e}')
                return

    def shutdown(self):
        self.down = True
        relay.close_sockets(self.input_list)

    def run(self):
        while not self.down:
            try:
                time.sleep(relay.delay)
                readable, writable, _ = select.select(
                    self.input_list, 
                    list(self.establishing.keys()), 
                    [], 
                    5.0
                )
            except KeyboardInterrupt:
                with self.lock:
                    self.send_cmd(relay.CLOSE_RELAY)
                self.shutdown()
                sys.exit(0)
            except Exception as e:
                logger.debug(f'Select error: {e}')
                self.shutdown()
                return

            for sock in writable:
                channel_id = self.establishing.get(sock)
                if channel_id is None:
                    continue
                try:
                    err = sock.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)
                    if err != 0:
                        raise socket.error(err, 'Connection failed')
                    sock.setblocking(1)
                    with self.lock:
                        self.send_cmd(relay.FORWARD_CONNECTION_SUCCESS, channel_id)
                    del self.establishing[sock]
                    self.input_list.append(sock)
                    self.channel[channel_id] = sock
                    self.id_by_socket[sock] = channel_id
                    logger.debug(f'Channel {channel_id} connected')
                except socket.error as e:
                    logger.debug(f'Channel {channel_id} connection failed: {e}')
                    del self.establishing[sock]
                    with self.lock:
                        self.send_cmd(relay.FORWARD_CONNECTION_FAILURE, channel_id)
                    sock.close()

            for sock in readable:
                if sock == self.sock:
                    try:
                        self.handle_remote()
                    except relay.RelayError as e:
                        logger.debug(f'Remote error: {e}')
                        relay.close_sockets(self.input_list)
                        return
                else:
                    self.handle_forward(sock)

    def handle_remote(self):
        try:
            header = relay.recvall(self.sock, 4, timeout=60)
        except relay.RelayError as e:
            raise
        except Exception as e:
            raise relay.RelayError(f'recv header error: {e}')
        
        if len(header) < 4:
            raise relay.RelayError('short header')
        
        channel_id, length = unpack('<HH', header)
        data = relay.recvall(self.sock, length, timeout=60) if length > 0 else b''
        
        if channel_id == relay.COMMAND_CHANNEL:
            self.handle_cmd(data)
        elif channel_id in self.channel:
            try:
                self.channel[channel_id].sendall(data)
            except Exception as e:
                logger.debug(f'Forward send error: {e}')
                self.close_channel(channel_id)

    def handle_cmd(self, data):
        if not data:
            return
        cmd = data[0:1]
        
        if cmd == relay.CHANNEL_CLOSE_CMD:
            channel_id = unpack('<H', data[1:3])[0]
            self.close_channel(channel_id)
        
        elif cmd == relay.CHANNEL_OPEN_CMD:
            channel_id, _, port = unpack('<HIH', data[1:9])
            ip = socket.inet_ntoa(data[3:7])
            logger.debug(f'Open channel {channel_id} to {ip}:{port}')
            self.establish(channel_id, ip, port)
        
        elif cmd == relay.CHANNEL_OPEN_CMD_DOMAIN:
            channel_id = unpack('<H', data[1:3])[0]
            dlen = data[3]
            domain = data[4:4+dlen].decode()
            port = unpack('<H', data[4+dlen:6+dlen])[0]
            logger.debug(f'Open channel {channel_id} to {domain}:{port}')
            try:
                ip = socket.gethostbyname(domain)
                self.establish(channel_id, ip, port)
            except Exception as e:
                logger.debug(f'DNS resolve failed: {e}')
                with self.lock:
                    self.send_cmd(relay.FORWARD_CONNECTION_FAILURE, channel_id)
        
        elif cmd == relay.CLOSE_RELAY:
            logger.info('Received CLOSE_RELAY')
            relay.close_sockets(self.input_list)
            sys.exit(0)
        
        elif cmd == relay.PING_CMD:
            self.last_ping = time.time()
            with self.lock:
                self.send_cmd(relay.PONG_CMD)
            logger.debug('PING received, PONG sent')
        
        elif cmd == relay.PONG_CMD:
            self.last_pong = time.time()
            logger.debug('PONG received')

    def handle_forward(self, sock):
        try:
            data = sock.recv(relay.buffer_size)
        except Exception as e:
            logger.debug(f'Forward recv error: {e}')
            self.close_forward(sock)
            return
        
        if not data:
            self.close_forward(sock)
            return
        
        channel_id = self.id_by_socket.get(sock)
        if channel_id is None:
            return
        
        try:
            with self.lock:
                relay.safe_send(self.sock, pack('<HH', channel_id, len(data)) + data)
        except relay.RelayError as e:
            raise

    def establish(self, channel_id, host, port):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.setblocking(False)
            relay.set_keepalive(sock)
            err = sock.connect_ex((host, port))
            if err == 0:
                sock.setblocking(True)
                self.input_list.append(sock)
                self.channel[channel_id] = sock
                self.id_by_socket[sock] = channel_id
                with self.lock:
                    self.send_cmd(relay.FORWARD_CONNECTION_SUCCESS, channel_id)
            elif err in (errno.EINPROGRESS, errno.EWOULDBLOCK, 10035, 115, 36):
                self.establishing[sock] = channel_id
            else:
                sock.close()
                with self.lock:
                    self.send_cmd(relay.FORWARD_CONNECTION_FAILURE, channel_id)
        except Exception as e:
            logger.debug(f'Establish error: {e}')
            with self.lock:
                self.send_cmd(relay.FORWARD_CONNECTION_FAILURE, channel_id)

    def close_forward(self, sock):
        channel_id = self.id_by_socket.get(sock)
        if channel_id is None:
            return
        del self.channel[channel_id]
        del self.id_by_socket[sock]
        try:
            sock.close()
        except:
            pass
        if sock in self.input_list:
            self.input_list.remove(sock)
        try:
            with self.lock:
                self.send_cmd(relay.CHANNEL_CLOSE_CMD, channel_id)
        except:
            pass

    def close_channel(self, channel_id):
        sock = self.channel.get(channel_id)
        if sock:
            del self.channel[channel_id]
            self.id_by_socket.pop(sock, None)
            self.establishing.pop(sock, None)
            try:
                sock.close()
            except:
                pass
            if sock in self.input_list:
                self.input_list.remove(sock)

    def send_cmd(self, cmd, *args):
        if cmd == relay.FORWARD_CONNECTION_SUCCESS:
            data = cmd + pack('<H', args[0])
        elif cmd == relay.FORWARD_CONNECTION_FAILURE:
            data = cmd + pack('<H', args[0])
        elif cmd == relay.CHANNEL_CLOSE_CMD:
            data = cmd + pack('<H', args[0])
        elif cmd in (relay.CLOSE_RELAY, relay.PING_CMD, relay.PONG_CMD):
            data = cmd
        else:
            return
        relay.safe_send(self.sock, pack('<HH', relay.COMMAND_CHANNEL, len(data)) + data)


def main():
    global logger
    parser = optparse.OptionParser()
    parser.add_option('--server-ip', dest='server_ip')
    parser.add_option('--server-port', default='443')
    parser.add_option('--verbose', action='store_true', default=False)
    parser.add_option('--logfile', default=None)
    parser.add_option('--tls', action='store_true', default=False)
    parser.add_option('--sni', default='www.microsoft.com')
    parser.add_option('--verify-cert', action='store_true', default=False)
    parser.add_option('--source', default=None)
    parser.add_option('--cString', dest='cstring', default=None, help='Connection string from server')
    opts = parser.parse_args()[0]
    
    if opts.cstring:
        try:
            opts.server_ip, port, opts.sni = decode_connection_string(opts.cstring)
            opts.server_port = str(port)
            opts.tls = True
        except Exception as e:
            print(f'Invalid connection string: {e}')
            sys.exit(1)
    elif not opts.server_ip:
        print('--server-ip or --cString required')
        sys.exit(1)
    
    logger = logging.getLogger('client')
    logger.setLevel(logging.DEBUG)
    ch = logging.FileHandler(opts.logfile) if opts.logfile else logging.StreamHandler()
    ch.setLevel(logging.DEBUG if opts.verbose else logging.INFO)
    ch.setFormatter(logging.Formatter('%(asctime)s [%(levelname)s] %(message)s'))
    logger.addHandler(ch)
    
    host = opts.server_ip
    port = int(opts.server_port)
    reconnect_delay = 5
    
    logger.info(f'R10.5 Client starting - TLS: {opts.tls}, Server: {host}:{port}')
    
    while True:
        sock = None
        try:
            raw = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            if opts.tls:
                sock = TLSSocket(raw, host, opts.sni, opts.verify_cert)
            else:
                sock = raw
                raw.settimeout(30)
            
            logger.info(f'Connecting to {host}:{port}...')
            sock.connect((host, port))
            
            if not opts.tls:
                relay.set_keepalive(raw)
                raw.settimeout(None)
            
            logger.info('Connected, sending banner...')
            sock.send(relay.banner)
            resp = sock.recv(4096)
            
            if resp != relay.banner_response:
                logger.error(f'Invalid banner response: {resp}')
                sock.close()
                time.sleep(reconnect_delay)
                continue
            
            source_name = opts.source or f'client_{host}'
            source_bytes = source_name.encode('utf-8')[:64]
            sock.send(bytes([len(source_bytes)]) + source_bytes)
            logger.info(f'Authenticated (source: {source_name})')
            
            reconnect_delay = 5
            SocksRelay(sock).run()
            
        except KeyboardInterrupt:
            logger.info('Interrupted')
            break
        except Exception as e:
            logger.error(f'Error: {e}')
        finally:
            if sock:
                try:
                    sock.close()
                except:
                    pass
        
        logger.info(f'Reconnecting in {reconnect_delay}s...')
        time.sleep(reconnect_delay)
        reconnect_delay = min(reconnect_delay * 1.5, 60)


if __name__ == '__main__':
    main()
