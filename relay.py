#!/usr/bin/env python3

import time
import socket
import ssl

buffer_size = 8192
delay = 0.001
socks_server_reply_success = b'\x00\x5a\xff\xff\xff\xff\xff\xff'
socks_server_reply_fail = b'\x00\x5b\xff\xff\xff\xff\xff\xff'
relay_timeout = 120
ping_interval = 15
banner = b'R10V4SEC'
banner_response = b'R10V4OK!'

COMMAND_CHANNEL = 0

CHANNEL_CLOSE_CMD = b'\xcc'
CHANNEL_OPEN_CMD = b'\xdd'
CHANNEL_OPEN_CMD_DOMAIN = b'\xde'
FORWARD_CONNECTION_SUCCESS = b'\xee'
FORWARD_CONNECTION_FAILURE = b'\xff'
CLOSE_RELAY = b'\xc4'
PING_CMD = b'\x70'
PONG_CMD = b'\x71'

SOCKS4_VERSION = 4
SOCKS5_VERSION = 5

SOCKS5_AUTH_NONE = 0x00
SOCKS5_AUTH_NO_ACCEPTABLE = 0xFF

SOCKS5_CMD_CONNECT = 0x01

SOCKS5_ATYP_IPV4 = 0x01
SOCKS5_ATYP_DOMAIN = 0x03
SOCKS5_ATYP_IPV6 = 0x04


class RelayError(Exception):
    pass


def set_keepalive(sock, after_idle=30, interval=10, max_fails=5):
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        if hasattr(socket, 'TCP_KEEPIDLE'):
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, after_idle)
        if hasattr(socket, 'TCP_KEEPINTVL'):
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, interval)
        if hasattr(socket, 'TCP_KEEPCNT'):
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, max_fails)
    except:
        pass


def recvall(sock, data_len, timeout=30):
    buf = b''
    start = time.time()
    retries = 0
    max_retries = 100
    
    while len(buf) < data_len:
        if time.time() - start > timeout:
            raise RelayError("recvall timeout")
        
        try:
            chunk = sock.recv(data_len - len(buf))
            if chunk:
                buf += chunk
                retries = 0
            else:
                retries += 1
                if retries > max_retries:
                    raise RelayError("connection closed")
                time.sleep(delay)
        except ssl.SSLWantReadError:
            time.sleep(delay)
        except ssl.SSLWantWriteError:
            time.sleep(delay)
        except socket.timeout:
            time.sleep(delay)
        except (socket.error, OSError) as e:
            if e.errno in (11, 35, 10035):
                time.sleep(delay)
            else:
                raise RelayError(f"socket error: {e}")
    
    return buf


def safe_send(sock, data):
    total = 0
    while total < len(data):
        try:
            sent = sock.send(data[total:])
            if sent == 0:
                raise RelayError("connection closed on send")
            total += sent
        except ssl.SSLWantWriteError:
            time.sleep(delay)
        except ssl.SSLWantReadError:
            time.sleep(delay)
        except socket.timeout:
            time.sleep(delay)
        except (socket.error, OSError) as e:
            if e.errno in (11, 35, 10035):
                time.sleep(delay)
            else:
                raise RelayError(f"send error: {e}")
    return total


def close_sockets(sockets):
    for s in sockets:
        try:
            s.close()
        except:
            pass
