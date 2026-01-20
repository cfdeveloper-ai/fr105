#!/usr/bin/env python3

import logging
import socket
import select
import sys
import time
from struct import pack, unpack
import random
import relay
import threading
import optparse
import http.server
import socketserver
import html
import ssl
import os
import subprocess
import base64
import urllib.request

client_registry = None


def get_public_ip():
    """Auto-detect public IP using external services."""
    services = [
        'https://ifconfig.me/ip',
        'https://api.ipify.org',
        'https://icanhazip.com',
        'https://checkip.amazonaws.com'
    ]
    for service in services:
        try:
            with urllib.request.urlopen(service, timeout=5) as response:
                return response.read().decode().strip()
        except:
            continue
    return None
connection_string = None


def generate_connection_string(ip, port, sni):
    """Generate obfuscated connection string from IP, port, and SNI."""
    plain = f"{ip}:{port}:{sni}"
    key = 0x5A
    obfuscated = bytes([b ^ key for b in plain.encode()])
    encoded = base64.b64encode(obfuscated).decode()
    return f"R105_{encoded}"


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
logger = None
cmd_options = None


def generate_certificate(cert_file='server.crt', key_file='server.key', domain='www.microsoft.com'):
    if os.path.exists(cert_file) and os.path.exists(key_file):
        return cert_file, key_file
    
    import tempfile
    config_file = os.path.join(tempfile.gettempdir(), 'openssl.cnf')
    config = f"""[req]
default_bits = 2048
prompt = no
default_md = sha256
distinguished_name = dn
x509_extensions = v3_req
[dn]
C = US
ST = Washington
L = Redmond
O = Microsoft Corporation
CN = {domain}
[v3_req]
subjectAltName = DNS:{domain},DNS:localhost
"""
    with open(config_file, 'w') as f:
        f.write(config)
    
    try:
        subprocess.run(['openssl', 'req', '-x509', '-nodes', '-days', '365',
            '-newkey', 'rsa:2048', '-keyout', key_file, '-out', cert_file,
            '-config', config_file], check=True, capture_output=True)
        logger.info(f'Certificate generated: {cert_file}')
    except:
        try:
            from cryptography import x509
            from cryptography.x509.oid import NameOID
            from cryptography.hazmat.primitives import hashes, serialization
            from cryptography.hazmat.primitives.asymmetric import rsa
            from cryptography.hazmat.backends import default_backend
            from datetime import datetime, timedelta, timezone
            key = rsa.generate_private_key(65537, 2048, default_backend())
            subject = issuer = x509.Name([
                x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Microsoft"),
                x509.NameAttribute(NameOID.COMMON_NAME, domain)])
            cert = x509.CertificateBuilder().subject_name(subject).issuer_name(issuer)\
                .public_key(key.public_key()).serial_number(x509.random_serial_number())\
                .not_valid_before(datetime.now(timezone.utc))\
                .not_valid_after(datetime.now(timezone.utc) + timedelta(days=365))\
                .sign(key, hashes.SHA256(), default_backend())
            with open(key_file, 'wb') as f:
                f.write(key.private_bytes(serialization.Encoding.PEM,
                    serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption()))
            with open(cert_file, 'wb') as f:
                f.write(cert.public_bytes(serialization.Encoding.PEM))
            logger.info('Certificate generated using cryptography')
        except Exception as e:
            logger.error(f'Failed to generate certificate: {e}')
            sys.exit(1)
    return cert_file, key_file


FAKE_HTTP_200 = b"HTTP/1.1 200 OK\r\nServer: Microsoft-IIS/10.0\r\nContent-Type: text/html\r\nContent-Length: 150\r\nConnection: close\r\n\r\n<!DOCTYPE html><html><head><title>Microsoft</title></head><body><h1>Welcome</h1></body></html>"
FAKE_HTTP_404 = b"HTTP/1.1 404 Not Found\r\nServer: Microsoft-IIS/10.0\r\nContent-Type: text/html\r\nContent-Length: 100\r\nConnection: close\r\n\r\n<!DOCTYPE html><html><head><title>404</title></head><body><h1>Not Found</h1></body></html>"


class ClientRegistry:
    def __init__(self, server_ip):
        self.clients = {}
        self.sources = {}
        self.lock = threading.Lock()
        self.server_ip = server_ip
    
    def register(self, client_id, proxy_port, client_ip, source=None):
        with self.lock:
            source_name = source if source else f"{''.join(random.choices('abcdefghijklmnopqrstuvwxyz', k=5))}_{client_id}"
            if source_name in self.sources:
                self.sources[source_name]['proxy_port'] = proxy_port
                self.sources[source_name]['client_ip'] = client_ip
                self.sources[source_name]['last_online'] = time.time()
                self.sources[source_name]['client_id'] = client_id
                self.sources[source_name]['is_online'] = True
            else:
                self.sources[source_name] = {
                    'proxy_port': proxy_port,
                    'client_ip': client_ip,
                    'last_online': time.time(),
                    'bytes_up': 0,
                    'bytes_down': 0,
                    'client_id': client_id,
                    'source': source_name,
                    'is_online': True
                }
            self.clients[client_id] = source_name
    
    def unregister(self, client_id):
        with self.lock:
            if client_id in self.clients:
                source_name = self.clients[client_id]
                if source_name in self.sources:
                    self.sources[source_name]['is_online'] = False
                    logger.info(f'Client {client_id} ({source_name}) marked offline')
                del self.clients[client_id]
            else:
                logger.warning(f'Client {client_id} not found in registry')
    
    def update_traffic(self, client_id, bytes_up=0, bytes_down=0):
        with self.lock:
            if client_id in self.clients:
                source_name = self.clients[client_id]
                if source_name in self.sources:
                    self.sources[source_name]['bytes_up'] += bytes_up
                    self.sources[source_name]['bytes_down'] += bytes_down
                    self.sources[source_name]['last_online'] = time.time()
    
    def get_all_clients(self):
        with self.lock:
            return {k: dict(v) for k, v in self.sources.items()}


def format_bytes(size):
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if size < 1024:
            return f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} PB"


class DashboardHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass
    
    def check_auth(self):
        if not cmd_options.web_user:
            return True
        auth_header = self.headers.get('Authorization')
        if not auth_header:
            return False
        try:
            auth_type, credentials = auth_header.split(' ', 1)
            if auth_type.lower() != 'basic':
                return False
            decoded = base64.b64decode(credentials).decode('utf-8')
            username, password = decoded.split(':', 1)
            return username == cmd_options.web_user and password == cmd_options.web_pass
        except:
            return False
    
    def send_auth_required(self):
        self.send_response(401)
        self.send_header('WWW-Authenticate', 'Basic realm="Dashboard"')
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        self.wfile.write(b'<h1>401 Unauthorized</h1>')
    
    def do_GET(self):
        if not self.check_auth():
            self.send_auth_required()
            return
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        clients = client_registry.get_all_clients() if client_registry else {}
        server_ip = client_registry.server_ip if client_registry else '0.0.0.0'
        total_up = sum(c.get('bytes_up', 0) for c in clients.values())
        total_down = sum(c.get('bytes_down', 0) for c in clients.values())
        online_count = sum(1 for c in clients.values() if c.get('is_online'))
        thread_count = threading.active_count()
        try:
            import psutil
            mem_bytes = psutil.Process().memory_info().rss
        except:
            try:
                with open('/proc/self/status') as f:
                    for line in f:
                        if line.startswith('VmRSS:'):
                            mem_bytes = int(line.split()[1]) * 1024
                            break
                    else:
                        mem_bytes = 0
            except:
                mem_bytes = 0
        mem_display = format_bytes(mem_bytes)
        rows = ''
        for cid, info in clients.items():
            addr = f"{server_ip}:{info['proxy_port']}"
            ts = time.strftime('%H:%M:%S', time.localtime(info['last_online']))
            up = format_bytes(info.get('bytes_up', 0))
            down = format_bytes(info.get('bytes_down', 0))
            source = html.escape(info.get('source', cid))
            is_online = info.get('is_online', False)
            status = '<span class="online">Online</span>' if is_online else '<span class="offline">Offline</span>'
            rows += f'<tr><td>{info["proxy_port"]}</td><td>{source}</td><td>{html.escape(info["client_ip"])}</td><td>{status}</td><td class="up">{up}</td><td class="down">{down}</td><td>{ts}</td><td><button onclick="navigator.clipboard.writeText(\'{addr}\')">Copy</button></td></tr>'
        if not rows:
            rows = '<tr><td colspan="8" style="text-align:center;color:#888">No clients</td></tr>'
        demo_usage = f'python client_tls.py --cString={connection_string} --source=EDIT_ME'
        public_ip = cmd_options.public_ip if cmd_options.public_ip else 'N/A'
        cstring_html = f'''<div class="cstring-box">
<div class="cstring-label">Demo Usage (click to select all)</div>
<input type="text" class="usage-input" value="{demo_usage}" onclick="this.select()" readonly>
</div>'''
        html_content = f'''<!DOCTYPE html><html><head><title>R10.5 - {public_ip}</title><meta http-equiv="refresh" content="5">
<style>
*{{box-sizing:border-box}}body{{font-family:'Segoe UI',system-ui,sans-serif;background:#ffffff;color:#1a1a1a;padding:20px;margin:0}}
h1{{color:#f97316;text-align:center;margin-bottom:5px;font-size:2em}}
.stats{{display:flex;justify-content:center;gap:20px;margin:15px 0}}
.stat{{background:#f8f8f8;padding:10px 20px;border-radius:8px;border:1px solid #e5e5e5;box-shadow:0 2px 4px rgba(0,0,0,0.05)}}
.stat-value{{font-size:1.3em;font-weight:bold;color:#1a1a1a}}
.stat-label{{font-size:0.8em;color:#666}}
.cstring-box{{max-width:800px;margin:15px auto;background:#1a1a2e;padding:15px 20px;border-radius:8px;text-align:center}}
.cstring-label{{color:#888;font-size:0.85em;margin-bottom:8px}}
.cstring-value{{display:flex;align-items:center;justify-content:center;gap:10px}}
.cstring-value code{{background:#0d0d1a;color:#22c55e;padding:8px 15px;border-radius:4px;font-family:'Consolas',monospace;font-size:0.9em;word-break:break-all}}
.cstring-value button{{background:#f97316}}
.cstring-value button:hover{{background:#ea580c}}
.usage-input{{width:100%;background:#0d0d1a;color:#22c55e;border:none;padding:10px 15px;border-radius:4px;font-family:'Consolas',monospace;font-size:0.85em;text-align:center;cursor:pointer}}
table{{width:100%;max-width:1200px;margin:20px auto;border-collapse:collapse;background:#fff;border-radius:8px;border:1px solid #e5e5e5;box-shadow:0 2px 8px rgba(0,0,0,0.08)}}
th,td{{padding:12px 10px;text-align:left;border-bottom:1px solid #e5e5e5}}
th{{background:#f97316;color:#fff;font-weight:600}}
tr:hover{{background:#fafafa}}
.up{{color:#22c55e;font-weight:600}}.down{{color:#ef4444;font-weight:600}}
.online{{color:#22c55e;font-weight:600}}.offline{{color:#888}}
button{{background:#22c55e;border:none;color:#fff;padding:6px 12px;cursor:pointer;border-radius:4px;font-weight:500}}
button:hover{{background:#16a34a}}
</style></head><body>
<h1>R10.5 TLS Proxy</h1>
{cstring_html}
<div class="stats">
<div class="stat"><div class="stat-value">{public_ip}</div><div class="stat-label">Port {cmd_options.server_port}</div></div>
<div class="stat"><div class="stat-value">{online_count}/{len(clients)}</div><div class="stat-label">Online</div></div>
<div class="stat"><div class="stat-value up">{format_bytes(total_up)}</div><div class="stat-label">Upload</div></div>
<div class="stat"><div class="stat-value down">{format_bytes(total_down)}</div><div class="stat-label">Download</div></div>
<div class="stat"><div class="stat-value">{mem_display}</div><div class="stat-label">Memory</div></div>
<div class="stat"><div class="stat-value">{thread_count}</div><div class="stat-label">Threads</div></div>
</div>
<table><tr><th>Port</th><th>Source</th><th>IP</th><th>Status</th><th>Up</th><th>Down</th><th>Last</th><th>Action</th></tr>{rows}</table>
</body></html>'''
        self.wfile.write(html_content.encode())


class RelayServer:
    def __init__(self, host, port, socket_with_server, client_id=None):
        self.input_list = [socket_with_server]
        self.channel = {}
        self.last_ping_time = time.time()
        self.last_pong_time = time.time()
        self.id_by_socket = {}
        self.pending_socks_clients = []
        self.socket_with_server = socket_with_server
        self.remote_side_down = False
        self.socks_version_by_socket = {}
        self.client_id = client_id
        self.lock = threading.Lock()
        
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server.bind((host, port))
        self.server.listen(200)
        
        threading.Thread(target=self.ping_worker, daemon=True).start()

    def ping_worker(self):
        while not self.remote_side_down:
            time.sleep(relay.ping_interval)
            if self.remote_side_down:
                return
            
            now = time.time()
            if now - self.last_pong_time > relay.relay_timeout:
                logger.warning(f'Client {self.client_id}: No PONG for {relay.relay_timeout}s')
                try:
                    self.socket_with_server.close()
                except:
                    pass
                return
            
            try:
                with self.lock:
                    self.send_remote_cmd(self.socket_with_server, relay.PING_CMD)
                logger.debug(f'Client {self.client_id}: PING sent')
            except Exception as e:
                logger.debug(f'Client {self.client_id}: PING failed: {e}')
                return

    def shutdown(self):
        self.remote_side_down = True
        relay.close_sockets(self.input_list)
        try:
            self.server.close()
        except:
            pass

    def main_loop(self):
        self.input_list.append(self.server)
        
        while not self.remote_side_down:
            try:
                readable, _, _ = select.select(self.input_list, [], [], 5.0)
            except Exception as e:
                logger.debug(f'Select error: {e}')
                return
            
            for sock in readable:
                if sock == self.server:
                    try:
                        client_sock, addr = self.server.accept()
                        relay.set_keepalive(client_sock)
                        self.input_list.append(client_sock)
                        self.pending_socks_clients.append(client_sock)
                    except:
                        pass
                
                elif sock == self.socket_with_server:
                    try:
                        self.manage_remote_socket(sock)
                    except relay.RelayError as e:
                        logger.debug(f'Remote error: {e}')
                        self.shutdown()
                        return
                
                elif sock in self.pending_socks_clients:
                    self.pending_socks_clients.remove(sock)
                    try:
                        dest, port = self.handle_socks_connection(sock)
                        channel_id = self.set_channel(sock)
                        with self.lock:
                            self.send_remote_cmd(self.socket_with_server, relay.CHANNEL_OPEN_CMD, channel_id, dest, port)
                    except relay.RelayError:
                        self.input_list.remove(sock)
                        sock.close()
                
                elif sock in self.id_by_socket:
                    self.manage_socks_client_socket(sock)

    def handle_socks_connection(self, sock):
        sock.settimeout(10)
        try:
            first_byte = sock.recv(1)
        finally:
            sock.settimeout(None)
        
        if not first_byte:
            raise relay.RelayError('no data')
        
        version = first_byte[0]
        if version == relay.SOCKS4_VERSION:
            data = first_byte + sock.recv(8)
            if len(data) < 9:
                raise relay.RelayError('short socks4')
            _, _, dstport, dstip = unpack('>BBHI', data[:8])
            self.socks_version_by_socket[sock] = 4
            return socket.inet_ntoa(pack(">L", dstip)), dstport
        
        elif version == relay.SOCKS5_VERSION:
            nmethods = sock.recv(1)[0]
            sock.recv(nmethods)
            sock.send(bytes([relay.SOCKS5_VERSION, relay.SOCKS5_AUTH_NONE]))
            request = sock.recv(4)
            if len(request) < 4:
                raise relay.RelayError('short socks5 request')
            _, cmd, _, atyp = request
            if cmd != relay.SOCKS5_CMD_CONNECT:
                sock.send(bytes([5, 7, 0, 1, 0, 0, 0, 0, 0, 0]))
                raise relay.RelayError('unsupported command')
            
            if atyp == relay.SOCKS5_ATYP_IPV4:
                dest = socket.inet_ntoa(sock.recv(4))
                port = unpack('>H', sock.recv(2))[0]
            elif atyp == relay.SOCKS5_ATYP_DOMAIN:
                dlen = sock.recv(1)[0]
                dest = sock.recv(dlen).decode()
                port = unpack('>H', sock.recv(2))[0]
            elif atyp == relay.SOCKS5_ATYP_IPV6:
                sock.send(bytes([5, 8, 0, 1, 0, 0, 0, 0, 0, 0]))
                raise relay.RelayError('ipv6 not supported')
            else:
                raise relay.RelayError('unknown atyp')
            
            self.socks_version_by_socket[sock] = 5
            return dest, port
        
        raise relay.RelayError('unknown version')

    def manage_remote_socket(self, sock):
        try:
            header = relay.recvall(sock, 4, timeout=60)
        except Exception as e:
            raise relay.RelayError(f'recv header: {e}')
        
        if len(header) < 4:
            raise relay.RelayError('short header')
        
        channel_id, length = unpack('<HH', header)
        data = relay.recvall(sock, length, timeout=60) if length > 0 else b''
        
        if channel_id == relay.COMMAND_CHANNEL:
            self.handle_remote_cmd(data)
        elif channel_id in self.channel:
            try:
                self.channel[channel_id].sendall(data)
                if self.client_id and client_registry:
                    client_registry.update_traffic(self.client_id, bytes_down=len(data))
            except:
                pass

    def handle_remote_cmd(self, data):
        if not data:
            return
        cmd = data[0:1]
        
        if cmd == relay.CHANNEL_CLOSE_CMD:
            channel_id = unpack('<H', data[1:3])[0]
            if channel_id in self.channel:
                sock = self.channel[channel_id]
                self.unset_channel(channel_id)
                self.input_list.remove(sock)
                sock.close()
        
        elif cmd == relay.FORWARD_CONNECTION_SUCCESS:
            channel_id = unpack('<H', data[1:3])[0]
            if channel_id in self.channel:
                sock = self.channel[channel_id]
                if self.socks_version_by_socket.get(sock) == 5:
                    sock.send(bytes([5, 0, 0, 1, 0, 0, 0, 0, 0, 0]))
                else:
                    sock.send(relay.socks_server_reply_success)
        
        elif cmd == relay.FORWARD_CONNECTION_FAILURE:
            channel_id = unpack('<H', data[1:3])[0]
            if channel_id in self.channel:
                sock = self.channel[channel_id]
                if self.socks_version_by_socket.get(sock) == 5:
                    sock.send(bytes([5, 5, 0, 1, 0, 0, 0, 0, 0, 0]))
                else:
                    sock.send(relay.socks_server_reply_fail)
                self.unset_channel(channel_id)
                self.input_list.remove(sock)
                sock.close()
        
        elif cmd == relay.PING_CMD:
            self.last_ping_time = time.time()
            with self.lock:
                self.send_remote_cmd(self.socket_with_server, relay.PONG_CMD)
            logger.debug(f'Client {self.client_id}: PING received, PONG sent')
        
        elif cmd == relay.PONG_CMD:
            self.last_pong_time = time.time()
            logger.debug(f'Client {self.client_id}: PONG received')

    def manage_socks_client_socket(self, sock):
        try:
            data = sock.recv(relay.buffer_size)
        except:
            self.close_socks_connection(sock)
            return
        
        if not data:
            self.close_socks_connection(sock)
            return
        
        channel_id = self.id_by_socket.get(sock)
        if channel_id is None:
            return
        
        try:
            with self.lock:
                relay.safe_send(self.socket_with_server, pack('<HH', channel_id, len(data)) + data)
            if self.client_id and client_registry:
                client_registry.update_traffic(self.client_id, bytes_up=len(data))
        except relay.RelayError:
            raise

    def set_channel(self, sock):
        new_id = random.randint(1, 65535)
        while new_id in self.channel:
            new_id = random.randint(1, 65535)
        self.channel[new_id] = sock
        self.id_by_socket[sock] = new_id
        return new_id

    def unset_channel(self, channel_id):
        sock = self.channel.get(channel_id)
        if sock:
            self.id_by_socket.pop(sock, None)
            self.socks_version_by_socket.pop(sock, None)
            del self.channel[channel_id]

    def close_socks_connection(self, sock):
        channel_id = self.id_by_socket.get(sock)
        if channel_id is None:
            return
        self.unset_channel(channel_id)
        if sock in self.input_list:
            self.input_list.remove(sock)
        sock.close()
        try:
            with self.lock:
                self.send_remote_cmd(self.socket_with_server, relay.CHANNEL_CLOSE_CMD, channel_id)
        except:
            pass

    def send_remote_cmd(self, sock, cmd, *args):
        if cmd == relay.CHANNEL_OPEN_CMD:
            channel_id, dest, port = args
            if isinstance(dest, str) and not dest.replace('.', '').isdigit():
                domain_bytes = dest.encode()
                data = relay.CHANNEL_OPEN_CMD_DOMAIN + pack('<H', channel_id) + bytes([len(domain_bytes)]) + domain_bytes + pack('<H', port)
            else:
                data = cmd + pack('<H', channel_id) + socket.inet_aton(dest) + pack('<H', port)
        elif cmd == relay.CHANNEL_CLOSE_CMD:
            data = cmd + pack('<H', args[0])
        elif cmd in (relay.PING_CMD, relay.PONG_CMD):
            data = cmd
        else:
            return
        relay.safe_send(sock, pack('<HH', relay.COMMAND_CHANNEL, len(data)) + data)


class ClientHandler(threading.Thread):
    def __init__(self, proxy_ip, proxy_port, client_sock, client_id, on_disconnect):
        super().__init__(daemon=True)
        self.proxy_ip = proxy_ip
        self.proxy_port = proxy_port
        self.client_sock = client_sock
        self.client_id = client_id
        self.on_disconnect = on_disconnect

    def run(self):
        try:
            RelayServer(self.proxy_ip, self.proxy_port, self.client_sock, self.client_id).main_loop()
        except Exception as e:
            logger.debug(f'Client {self.client_id} error: {e}')
        finally:
            logger.info(f'Client {self.client_id} disconnected')
            self.on_disconnect(self.proxy_port, self.client_id)


def run_server(host, port, use_tls=False, cert_file=None, key_file=None, sni_domain='www.microsoft.com'):
    global client_registry, cmd_options
    base_port = int(cmd_options.proxy_port)
    active_ports = set()
    reserved_ports = {}  # (source, ip) -> port
    next_client_id = 1
    lock = threading.Lock()

    def get_port(source_name, client_ip):
        nonlocal next_client_id
        with lock:
            client_key = (source_name or '', client_ip)
            if client_key in reserved_ports:
                p = reserved_ports[client_key]
                logger.info(f'Reassigning reserved port {p} to {client_key}')
            else:
                p = base_port
                while p in active_ports or p in reserved_ports.values():
                    p += 1
                reserved_ports[client_key] = p
                logger.info(f'Reserving new port {p} for {client_key}')
            active_ports.add(p)
            cid = next_client_id
            next_client_id += 1
            return p, cid

    def release_port(p, cid):
        with lock:
            active_ports.discard(p)
        client_registry.unregister(cid)

    serversock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    serversock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    serversock.bind((host, port))
    serversock.listen(50)
    
    ssl_context = None
    if use_tls:
        generate_certificate(cert_file, key_file, sni_domain)
        ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ssl_context.load_cert_chain(cert_file, key_file)
        ssl_context.set_ciphers('ECDHE+AESGCM:DHE+AESGCM:ECDHE+CHACHA20:!aNULL:!MD5')
    
    logger.info(f'R10.5 {"TLS " if use_tls else ""}Server on {host}:{port}')

    while True:
        try:
            client_sock, addr = serversock.accept()
            relay.set_keepalive(client_sock)
            
            if use_tls:
                try:
                    client_sock.settimeout(30)
                    client_sock = ssl_context.wrap_socket(client_sock, server_side=True)
                    client_sock.settimeout(None)
                except ssl.SSLError as e:
                    logger.debug(f'TLS handshake failed from {addr}: {e}')
                    try:
                        client_sock.send(FAKE_HTTP_404)
                    except:
                        pass
                    client_sock.close()
                    continue
            
            try:
                client_sock.settimeout(30)
                banner = client_sock.recv(4096)
                if banner != relay.banner:
                    logger.debug(f'Invalid banner from {addr}')
                    client_sock.send(FAKE_HTTP_200)
                    client_sock.close()
                    continue
                client_sock.send(relay.banner_response)
                
                source_len_data = client_sock.recv(1)
                source_name = None
                if source_len_data:
                    source_len = source_len_data[0]
                    source_name = client_sock.recv(source_len).decode('utf-8', errors='ignore')
                client_sock.settimeout(None)
            except Exception as e:
                logger.debug(f'Banner exchange failed: {e}')
                client_sock.close()
                continue

            proxy_port, client_id = get_port(source_name, addr[0])
            client_registry.register(client_id, proxy_port, addr[0], source_name)
            logger.info(f'Client {client_id} ({source_name or "unknown"}) from {addr[0]} -> port {proxy_port}')
            ClientHandler(cmd_options.proxy_ip, proxy_port, client_sock, client_id, release_port).start()

        except KeyboardInterrupt:
            logger.info('Shutting down...')
            break
        except Exception as e:
            logger.debug(f'Accept error: {e}')
    
    serversock.close()


def main():
    global logger, cmd_options, client_registry
    parser = optparse.OptionParser()
    parser.add_option('--server-ip', default='0.0.0.0')
    parser.add_option('--server-port', default='443')
    parser.add_option('--proxy-ip', default='0.0.0.0')
    parser.add_option('--proxy-port', default='5555')
    parser.add_option('--verbose', action='store_true', default=False)
    parser.add_option('--logfile', default=None)
    parser.add_option('--web-port', default='1357')
    parser.add_option('--tls', action='store_true', default=True)
    parser.add_option('--cert', default='server.crt')
    parser.add_option('--key', default='server.key')
    parser.add_option('--sni', default='www.microsoft.com')
    parser.add_option('--web-user', default='goku')
    parser.add_option('--web-pass', default=None)
    parser.add_option('--public-ip', default=None, help='Public IP for connection string generation')
    cmd_options = parser.parse_args()[0]
    
    logger = logging.getLogger('server')
    logger.setLevel(logging.DEBUG)
    ch = logging.FileHandler(cmd_options.logfile) if cmd_options.logfile else logging.StreamHandler()
    ch.setLevel(logging.DEBUG if cmd_options.verbose else logging.INFO)
    ch.setFormatter(logging.Formatter('%(asctime)s [%(levelname)s] %(message)s'))
    logger.addHandler(ch)
    
    client_registry = ClientRegistry(cmd_options.proxy_ip)
    
    if not cmd_options.web_pass:
        cmd_options.web_pass = ''.join(random.choices('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789', k=12))
    
    class ThreadedHTTPServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
        daemon_threads = True
    
    web_server = ThreadedHTTPServer(('0.0.0.0', int(cmd_options.web_port)), DashboardHandler)
    threading.Thread(target=web_server.serve_forever, daemon=True).start()
    
    if not cmd_options.public_ip:
        logger.info('Auto-detecting public IP...')
        cmd_options.public_ip = get_public_ip()
        if cmd_options.public_ip:
            logger.info(f'Auto-detected public IP: {cmd_options.public_ip}')
        else:
            logger.warning('Could not auto-detect public IP')

    dashboard_ip = cmd_options.public_ip if cmd_options.public_ip else '0.0.0.0'
    dashboard_url = f'http://{cmd_options.web_user}:{cmd_options.web_pass}@{dashboard_ip}:{cmd_options.web_port}/'
    logger.info(f'Dashboard: {dashboard_url}')
    # print(f'============= DASHBOARD =============\n{dashboard_url}\n=================')

    if cmd_options.public_ip:
        global connection_string
        connection_string = generate_connection_string(cmd_options.public_ip, cmd_options.server_port, cmd_options.sni)
        logger.info(f'Connection String: --cString={connection_string}')
        # print(f'\n=== CONNECTION STRING ===\n{connection_string}\n=========================')
        # print(f'Client usage: python client_tls.py --cString={connection_string}')
    
    run_server(cmd_options.server_ip, int(cmd_options.server_port), cmd_options.tls, cmd_options.cert, cmd_options.key, cmd_options.sni)


if __name__ == '__main__':
    main()
