#HTTPS: TLS, session and mTLS
import json
import os
import ssl
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sessions = {}

class TLSHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/':
            self.send_response(200)
            self.end_headers()
        elif self.path == '/me':
            cookie_header = self.headers.get('Cookie', '')
            session_id = None
            for cookie in cookie_header.split(';'):
                if 'session_id=' in cookie:
                    session_id = cookie.split('=')[1].strip()

            if session_id and session_id in sessions:
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps({"user": sessions[session_id]}).encode())
            else:
                self.send_response(401)
                self.end_headers()
        else:
            self.send_response(404)
            self.end_headers()

    def do_POST(self):
        if self.path == '/login':
            try:
                length = int(self.headers.get('Content-Length', 0))
                body = json.loads(self.rfile.read(length))
                if body.get('password') == 'netsec':
                    session_id = os.urandom(16).hex()
                    sessions[session_id] = body.get('user')

                    self.send_response(200)
                    self.send_header('Set-Cookie', f'session_id={session_id}; Secure; HttpOnly')
                    self.end_headers()
                else:
                    self.send_response(401)
                    self.end_headers()
            except json.JSONDecodeError:
                self.send_response(400)
                self.end_headers()
        else:
            self.send_response(404)
            self.end_headers()


class mTLSHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/whoami':
            cert = self.connection.getpeercert()
            cn = "UNKNOWN"
            if cert:
                for sub in cert.get('subject', ()):
                    for key, value in sub:
                        if key == 'commonName':
                            cn = value

            self.send_response(200)
            self.send_header('Content-Type', 'text/plain')
            self.end_headers()
            self.wfile.write(cn.encode('utf-8'))
        else:
            self.send_response(404)
            self.end_headers()


def start_tls_server():
    httpd = ThreadingHTTPServer(('0.0.0.0', 8443), TLSHandler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile='server.crt', keyfile='server.key')
    httpd.socket = context.wrap_socket(httpd.socket, server_side=True)
    httpd.serve_forever()


def start_mtls_server():
    httpd = ThreadingHTTPServer(('0.0.0.0', 8444), mTLSHandler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile='server.crt', keyfile='server.key')

    context.verify_mode = ssl.CERT_REQUIRED
    context.load_verify_locations(cafile='ca.crt')

    httpd.socket = context.wrap_socket(httpd.socket, server_side=True)
    httpd.serve_forever()


if __name__ == '__main__':
    threading.Thread(target=start_tls_server, daemon=True).start()
    start_mtls_server()