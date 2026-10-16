#HTTP: mini API

import json
from urllib.parse import urlparse, parse_qs
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

notes_db = {}
next_id = 1

class SimpleHTTPRequestHandler(BaseHTTPRequestHandler):
    def _send_json(self, status_code, payload):
        self.send_response(status_code)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        self.wfile.write(json.dumps(payload).encode('utf-8'))

    def _send_empty(self, status_code):
        self.send_response(status_code)
        self.end_headers()

    def do_GET(self):
        parsed_url = urlparse(self.path)
        path = parsed_url.path

        if path == '/':
            self.send_response(200)
            self.send_header('Content-type', 'text/plain')
            self.end_headers()
            self.wfile.write(b"200 OK\n")

        elif path == '/echo':
            query_params = parse_qs(parsed_url.query)
            msg = query_params.get('msg', [''])[0]
            self._send_json(200, {"msg": msg})

        elif path.startswith('/notes/'):
            id_str = path[len('/notes/'):]
            if not id_str.isdigit():
                self._send_empty(404)
                return

            note_id = int(id_str)
            if note_id in notes_db:
                self._send_json(200, {"id": note_id, "text": notes_db[note_id]})
            else:
                self._send_empty(404)

        elif path == '/notes':
            self._send_empty(405)
        else:
            self._send_empty(404)

    def do_POST(self):
        parsed_url = urlparse(self.path)
        path = parsed_url.path

        if path == '/notes':
            if self.headers.get('Content-Type') != 'application/json':
                self._send_empty(415)
                return

            content_length = int(self.headers.get('Content-Length', 0))
            body = self.rfile.read(content_length)

            try:
                data = json.loads(body)
            except json.JSONDecodeError:
                self._send_empty(400)
                return

            if 'text' not in data or not isinstance(data['text'], str):
                self._send_empty(400)
                return

            global next_id
            note_id = next_id
            next_id += 1
            notes_db[note_id] = data['text']

            self._send_json(201, {"id": note_id})
        else:
            self._send_empty(404)

    def do_DELETE(self):
        parsed_url = urlparse(self.path)
        path = parsed_url.path

        if path.startswith('/notes/'):
            id_str = path[len('/notes/'):]
            if not id_str.isdigit():
                self._send_empty(404)
                return

            note_id = int(id_str)
            if note_id in notes_db:
                del notes_db[note_id]
                self._send_empty(204)
            else:
                self._send_empty(404)
        elif path == '/notes':
            self._send_empty(405)
        else:
            self._send_empty(404)

    def do_PUT(self):
        # Gestisce i metodi non supportati sulla risorsa /notes come richiesto
        if self.path == '/notes' or self.path.startswith('/notes/'):
            self._send_empty(405)
        else:
            self._send_empty(404)


if __name__ == '__main__':
    server_address = ('0.0.0.0', 8080)
    httpd = ThreadingHTTPServer(server_address, SimpleHTTPRequestHandler)
    httpd.serve_forever()