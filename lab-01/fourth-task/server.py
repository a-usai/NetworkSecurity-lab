#HTTP/3: QUIC
import os
import hashlib
import asyncio
from hypercorn.config import Config
from hypercorn.asyncio import serve


async def app(scope, receive, send):
    if scope['type'] != 'http':
        return

    path = scope['path']
    method = scope['method']
    version = str(scope.get('http_version', '1.1'))

    if method == 'GET' and path == '/':
        headers = [(b'content-type', b'text/plain')]
        if version in ('1.0', '1.1', '2'):
            headers.append((b'alt-svc', b'h3=":4433"'))

        await send({'type': 'http.response.start', 'status': 200, 'headers': headers})
        await send({'type': 'http.response.body', 'body': b'200 OK'})


    elif method == 'GET' and path == '/proto':

        if version in ('3', 'h3'):

            body = b'HTTP/3'

        elif version == '2':

            body = b'HTTP/2'

        else:

            body = b'HTTP/1.1'

        await send({'type': 'http.response.start', 'status': 200, 'headers': [(b'content-type', b'text/plain')]})

        await send({'type': 'http.response.body', 'body': body})

    elif method == 'POST' and path == '/hash':
        body = b''
        more_body = True
        while more_body:
            msg = await receive()
            body += msg.get('body', b'')
            more_body = msg.get('more_body', False)

        sha256_hash = hashlib.sha256(body).hexdigest().encode('utf-8')
        await send({'type': 'http.response.start', 'status': 200, 'headers': [(b'content-type', b'text/plain')]})
        await send({'type': 'http.response.body', 'body': sha256_hash})

    else:
        await send({'type': 'http.response.start', 'status': 404, 'headers': []})
        await send({'type': 'http.response.body', 'body': b''})


if __name__ == '__main__':
    base_dir = os.path.dirname(os.path.abspath(__file__))

    config = Config()
    config.bind = ["0.0.0.0:4433"]
    config.quic_bind = ["0.0.0.0:4433"]
    config.certfile = os.path.join(base_dir, "server.crt")
    config.keyfile = os.path.join(base_dir, "server.key")
    config.alpn_protocols = ["h3", "h2", "http/1.1"]

    asyncio.run(serve(app, config))