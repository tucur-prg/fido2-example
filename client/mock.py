import os
import sys
import urllib.parse
import html

import jwt
import json
import time

from http.server import BaseHTTPRequestHandler, SimpleHTTPRequestHandler
from http.server import HTTPServer
from http import HTTPStatus

class StubHttpRequestHandler(BaseHTTPRequestHandler):
    server_version = "HTTP Stub/0.1"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def do_GET(self):
        enc = sys.getfilesystemencoding()

        paths = self.path.split('?')

        file = '.' + paths[0]
        if os.path.isfile(file) == False:
            self.send_response(HTTPStatus.NOT_FOUND)
            self.send_header("Content-type", "text/html; charset=%s" % enc)
            self.end_headers()
            return

        with open(file) as f:
            r = f.read()

        if len(paths) > 1:
            params = dict(list(map(lambda x: x.split('='), paths[1].split('&'))))
            if 'nonce' in params:
                with open('./.tmp/1234.txt', mode='w') as f:
                    f.write(params['nonce'])

        encoded = r.encode(enc, 'surrogateescape')

        self.send_response(HTTPStatus.OK)
        self.send_header("Content-type", "text/html; charset=%s" % enc)
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()

        self.wfile.write(encoded)

    def do_POST(self):
        enc = sys.getfilesystemencoding()

        file = '.' + self.path
        if os.path.isfile(file) == False:
            self.send_response(HTTPStatus.NOT_FOUND)
            self.send_header("Content-type", "text/html; charset=%s" % enc)
            self.end_headers()
            return

        with open('./.tmp/1234.txt') as f:
            nonce = f.read()

        iat = int(time.time())

        id_token = jwt.encode(
            payload={
                "iss": "http://localhost/mock-app-auth/",
                "sub": "dummy",
                "aud": ["app-auth"],
                "exp": iat + 600,
                "iat": iat,
                "nonce": nonce
            },
            key='my_secret'
        )

        data = {
            "access_token": "dummy.access_token",
            "expires_in": 60,
            "id_token": id_token,
            "refresh_expires_in": 1800,
            "refresh_token": "dummy.refresh_token",
            "scope": "openid",
            "token_type": "Bearer",
        }
        r = json.dumps(data)

        encoded = r.encode(enc)

        self.send_response(HTTPStatus.OK)
        self.send_header("Content-type", "text/plain; charset=%s" % enc)
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()

        self.wfile.write(encoded)

handler = StubHttpRequestHandler

httpd = HTTPServer(('',80), handler)
httpd.serve_forever()
