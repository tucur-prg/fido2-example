from http.server import HTTPServer, SimpleHTTPRequestHandler

import ssl

httpd = HTTPServer(('', 443), SimpleHTTPRequestHandler)
httpd.socket = ssl.wrap_socket(
  httpd.socket,
  keyfile="./cert/private.key",
  certfile='./cert/server.crt',
  server_side=True)
httpd.serve_forever()
