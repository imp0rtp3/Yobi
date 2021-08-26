from http.server import HTTPServer, BaseHTTPRequestHandler
import ssl
import config
import logging

class SimpleHTTPRequestHandler(BaseHTTPRequestHandler):

    def do_GET(self):
        self.send_response(200)
        self.end_headers()
        self.wfile.write('<h1>Certificate Install Done Succesfully!</h1>'.encode("utf-8"))


logging.getLogger("HTTPServer").setLevel(logging.WARNING)
httpd = HTTPServer(('localhost', config.WS_PORT), SimpleHTTPRequestHandler)

httpd.socket = ssl.wrap_socket (httpd.socket, 
        keyfile=config.WS_KEY, 
        certfile=config.WS_CERT, server_side=True)
httpd.handle_request()
httpd.handle_request()