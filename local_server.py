from http.server import HTTPServer, BaseHTTPRequestHandler
import base64

class AuthHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        auth = self.headers.get('Authorization')
        expected = 'Basic ' + base64.b64encode(b'admin:password123').decode()
        if not auth or auth != expected:
            self.send_response(401)
            self.send_header('WWW-Authenticate', 'Basic realm="Secure Area"')
            self.end_headers()
            self.wfile.write(b"Unauthorized")
        else:
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"Welcome Admin!")
    def log_message(self, format, *args):
        return

if __name__ == '__main__':
    server = HTTPServer(('127.0.0.1', 8080), AuthHandler)
    server.serve_forever()
