from http.server import HTTPServer, BaseHTTPRequestHandler
import urllib.parse

class FormHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        content_length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(content_length).decode('utf-8')
        params = urllib.parse.parse_qs(body)
        
        user = params.get('username', [''])[0]
        pwd = params.get('password', [''])[0]
        
        self.send_response(200)
        self.end_headers()
        if user == 'admin' and pwd == 'supersecret123':
            self.wfile.write(b"Welcome to your dashboard!")
        else:
            self.wfile.write(b"Login failed: Invalid username or password.")
            
    def log_message(self, format, *args):
        return

if __name__ == '__main__':
    server = HTTPServer(('127.0.0.1', 8080), FormHandler)
    server.serve_forever()
