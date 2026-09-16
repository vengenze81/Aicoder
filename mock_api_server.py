from http.server import HTTPServer, BaseHTTPRequestHandler

class APITokenHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        auth_header = self.headers.get('Authorization', '')
        
        if auth_header == 'Bearer secret_api_token_123':
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(b'{"status": "success", "message": "Access granted to secure API"}')
        else:
            self.send_response(401)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(b'{"status": "error", "message": "Unauthorized token"}')

    def log_message(self, format, *args):
        return

if __name__ == '__main__':
    server = HTTPServer(('127.0.0.1', 8090), APITokenHandler)
    server.serve_forever()
