import http.server
import socketserver

PORT = 8081
class Handler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"Mock Target Active")

with socketserver.TCPServer(("", PORT), Handler) as httpd:
    print(f"Server active on http://127.0.0.1:{PORT}")
    httpd.serve_forever()
