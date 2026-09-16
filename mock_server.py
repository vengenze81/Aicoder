import http.server
import urllib.parse
import socketserver

PORT = 8080

class ThreadingHTTPServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True

class MockAuthHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-type", "text/html")
        self.end_headers()
        self.wfile.write(b'''
            <html>
                <body>
                    <h2>Mock Login</h2>
                    <form method="POST">
                        <input type="text" name="username" />
                        <input type="password" name="password" />
                        <input type="hidden" name="csrf_token" value="abc123xyz" />
                        <input type="submit" value="Login" />
                    </form>
                </body>
            </html>
        ''')

    def do_POST(self):
        content_length = int(self.headers.get('Content-Length', 0))
        # FIXED: Use rfile for reading request body data
        post_data = self.rfile.read(content_length).decode('utf-8')
        params = urllib.parse.parse_qs(post_data)
        
        user = params.get('username', [''])[0]
        pwd = params.get('password', [''])[0]

        self.send_response(200)
        self.send_header("Content-type", "text/html")
        self.end_headers()

        if user == "admin" and pwd == "supersecret2026!":
            self.wfile.write(b"Welcome back, admin! Login successful.")
        else:
            self.wfile.write(b"Invalid username or password. Too many attempts will lock your account.")

    def log_message(self, format, *args):
        return

if __name__ == "__main__":
    with ThreadingHTTPServer(("", PORT), MockAuthHandler) as httpd:
        print(f"[*] Threaded Mock authentication server running on http://127.0.0.1:{PORT}")
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\n[*] Shutting down mock server.")
