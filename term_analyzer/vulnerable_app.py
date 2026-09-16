import http.server
import socketserver
import urllib.parse

PORT = 8080

class VulnerableHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        parsed_path = urllib.parse.urlparse(self.path)
        path = parsed_path.path
        query = urllib.parse.parse_qs(parsed_path.query)

        if path == "/" or path == "/index.php":
            self.send_response(200)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            self.wfile.write(b"""
                <html><body>
                    <h1>Welcome to Local DVWA Clone</h1>
                    <p>Secret: AKIAIOSFODNN7EXAMPLE</p>
                    <ul>
                        <li><a href="/vulnerabilities/sqli/?id=1">SQLi Vulnerability Page</a></li>
                        <li><a href="/admin/config.php">Admin Configuration</a></li>
                    </ul>
                </body></html>
            """)
        
        elif path == "/vulnerabilities/sqli/":
            id_param = query.get("id", [""])[0]
            self.send_response(200)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            if "'" in id_param or "OR" in id_param.upper():
                response = f"<html><body><h3>Database Error!</h3><p>Syntax near '{id_param}'</p><p>FLAG{{sql_injection_success}}</p></body></html>"
            else:
                response = f"<html><body><h3>User ID: {id_param}</h3><p><a href='/'>Back Home</a></p></body></html>"
            self.wfile.write(response.encode())
            
        elif path == "/admin/config.php":
            self.send_response(200)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            self.wfile.write(b"<html><body><h3>Admin Configuration</h3><p>db_user='root'</p><p><a href='/'>Back Home</a></p></body></html>")
            
        else:
            self.send_response(404)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            self.wfile.write(b"<html><body><h1>404 Not Found</h1></body></html>")

    def log_message(self, format, *args):
        return

print(f"[*] Starting local vulnerable test server on http://127.0.0.1:{PORT}")
with socketserver.TCPServer(("", PORT), VulnerableHandler) as httpd:
    httpd.serve_forever()
