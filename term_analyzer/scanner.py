import socket

def scan_target_ports(target_host, port_list, timeout=1.0):
    """
    Performs a quick TCP connect scan on the target host across specified ports.
    Returns a list of discovered open ports.
    """
    open_ports = []
    print(f"[*] Scanning {target_host} across {len(port_list)} ports...")
    
    for port in port_list:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            result = s.connect_ex((target_host, port))
            if result == 0:
                print(f"    [+] Port {port} is OPEN")
                open_ports.append(port)
            s.close()
        except Exception:
            pass
            
    return open_ports
