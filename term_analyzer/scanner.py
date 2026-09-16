import socket
import ipaddress

def expand_targets(target_input):
    """
    Expands a single IP, hostname, or CIDR network block into a list of target IPs.
    """
    try:
        network = ipaddress.ip_network(target_input, strict=False)
        # If it is a single IP, network.num_addresses will be 1
        return [str(ip) for ip in network.hosts()] or [str(network.network_address)]
    except ValueError:
        # Not a valid CIDR, treat as a hostname or single IP string
        return [target_input]

def scan_target_ports(target_host, port_list, timeout=1.0):
    """
    Performs a quick TCP connect scan on the target host across specified ports.
    Returns a list of discovered open ports.
    """
    open_ports = []
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
