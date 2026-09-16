from term_analyzer.spraying import run_credential_spray

def main(args, discovered_ports=None):
    target_host = getattr(args, "scan", "127.0.0.1")
    open_ports = discovered_ports or [8080, 80, 22]
    
    if getattr(args, "spray", False):
        run_credential_spray(
            target_host=target_host,
            open_ports=open_ports,
            user_arg=getattr(args, "username", "admin"),
            password_arg=args.spray if isinstance(args.spray, str) else None
        )
