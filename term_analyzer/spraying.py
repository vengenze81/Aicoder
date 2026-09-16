from term_analyzer.defaults import get_defaults_for_port

def run_credential_spray(target_host, open_ports, user_arg, password_arg):
    """
    Executes credential spraying, leveraging port defaults if no passwords are provided.
    """
    usernames = [u.strip() for u in user_arg.split(",")] if user_arg else ["admin"]

    for port in open_ports:
        if password_arg:
            passwords = [password_arg]
        else:
            default_pairs = get_defaults_for_port(port)
            print(f"[*] Loaded {len(default_pairs)} default credentials for port {port}")
            passwords = [pwd for _, pwd in default_pairs]

        for username in usernames:
            for password in passwords:
                print(f"[+] Testing {username}:{password} on {target_host}:{port}")
                # TODO: Add your actual authentication request implementation here
