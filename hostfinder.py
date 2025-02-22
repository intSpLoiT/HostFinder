import socket
import requests
import argparse
import socks
import dns.resolver

# Tor proxy settings
TOR_SOCKS_PROXY = "127.0.0.1"
TOR_SOCKS_PORT = 9050

def start_tor():
    """Enable Tor anonymity."""
    socks.set_default_proxy(socks.SOCKS5, TOR_SOCKS_PROXY, TOR_SOCKS_PORT)
    socket.socket = socks.socksocket

def whois_lookup(target):
    """Fetch WHOIS info."""
    try:
        url = f"https://api.hackertarget.com/whois/?q={target}"
        headers = {"User-Agent": "Anonymous"}
        response = requests.get(url, headers=headers)
        return response.text
    except Exception as e:
        return f"Error: {e}"

def dns_lookup(target):
    """Resolve domain to IP."""
    try:
        ip = socket.gethostbyname(target)
        return ip
    except Exception as e:
        return f"Error: {e}"

def subdomain_scan(target):
    """Scan for subdomains."""
    subdomains = ["www", "mail", "ftp", "dev", "test", "admin"]
    found = []

    for sub in subdomains:
        try:
            full_domain = f"{sub}.{target}"
            ip = socket.gethostbyname(full_domain)
            found.append(f"{full_domain} -> {ip}")
        except:
            pass
    return found

def main():
    parser = argparse.ArgumentParser(description="Anonymous Host Finder")
    parser.add_argument("-t", "--target", required=True, help="Target domain")
    parser.add_argument("--tor", action="store_true", help="Enable anonymous mode via Tor")
    parser.add_argument("--whois", action="store_true", help="Fetch WHOIS info")
    parser.add_argument("--ip", action="store_true", help="Find IP address")
    parser.add_argument("--subdomain", action="store_true", help="Scan subdomains")

    args = parser.parse_args()

    if args.tor:
        print("[+] Enabling Anonymous Mode...")
        start_tor()

    print(f"[+] Scanning {args.target}...\n")

    if args.ip:
        ip = dns_lookup(args.target)
        print(f"[*] IP Address: {ip}")

    if args.whois:
        whois_data = whois_lookup(args.target)
        print("\n[*] WHOIS Info:\n", whois_data)

    if args.subdomain:
        print("\n[*] Subdomains:")
        subdomains = subdomain_scan(args.target)
        for sub in subdomains:
            print(f" - {sub}")

if __name__ == "__main__":
    main()
