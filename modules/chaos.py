import subprocess

def run_chaos(domain):
    """Run Chaos for subdomain enumeration."""
    print(f"[+] Running Chaos for {domain}")
    result = subprocess.run(["chaos", "-d", domain, "-silent"], capture_output=True, text=True)
    return [sub for sub in result.stdout.split("\n") if sub and '*' not in sub]
