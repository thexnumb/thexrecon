import subprocess

def run_gau(domain):
    """Run GAU for subdomain discovery."""
    print(f"[+] Running GAU for {domain}")
    result = subprocess.run(["gau", domain, "--threads", "10", "--subs"], capture_output=True, text=True)
    return [sub for sub in result.stdout.split("\n") if sub and '*' not in sub]
