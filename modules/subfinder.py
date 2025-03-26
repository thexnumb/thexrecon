import subprocess

def run_subfinder(domain):
    """Run subfinder and filter results."""
    print(f"[+] Running Subfinder for {domain}")
    result = subprocess.run(["subfinder", "-d", domain, "-all", "-silent"], capture_output=True, text=True)
    return [sub for sub in result.stdout.split("\n") if sub and '*' not in sub]
