import subprocess

def run_amass(domain):
    """Run Amass and filter results."""
    print(f"[+] Running Amass for {domain}")
    result = subprocess.run(["amass", "enum", "-active", "-d", domain], capture_output=True, text=True)
    return [sub for sub in result.stdout.split("\n") if sub and '*' not in sub]
