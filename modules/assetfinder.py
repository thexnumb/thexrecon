import subprocess

def run_assetfinder(domain):
    """Run assetfinder and filter results."""
    print(f"[+] Running Assetfinder for {domain}")
    result = subprocess.run(["assetfinder", domain], capture_output=True, text=True)
    return [sub for sub in result.stdout.split("\n") if sub and '*' not in sub]
