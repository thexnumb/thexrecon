import subprocess

def run_wayback(domain):
    """Fetch subdomains from the Wayback Machine."""
    print(f"[+] Running Wayback Machine for {domain}")
    result = subprocess.run(["curl", "-s", f"https://web.archive.org/cdx/search/cdx?url=*{domain}/*&fl=original&collapse=urlkey"],
                            capture_output=True, text=True)
    return [sub for sub in result.stdout.split("\n") if sub and '*' not in sub]
