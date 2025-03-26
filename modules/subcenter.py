import requests

def subcenter(domain):
    """Fetch subdomains from Subdomain Center API."""
    print(f"[+] Running Subdomain Center for {domain}")
    url = f"https://api.subdomain.center/?domain={domain}"
    response = requests.get(url)
    
    if response.status_code == 200:
        return response.json()
    return []
