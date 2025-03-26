import requests
import json

def crtsh(domain):
    """Fetch subdomains from crt.sh."""
    print(f"[+] Running crt.sh for {domain}")
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    response = requests.get(url)
    
    if response.status_code == 200:
        data = json.loads(response.text)
        return sorted(set(entry['name_value'].replace('*.', '') for entry in data if 'name_value' in entry))
    return []
