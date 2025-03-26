import requests
from bs4 import BeautifulSoup

def abuseipdb(domain, session_cookie):
    """Fetch WHOIS information from AbuseIPDB."""
    print(f"[+] Running AbuseIPDB for {domain}")
    url = f"https://www.abuseipdb.com/whois/{domain}"
    headers = {
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                      "(KHTML, like Gecko) Chrome/117.0.0.0 Safari/537.36"
    }
    cookies = {"abuseipdb_session": session_cookie}

    response = requests.get(url, headers=headers, cookies=cookies)
    soup = BeautifulSoup(response.text, 'html.parser')
    whois_data = [li.text.strip() + f".{domain}" for li in soup.find_all("li")]
    return whois_data
