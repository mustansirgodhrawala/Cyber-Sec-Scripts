import requests
from bs4 import BeautifulSoup
import sys

def whois_in(domain):
    url = "https://whois.registry.in/WHOIS"
    payload = {"domain": domain}
    
    r = requests.post(url, data=payload, timeout=15, verify=True)

    if r.status_code != 200:
        print(f"Error: HTTP {r.status_code}")
        return
    
    soup = BeautifulSoup(r.text, "html.parser")
    pre = soup.find("pre")  # NIXI renders results inside <pre>
    if pre:
        print(pre.get_text())
    else:
        print("No WHOIS data found or NIXI changed their format.")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python whois_in.py example.in")
    else:
        whois_in(sys.argv[1])
