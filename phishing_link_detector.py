import re
import requests

def is_suspicious_link(url):
    """
    Checks if the given URL is potentially malicious.
    """
    try:
        # Extract the domain from the URL
        domain = re.search(r"https?://([^/]+)", url).group(1)
        
        # Check if the domain is known to be malicious
        malicious_domains = [
            "example-phishing.com",
            "malicioussite.net"
        ]
        if domain in malicious_domains:
            return True
        
        # Check if the domain responds with a suspicious status code
        response = requests.get(url, timeout=5)
        if response.status_code != 200:
            return True
    except:
        pass
    
    return False

def scan_text(text):
    """
    Scans the given text for potential malicious links.
    """
    # Find all URLs in the text
    urls = re.findall(r"https?://\S+", text)
    
    # Check each URL for potential malicious behavior
    malicious_links = []
    for url in urls:
        if is_suspicious_link(url):
            malicious_links.append(url)
    
    return malicious_links

# Example usage
text = "Visit https://example.com or https://example-phishing.com for more information. Also, check out https://malicioussite.net and https://phishingexample.com."
malicious_links = scan_text(text)
if malicious_links:
    print("Potential malicious links found:")
    for link in malicious_links:
        print(link)
else:
    print("No malicious links found.")