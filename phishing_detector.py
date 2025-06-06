# phishing_detector.py
import re

def is_suspicious_url(url):
    suspicious_patterns = [
        r"@",
        r"http[s]?://\d{1,3}(\.\d{1,3}){3}",  # IP address in URL
        r"https?://[^\s]*\.[a-z]{2,4}/[^\s]*@",  # @ in URL
        r"(login|verify|bank|secure).*\.html",  # suspicious keywords
        r"[0-9a-zA-Z]{10,}\.(tk|ml|ga|cf|gq)"  # shady domains
    ]
    for pattern in suspicious_patterns:
        if re.search(pattern, url):
            return True
    return False
