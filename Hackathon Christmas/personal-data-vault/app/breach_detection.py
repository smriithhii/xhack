import requests
from datetime import datetime

class BreachDetector:
    def __init__(self):
        self.breach_api_url = "https://haveibeenpwned.com/api/v3"
        
    def check_password(self, password_hash):
        prefix = password_hash[:5]
        suffix = password_hash[5:]
        response = requests.get(f"{self.breach_api_url}/range/{prefix}")
        return any(suffix.upper() in line for line in response.text.splitlines())
        
    def check_account(self, email):
        response = requests.get(f"{self.breach_api_url}/breachedaccount/{email}")
        return response.json() if response.status_code == 200 else []
