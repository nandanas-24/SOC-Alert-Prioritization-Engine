import os
import requests
from dotenv import load_dotenv

load_dotenv()

API_KEY = os.getenv("ABUSEIPDB_API_KEY")

def check_ip_reputation(ip_address):

    if not API_KEY:
        return None

    url = "https://api.abuseipdb.com/api/v2/check"

    headers = {
        "Key": API_KEY,
        "Accept": "application/json"
    }

    params = {
        "ipAddress": ip_address,
        "maxAgeInDays": 90
    }

    try:
        response = requests.get(
            url,
            headers=headers,
            params=params,
            timeout=10
        )

        response.raise_for_status()

        data = response.json()["data"]

        return {
            "abuse_score": data["abuseConfidenceScore"],
            "total_reports": data["totalReports"],
            "country": data["countryCode"]
        }

    except requests.RequestException as error:
        print("API Error:", error)
        return None