import os
import requests
import ipaddress
from dotenv import load_dotenv

load_dotenv(override=True)

API_KEY = os.getenv("ABUSEIPDB_API_KEY")

URL = "https://api.abuseipdb.com/api/v2/check"


def check_ip(ip_address):

    if not API_KEY:
        print("API key not configured.")
        return None

    # Only check public IP addresses
    try:
        ip = ipaddress.ip_address(ip_address)

        if not ip.is_global:
            print(f"Skipping non-public IP: {ip_address}")
            return None

    except ValueError:
        print(f"Invalid IP address: {ip_address}")
        return None

    headers = {
        "Accept": "application/json",
        "Key": API_KEY.strip()
    }

    params = {
        "ipAddress": ip_address,
        "maxAgeInDays": 90
    }

    try:
        response = requests.get(
            URL,
            headers=headers,
            params=params,
            timeout=15
        )

        response.raise_for_status()

        result = response.json()["data"]

        threat_data = {
            "ip_address": result["ipAddress"],
            "abuse_score": result["abuseConfidenceScore"],
            "total_reports": result["totalReports"],
            "country": result.get("countryCode")
        }

        return threat_data

    except requests.RequestException as error:
        print("API Request Error:", error)
        return None


if __name__ == "__main__":

    result = check_ip("8.8.8.8")

    if result:
        print("\n========== THREAT INTELLIGENCE ==========")
        print("IP Address:", result["ip_address"])
        print("Abuse Confidence Score:", result["abuse_score"], "%")
        print("Total Reports:", result["total_reports"])
        print("Country:", result["country"])