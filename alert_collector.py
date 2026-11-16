import sqlite3

def collect_alert():

    connection = sqlite3.connect("alerts.db")
    cursor = connection.cursor()

    alerts = [
        (
            "Multiple Failed Login Attempts",
            "192.168.1.10",
            "192.168.1.100",
            "High",
            "Multiple failed login attempts detected from one IP address."
        ),
        (
            "Suspicious IP Connection",
            "203.0.113.50",
            "192.168.1.100",
            "Critical",
            "Connection detected from a simulated suspicious external IP."
        ),
        (
            "Port Scanning Detected",
            "192.168.1.25",
            "192.168.1.100",
            "Medium",
            "Multiple ports accessed within a short period."
        ),
        (
            "Unusual DNS Request",
            "192.168.1.30",
            "192.168.1.100",
            "Low",
            "Unusual DNS request detected."
        ),
        (
            "Malware Detection",
            "192.168.1.40",
            "192.168.1.100",
            "Critical",
            "Simulated malware detection alert."
        )
    ]

    cursor.executemany("""
        INSERT INTO security_alerts
        (alert_name, source_ip, destination_ip, severity, description)
        VALUES (?, ?, ?, ?, ?)
    """, alerts)

    connection.commit()
    connection.close()

    print("Security Alerts Collected Successfully!")
    print("Total Alerts Added:", len(alerts))


if __name__ == "__main__":
    collect_alert()