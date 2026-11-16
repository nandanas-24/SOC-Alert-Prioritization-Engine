import sqlite3

connection = sqlite3.connect("alerts.db")
cursor = connection.cursor()

cursor.execute("SELECT * FROM security_alerts")

alerts = cursor.fetchall()

print("\n========== SOC SECURITY ALERTS ==========\n")

for alert in alerts:
    print("Alert ID:", alert[0])
    print("Alert Name:", alert[1])
    print("Source IP:", alert[2])
    print("Destination IP:", alert[3])
    print("Severity:", alert[4])
    print("Description:", alert[5])
    print("Status:", alert[6])
    print("-" * 45)

connection.close()