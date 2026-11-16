import sqlite3
from collections import defaultdict

def detect_duplicates():

    connection = sqlite3.connect("alerts.db")
    cursor = connection.cursor()

    cursor.execute("""
        SELECT id, alert_name, source_ip, severity
        FROM security_alerts
    """)

    alerts = cursor.fetchall()

    alert_groups = defaultdict(list)

    for alert in alerts:

        alert_id, alert_name, source_ip, severity = alert

        key = (alert_name, source_ip)

        alert_groups[key].append(alert_id)

    print("\n========== DUPLICATE ALERT ANALYSIS ==========\n")

    duplicate_count = 0

    for key, alert_ids in alert_groups.items():

        if len(alert_ids) > 1:

            duplicate_count += len(alert_ids) - 1

            print("Alert Name:", key[0])
            print("Source IP:", key[1])
            print("Occurrences:", len(alert_ids))
            print("Alert IDs:", alert_ids)
            print("-" * 40)

    if duplicate_count == 0:
        print("No duplicate alerts detected.")

    else:
        print("Total duplicate records:", duplicate_count)

    connection.close()


if __name__ == "__main__":
    detect_duplicates()