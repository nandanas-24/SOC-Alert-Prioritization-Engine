import sqlite3

def create_database():

    connection = sqlite3.connect("alerts.db")
    cursor = connection.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS security_alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            alert_name TEXT NOT NULL,
            source_ip TEXT,
            destination_ip TEXT,
            severity TEXT,
            description TEXT,
            status TEXT DEFAULT 'New',
            risk_score INTEGER DEFAULT 0,
            abuse_score INTEGER DEFAULT 0,
            total_reports INTEGER DEFAULT 0,
            country TEXT
        )
    """)

    cursor.execute("PRAGMA table_info(security_alerts)")
    columns = [column[1] for column in cursor.fetchall()]

    new_columns = {
        "risk_score": "INTEGER DEFAULT 0",
        "abuse_score": "INTEGER DEFAULT 0",
        "total_reports": "INTEGER DEFAULT 0",
        "country": "TEXT"
    }

    for column, data_type in new_columns.items():
        if column not in columns:
            cursor.execute(
                f"ALTER TABLE security_alerts ADD COLUMN {column} {data_type}"
            )

    connection.commit()
    connection.close()

    print("Database Updated Successfully!")


if __name__ == "__main__":
    create_database()