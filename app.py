from flask import Flask, render_template, abort, request, redirect, url_for
import sqlite3
import ipaddress

from ip_reputation import check_ip_reputation
from risk_engine import calculate_final_risk, classify_risk

app = Flask(__name__)

DATABASE = "alerts.db"

ALLOWED_ANALYST_STATUSES = ["New", "Investigating", "Resolved"]


def get_connection():
    connection = sqlite3.connect(DATABASE)
    connection.row_factory = sqlite3.Row
    return connection


# Initialize database columns
def initialize_columns():

    connection = get_connection()

    try:
        cursor = connection.cursor()

        cursor.execute("PRAGMA table_info(security_alerts)")
        columns = [row["name"] for row in cursor.fetchall()]

        if "internal_score" not in columns:

            cursor.execute("""
                ALTER TABLE security_alerts
                ADD COLUMN internal_score INTEGER DEFAULT 0
            """)

            cursor.execute("""
                UPDATE security_alerts
                SET internal_score = risk_score
                WHERE internal_score = 0
            """)

        if "analyst_status" not in columns:

            cursor.execute("""
                ALTER TABLE security_alerts
                ADD COLUMN analyst_status TEXT DEFAULT 'New'
            """)

        connection.commit()

    finally:
        connection.close()


# Update IP reputation using AbuseIPDB
def update_ip_reputation():

    connection = get_connection()

    try:
        cursor = connection.cursor()

        cursor.execute("""
            SELECT DISTINCT source_ip
            FROM security_alerts
            WHERE source_ip IS NOT NULL
            AND source_ip != ''
        """)

        ips = cursor.fetchall()

        for row in ips:

            ip = row["source_ip"]

            try:
                address = ipaddress.ip_address(ip)

                if not address.is_global:
                    continue

            except ValueError:
                continue

            reputation = check_ip_reputation(ip)

            if reputation is not None:

                cursor.execute("""
                    UPDATE security_alerts
                    SET abuse_score = ?,
                        total_reports = ?,
                        country = ?
                    WHERE source_ip = ?
                """, (
                    reputation["abuse_score"],
                    reputation["total_reports"],
                    reputation["country"],
                    ip
                ))

        connection.commit()

    finally:
        connection.close()


# Calculate risk scores
def update_risk_scores():

    connection = get_connection()

    try:
        cursor = connection.cursor()

        cursor.execute("""
            SELECT
                alert_name,
                source_ip,
                destination_ip,
                severity,
                description,
                MAX(internal_score) AS internal_score,
                MAX(abuse_score) AS abuse_score,
                COUNT(*) AS occurrences
            FROM security_alerts
            GROUP BY
                alert_name,
                source_ip,
                destination_ip,
                severity,
                description
        """)

        alerts = cursor.fetchall()

        for alert in alerts:

            internal_score = alert["internal_score"] or 0
            abuse_score = alert["abuse_score"] or 0
            occurrences = alert["occurrences"] or 1

            final_score = calculate_final_risk(
                internal_score,
                abuse_score,
                occurrences
            )

            risk_classification = classify_risk(final_score)

            cursor.execute("""
                UPDATE security_alerts
                SET risk_score = ?,
                    status = ?
                WHERE alert_name IS ?
                AND source_ip IS ?
                AND destination_ip IS ?
                AND severity IS ?
                AND description IS ?
            """, (
                final_score,
                risk_classification,
                alert["alert_name"],
                alert["source_ip"],
                alert["destination_ip"],
                alert["severity"],
                alert["description"]
            ))

        connection.commit()

    finally:
        connection.close()


# Retrieve grouped alerts
def get_alerts():

    connection = get_connection()

    try:
        cursor = connection.cursor()

        cursor.execute("""
            SELECT
                MAX(id) AS id,
                alert_name,
                source_ip,
                destination_ip,
                severity,
                description,
                MAX(status) AS status,
                MAX(analyst_status) AS analyst_status,
                MAX(risk_score) AS risk_score,
                MAX(abuse_score) AS abuse_score,
                MAX(total_reports) AS total_reports,
                MAX(country) AS country,
                COUNT(*) AS occurrences
            FROM security_alerts
            GROUP BY
                alert_name,
                source_ip,
                destination_ip,
                severity,
                description
            ORDER BY MAX(risk_score) DESC
        """)

        return cursor.fetchall()

    finally:
        connection.close()


# Rule-based investigation recommendations
def generate_recommendations(alert, occurrences):

    recommendations = []
    reasons = []

    alert_name = (alert["alert_name"] or "").lower()
    severity = (alert["severity"] or "").lower()

    abuse_score = alert["abuse_score"] or 0
    total_reports = alert["total_reports"] or 0

    if severity == "critical":

        reasons.append(
            "The alert has been marked as Critical severity."
        )

        recommendations.append(
            "Prioritize investigation and validate the alert immediately."
        )

    elif severity == "high":

        reasons.append(
            "The alert has been marked as High severity."
        )

        recommendations.append(
            "Investigate this alert with high priority."
        )

    elif severity == "medium":

        reasons.append(
            "The alert has been marked as Medium severity."
        )

        recommendations.append(
            "Review related network and system activity."
        )

    else:

        reasons.append(
            "The alert has Low or unspecified severity."
        )

        recommendations.append(
            "Monitor the event and review it for unusual patterns."
        )

    if abuse_score >= 75:

        reasons.append(
            "The source IP has a high AbuseIPDB confidence score."
        )

        recommendations.append(
            "Review the source IP reputation and investigate related activity."
        )

    elif abuse_score >= 25:

        reasons.append(
            "The source IP has a moderate AbuseIPDB confidence score."
        )

        recommendations.append(
            "Validate the IP reputation using additional trusted threat intelligence."
        )

    else:

        reasons.append(
            "The source IP has a low or zero AbuseIPDB confidence score, "
            "or reputation data is unavailable."
        )

        recommendations.append(
            "Do not assume the IP is safe; review the surrounding activity."
        )

    if total_reports > 0:

        reasons.append(
            f"The source IP has {total_reports} reports in AbuseIPDB."
        )

        recommendations.append(
            "Review the report history and check whether the activity "
            "matches the current alert."
        )

    if occurrences > 1:

        reasons.append(
            f"This alert occurred {occurrences} times."
        )

        recommendations.append(
            "Compare repeated events and check whether they share "
            "the same source and destination."
        )

    if "failed login" in alert_name or "login" in alert_name:

        recommendations.append(
            "Review authentication logs and verify whether the login "
            "attempts were authorized."
        )

    if "port scan" in alert_name or "scanning" in alert_name:

        recommendations.append(
            "Review firewall and network logs for unusual connection attempts."
        )

    if "malware" in alert_name:

        recommendations.append(
            "Follow your organization's malware investigation procedure "
            "and review endpoint security alerts."
        )

    if "dns" in alert_name:

        recommendations.append(
            "Review DNS query logs and validate whether the requested "
            "domain is expected."
        )

    if "suspicious ip" in alert_name:

        recommendations.append(
            "Review traffic involving the source IP and verify its "
            "business or operational purpose."
        )

    return {
        "reasons": reasons,
        "actions": recommendations
    }


# Main dashboard
@app.route("/")
def dashboard():

    initialize_columns()

    update_ip_reputation()
    update_risk_scores()

    alerts = get_alerts()

    connection = get_connection()

    try:
        cursor = connection.cursor()

        cursor.execute("""
            SELECT COUNT(*)
            FROM security_alerts
        """)

        total_alerts = cursor.fetchone()[0]

    finally:
        connection.close()

    unique_alerts = len(alerts)

    duplicate_alerts = total_alerts - unique_alerts

    critical_alerts = sum(
        1 for alert in alerts
        if alert["status"] == "Critical"
    )

    high_alerts = sum(
        1 for alert in alerts
        if alert["status"] == "High"
    )

    # SOC Analyst Performance Statistics

    pending_alerts = sum(
        1 for alert in alerts
        if (alert["analyst_status"] or "New") == "New"
    )

    investigating_alerts = sum(
        1 for alert in alerts
        if alert["analyst_status"] == "Investigating"
    )

    resolved_alerts = sum(
        1 for alert in alerts
        if alert["analyst_status"] == "Resolved"
    )

    investigation_progress = (
        round((resolved_alerts / unique_alerts) * 100)
        if unique_alerts > 0 else 0
    )

    return render_template(
        "index.html",
        alerts=alerts,
        total_alerts=total_alerts,
        unique_alerts=unique_alerts,
        duplicate_alerts=duplicate_alerts,
        critical_alerts=critical_alerts,
        high_alerts=high_alerts,
        pending_alerts=pending_alerts,
        investigating_alerts=investigating_alerts,
        resolved_alerts=resolved_alerts,
        investigation_progress=investigation_progress
    )


# Update analyst workflow status
@app.route("/alert/<int:alert_id>/status", methods=["POST"])
def update_alert_status(alert_id):

    new_status = request.form.get("analyst_status")

    if new_status not in ALLOWED_ANALYST_STATUSES:
        abort(400)

    connection = get_connection()

    try:
        cursor = connection.cursor()

        cursor.execute("""
            SELECT *
            FROM security_alerts
            WHERE id = ?
        """, (alert_id,))

        alert = cursor.fetchone()

        if alert is None:
            abort(404)

        cursor.execute("""
            UPDATE security_alerts
            SET analyst_status = ?
            WHERE alert_name IS ?
            AND source_ip IS ?
            AND destination_ip IS ?
            AND severity IS ?
            AND description IS ?
        """, (
            new_status,
            alert["alert_name"],
            alert["source_ip"],
            alert["destination_ip"],
            alert["severity"],
            alert["description"]
        ))

        connection.commit()

    finally:
        connection.close()

    return redirect(url_for("dashboard"))


# Alert investigation page
@app.route("/alert/<int:alert_id>")
def investigate_alert(alert_id):

    initialize_columns()

    connection = get_connection()

    try:
        cursor = connection.cursor()

        cursor.execute("""
            SELECT *
            FROM security_alerts
            WHERE id = ?
        """, (alert_id,))

        alert = cursor.fetchone()

        if alert is None:
            abort(404)

        cursor.execute("""
            SELECT COUNT(*)
            FROM security_alerts
            WHERE alert_name IS ?
            AND source_ip IS ?
            AND destination_ip IS ?
            AND severity IS ?
            AND description IS ?
        """, (
            alert["alert_name"],
            alert["source_ip"],
            alert["destination_ip"],
            alert["severity"],
            alert["description"]
        ))

        occurrences = cursor.fetchone()[0]

        internal_score = alert["internal_score"] or 0
        abuse_score = alert["abuse_score"] or 0

        internal_points = round(
            min(max(internal_score, 0), 100) * 0.70, 2
        )

        abuse_points = round(
            min(max(abuse_score, 0), 100) * 0.20, 2
        )

        duplicate_points = min(
            max(occurrences - 1, 0) * 5, 10
        )

        risk_assessment = {
            "internal_score": internal_score,
            "internal_points": internal_points,
            "abuse_score": abuse_score,
            "abuse_points": abuse_points,
            "duplicate_points": duplicate_points,
            "final_score": alert["risk_score"],
            "classification": alert["status"]
        }

        investigation = generate_recommendations(
            alert,
            occurrences
        )

        return render_template(
            "investigation.html",
            alert=alert,
            occurrences=occurrences,
            risk_assessment=risk_assessment,
            investigation=investigation
        )

    finally:
        connection.close()


if __name__ == "__main__":

    initialize_columns()

    app.run(debug=True)