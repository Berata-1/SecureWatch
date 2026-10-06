import sqlite3
import csv
from datetime import datetime

from database import DB_PATH


def show_dashboard(max_recent_events=5):
    connection = sqlite3.connect(DB_PATH)
    cursor = connection.cursor()

    cursor.execute("SELECT COUNT(*) FROM files")
    monitored_files = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM events")
    total_events = cursor.fetchone()[0]

    cursor.execute("""
        SELECT COUNT(*) FROM events
        WHERE severity = 'CRITICAL'
    """)
    critical_alerts = cursor.fetchone()[0]

    cursor.execute("""
        SELECT COUNT(*) FROM events
        WHERE severity = 'HIGH'
    """)
    high_alerts = cursor.fetchone()[0]

    cursor.execute("""
        SELECT COUNT(*) FROM events
        WHERE severity = 'MEDIUM'
    """)
    medium_alerts = cursor.fetchone()[0]

    cursor.execute("""
        SELECT COUNT(*) FROM events
        WHERE event_type = 'CREATED'
    """)
    created = cursor.fetchone()[0]

    cursor.execute("""
        SELECT COUNT(*) FROM events
        WHERE event_type = 'MODIFIED'
    """)
    modified = cursor.fetchone()[0]

    cursor.execute("""
        SELECT COUNT(*) FROM events
        WHERE event_type = 'DELETED'
    """)
    deleted = cursor.fetchone()[0]

    cursor.execute("""
        SELECT event_type, severity, file_path, created_at
        FROM events
        ORDER BY id DESC
        LIMIT ?
    """, (max_recent_events,))

    recent_events = cursor.fetchall()

    connection.close()

    print("\n" + "=" * 65)
    print("                 SECUREWATCH SECURITY DASHBOARD")
    print("=" * 65)

    print(f" Monitored Files  : {monitored_files}")
    print(f" Total Events     : {total_events}")

    print("-" * 65)

    print(f" CRITICAL Alerts  : {critical_alerts}")
    print(f" HIGH Alerts      : {high_alerts}")
    print(f" MEDIUM Alerts    : {medium_alerts}")

    print("-" * 65)

    print(f" CREATED          : {created}")
    print(f" MODIFIED         : {modified}")
    print(f" DELETED          : {deleted}")

    print(f"\n RECENT SECURITY EVENTS (Last {max_recent_events})")
    print("-" * 65)

    if not recent_events:
        print(" No security events recorded.")
    else:
        for event_type, severity, file_path, created_at in recent_events:
            print(
                f" [{severity:<8}] "
                f"{event_type:<8} | "
                f"{file_path} | "
                f"{created_at[:19]}"
            )

    print("=" * 65)


def export_report():
    connection = sqlite3.connect(DB_PATH)
    cursor = connection.cursor()

    cursor.execute("""
        SELECT
            id,
            event_type,
            severity,
            file_path,
            old_hash,
            new_hash,
            created_at
        FROM events
        ORDER BY id DESC
    """)

    events = cursor.fetchall()
    connection.close()

    if not events:
        print("[!] No events available for report.")
        return

    report_name = datetime.now().strftime(
        "reports/securewatch_report_%Y-%m-%d_%H-%M-%S.csv"
    )

    with open(
        report_name,
        "w",
        newline="",
        encoding="utf-8"
    ) as file:

        writer = csv.writer(file)

        writer.writerow([
            "ID",
            "Event Type",
            "Severity",
            "File Path",
            "Old SHA256",
            "New SHA256",
            "Timestamp"
        ])

        writer.writerows(events)

    print(f"[+] Security report exported: {report_name}")