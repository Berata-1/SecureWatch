from pathlib import Path
from datetime import datetime
import sqlite3

from hash_engine import calculate_sha256
from database import DB_PATH
from detector import calculate_severity


def add_event(cursor, event_type, severity, file_path,
              old_hash=None, new_hash=None):

    cursor.execute("""
        INSERT INTO events (
            event_type,
            severity,
            file_path,
            old_hash,
            new_hash,
            created_at
        )
        VALUES (?, ?, ?, ?, ?, ?)
    """, (
        event_type,
        severity,
        str(file_path),
        old_hash,
        new_hash,
        datetime.now().isoformat()
    ))


def should_ignore(file_path, ignored_directories, ignored_extensions):
    path = Path(file_path)

    # Klasörlerden biri ignore listesindeyse
    for part in path.parts:
        if part in ignored_directories:
            return True

    # Dosya uzantısı ignore listesindeyse
    if path.suffix.lower() in ignored_extensions:
        return True

    return False


def scan_directory(
    directory_path,
    ignored_directories=None,
    ignored_extensions=None
):
    if ignored_directories is None:
        ignored_directories = []

    if ignored_extensions is None:
        ignored_extensions = []

    directory = Path(directory_path)

    if not directory.exists():
        print(f"[-] Directory not found: {directory}")
        return

    if not directory.is_dir():
        print(f"[-] Not a directory: {directory}")
        return

    connection = sqlite3.connect(DB_PATH)
    cursor = connection.cursor()

    print(f"\n[+] Scanning: {directory}\n")

    cursor.execute(
        "SELECT file_path, file_hash FROM files"
    )

    database_files = {
        file_path: file_hash
        for file_path, file_hash in cursor.fetchall()
    }

    current_files = set()

    # CREATED / MODIFIED
    for file_path in directory.rglob("*"):

        if not file_path.is_file():
            continue

        if should_ignore(
            file_path,
            ignored_directories,
            ignored_extensions
        ):
            continue

        file_path_string = str(file_path)
        current_files.add(file_path_string)

        file_hash = calculate_sha256(file_path)

        if file_hash is None:
            print(f"[!] Could not read: {file_path}")
            continue

        cursor.execute(
            "SELECT file_hash FROM files WHERE file_path = ?",
            (file_path_string,)
        )

        result = cursor.fetchone()

        # CREATED
        if result is None:

            cursor.execute("""
                INSERT INTO files (
                    file_path,
                    file_hash,
                    last_checked
                )
                VALUES (?, ?, ?)
            """, (
                file_path_string,
                file_hash,
                datetime.now().isoformat()
            ))

            severity = calculate_severity(
                file_path_string,
                "CREATED"
            )

            add_event(
                cursor,
                "CREATED",
                severity,
                file_path_string,
                new_hash=file_hash
            )

            print(
                f"[{severity}] CREATED  -> {file_path.name}"
            )

        # MODIFIED
        elif result[0] != file_hash:

            old_hash = result[0]

            cursor.execute("""
                UPDATE files
                SET file_hash = ?, last_checked = ?
                WHERE file_path = ?
            """, (
                file_hash,
                datetime.now().isoformat(),
                file_path_string
            ))

            severity = calculate_severity(
                file_path_string,
                "MODIFIED"
            )

            add_event(
                cursor,
                "MODIFIED",
                severity,
                file_path_string,
                old_hash=old_hash,
                new_hash=file_hash
            )

            print(
                f"[{severity}] MODIFIED -> {file_path.name}"
            )

    # DELETED
    for stored_path, old_hash in database_files.items():

        stored_file = Path(stored_path)

        try:
            stored_file.relative_to(directory)
        except ValueError:
            continue

        # Ignore edilen dosyalar için DELETED alarmı üretme
        if should_ignore(
            stored_file,
            ignored_directories,
            ignored_extensions
        ):
            continue

        if stored_path not in current_files:

            severity = calculate_severity(
                stored_path,
                "DELETED"
            )

            add_event(
                cursor,
                "DELETED",
                severity,
                stored_path,
                old_hash=old_hash
            )

            cursor.execute(
                "DELETE FROM files WHERE file_path = ?",
                (stored_path,)
            )

            print(
                f"[{severity}] DELETED  -> {stored_file.name}"
            )

    connection.commit()
    connection.close()

    print("\n[+] Scan completed.")