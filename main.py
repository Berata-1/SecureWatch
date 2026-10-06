import json
import time
from pathlib import Path

from database import create_database
from monitor import scan_directory
from reporter import show_dashboard, export_report


CONFIG_PATH = Path("config") / "config.json"


def load_config():
    try:
        with open(CONFIG_PATH, "r", encoding="utf-8") as file:
            config = json.load(file)

        # Scan interval kontrolü
        scan_interval = config.get("scan_interval", 5)

        if not isinstance(scan_interval, (int, float)) or scan_interval <= 0:
            print("[-] Invalid scan_interval. Using default: 5 seconds.")
            config["scan_interval"] = 5

        # Recent events kontrolü
        max_recent_events = config.get("max_recent_events", 5)

        if not isinstance(max_recent_events, int) or max_recent_events <= 0:
            print("[-] Invalid max_recent_events. Using default: 5.")
            config["max_recent_events"] = 5

        # Report ayarı kontrolü
        if not isinstance(config.get("report_on_exit", True), bool):
            print("[-] Invalid report_on_exit. Using default: true.")
            config["report_on_exit"] = True

        # Ignore listeleri kontrolü
        if not isinstance(config.get("ignored_directories", []), list):
            config["ignored_directories"] = []

        if not isinstance(config.get("ignored_extensions", []), list):
            config["ignored_extensions"] = []

        return config

    except FileNotFoundError:
        print(f"[-] Config file not found: {CONFIG_PATH}")
        return None

    except json.JSONDecodeError as error:
        print("[-] Invalid JSON configuration.")
        print(f"[-] Details: {error}")
        return None

    except OSError as error:
        print(f"[-] Could not read configuration: {error}")
        return None


def start_monitoring(config):
    scan_interval = config.get("scan_interval", 5)

    ignored_directories = config.get(
        "ignored_directories",
        []
    )

    ignored_extensions = config.get(
        "ignored_extensions",
        []
    )

    max_recent_events = config.get(
        "max_recent_events",
        5
    )

    report_on_exit = config.get(
        "report_on_exit",
        True
    )

    directory = input(
        "\nDirectory to monitor: "
    ).strip()

    print("\n[+] Configuration loaded successfully.")
    print(f"[+] Scan interval: {scan_interval} seconds")
    print(f"[+] Ignored directories: {len(ignored_directories)}")
    print(f"[+] Ignored extensions: {len(ignored_extensions)}")
    print("[+] Real-time monitoring started.")
    print("[+] Press CTRL+C to stop.\n")

    try:
        while True:

            scan_directory(
                directory,
                ignored_directories,
                ignored_extensions
            )

            time.sleep(scan_interval)

    except KeyboardInterrupt:
        print("\n[!] Monitoring stopped.")

        show_dashboard(max_recent_events)

        if report_on_exit:
            export_report()

        input("\nPress ENTER to return to menu...")


def show_menu():
    print("\n" + "=" * 60)
    print("                     SECUREWATCH")
    print("          File Integrity & Threat Monitor")
    print("=" * 60)

    print("""
 [1] Start Monitoring
 [2] Security Dashboard
 [3] Export Security Report
 [4] Exit
""")

    print("=" * 60)


def main():
    create_database()

    config = load_config()

    if config is None:
        return

    while True:
        show_menu()

        choice = input("Select option: ").strip()

        if choice == "1":
            start_monitoring(config)

        elif choice == "2":
            max_recent_events = config.get(
                "max_recent_events",
                5
            )

            show_dashboard(max_recent_events)

            input("\nPress ENTER to return to menu...")

        elif choice == "3":
            export_report()

            input("\nPress ENTER to return to menu...")

        elif choice == "4":
            print("\n[+] SecureWatch closed.")
            break

        else:
            print("\n[-] Invalid option.")
            input("Press ENTER to try again...")


if __name__ == "__main__":
    main()