import argparse

from event_reader import read_security_events
from event_parser import parse_event
from analyzer import analyze_events
from reporter import generate_report, generate_json_report


def parse_arguments():
    parser = argparse.ArgumentParser(
        description="Windows Security Event Log Analyzer"
    )

    parser.add_argument(
        "--hours",
        type=float,
        default=None,
        help="Analyze events from the last N hours"
    )

    parser.add_argument(
        "--threshold",
        type=int,
        default=5,
        help="Failed login attempts required to trigger brute-force detection"
    )

    parser.add_argument(
        "--window",
        type=int,
        default=5,
        help="Time window in minutes for brute-force detection"
    )

    return parser.parse_args()


def main():
    args = parse_arguments()

    if args.hours is not None and args.hours <= 0:
        print("ERROR: --hours must be greater than 0.")
        return

    if args.threshold <= 0:
        print("ERROR: --threshold must be greater than 0.")
        return

    if args.window <= 0:
        print("ERROR: --window must be greater than 0.")
        return

    raw_events = read_security_events(hours=args.hours)

    events = []

    for raw_event in raw_events:
        parsed_event = parse_event(raw_event)
        events.append(parsed_event)

    summary, alerts = analyze_events(
        events,
        threshold=args.threshold,
        window_minutes=args.window
    )

    report_file = generate_report(
        summary,
        alerts,
        events
    )

    json_report_file = generate_json_report(
        summary,
        alerts,
        events
    )

    print()
    print("=" * 60)
    print("        WINDOWS SECURITY LOG ANALYZER")
    print("=" * 60)

    print()

    print("CONFIGURATION")
    print("-" * 60)

    if args.hours is None:
        print("Time Range        : All available events")
    else:
        print(f"Time Range        : Last {args.hours} hours")

    print(f"Threshold         : {args.threshold} failed attempts")
    print(f"Detection Window  : {args.window} minutes")

    print()

    print("SUMMARY")
    print("-" * 60)
    print("Successful Logins :", summary["successful_logins"])
    print("Failed Logins     :", summary["failed_logins"])
    print("Logoffs           :", summary["logoffs"])
    print("Interactive       :", summary["interactive_logins"])
    print("RDP Logins        :", summary["rdp_logins"])
    print("Network Logins    :", summary["network_logins"])
    print("Service Logins    :", summary["service_logins"])
    print("Other Logins      :", summary["other_logins"])

    print()

    print("SECURITY ALERTS")
    print("-" * 60)

    if not alerts:
        print("No brute-force activity detected.")
    else:
        for alert in alerts:
            print()
            print("!!! POSSIBLE BRUTE FORCE !!!")
            print("User     :", alert["user"])
            print("IP       :", alert["ip"])
            print("Attempts :", alert["attempts"])
            print("Window   :", alert["window_minutes"], "minutes")
            print("Risk     :", alert["risk"])
            print("First    :", alert["first_seen"])
            print("Last     :", alert["last_seen"])

    print()

    print("RECENT EVENTS")
    print("-" * 60)

    for event in events[:20]:
        print(
            f'{event["time"]} | '
            f'Event {event["event_id"]} | '
            f'{event["event_type"]} | '
            f'User: {event.get("user", "Unknown")} | '
            f'IP: {event.get("ip_address", "Unknown")}'
        )

    print()

    print("REPORTS GENERATED")
    print("-" * 60)
    print("TXT Report  :", report_file)
    print("JSON Report :", json_report_file)

    print()


if __name__ == "__main__":
    main()