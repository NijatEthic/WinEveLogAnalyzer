from event_reader import read_security_events
from event_parser import parse_event
from analyzer import analyze_events
from reporter import generate_report


def main():

    # Read Windows Security Events
    raw_events = read_security_events()

    # Parse raw Windows events
    events = []

    for raw_event in raw_events:

        parsed_event = parse_event(
            raw_event
        )

        events.append(parsed_event)

    # Analyze events
    summary, alerts = analyze_events(
        events
    )

    # Generate security report
    report_file = generate_report(
        summary,
        alerts,
        events
    )

    print()
    print("=" * 60)
    print(
        "        WINDOWS SECURITY LOG ANALYZER"
    )
    print("=" * 60)

    print()
    print("SUMMARY")
    print("-" * 60)

    print(
        "Successful Logins :",
        summary["successful_logins"]
    )

    print(
        "Failed Logins     :",
        summary["failed_logins"]
    )

    print(
        "Logoffs           :",
        summary["logoffs"]
    )

    print(
        "Interactive       :",
        summary["interactive_logins"]
    )

    print(
        "RDP Logins        :",
        summary["rdp_logins"]
    )

    print(
        "Network Logins    :",
        summary["network_logins"]
    )

    print(
        "Service Logins    :",
        summary["service_logins"]
    )

    print(
        "Other Logins      :",
        summary["other_logins"]
    )

    print()
    print("SECURITY ALERTS")
    print("-" * 60)

    if not alerts:

        print(
            "No brute-force activity detected."
        )

    else:

        for alert in alerts:

            print()
            print(
                "!!! POSSIBLE BRUTE FORCE !!!"
            )

            print(
                "User     :",
                alert["user"]
            )

            print(
                "IP       :",
                alert["ip"]
            )

            print(
                "Attempts :",
                alert["attempts"]
            )

            print(
                "Window   :",
                alert["window_minutes"],
                "minutes"
            )

            print(
                "Risk     :",
                alert["risk"]
            )

            print(
                "First    :",
                alert["first_seen"]
            )

            print(
                "Last     :",
                alert["last_seen"]
            )

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
    print("REPORT GENERATED")
    print("-" * 60)
    print(
        "Report:",
        report_file
    )

    print()


if __name__ == "__main__":
    main()