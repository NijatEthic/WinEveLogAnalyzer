from pathlib import Path
import json


REPORT_DIR = (
    Path(__file__).resolve().parent.parent
    / "reports"
)


def generate_report(summary, alerts, events):

    REPORT_DIR.mkdir(
        exist_ok=True
    )

    report_file = (
        REPORT_DIR
        / "security_report.txt"
    )

    with open(
        report_file,
        "w",
        encoding="utf-8"
    ) as file:

        file.write(
            "WINDOWS SECURITY LOG ANALYZER\n"
        )

        file.write(
            "=" * 60 + "\n\n"
        )

        file.write(
            "SUMMARY\n"
        )

        file.write(
            "-" * 60 + "\n"
        )

        file.write(
            f"Successful Logins : "
            f"{summary['successful_logins']}\n"
        )

        file.write(
            f"Failed Logins     : "
            f"{summary['failed_logins']}\n"
        )

        file.write(
            f"Logoffs           : "
            f"{summary['logoffs']}\n"
        )

        file.write(
            f"Interactive       : "
            f"{summary['interactive_logins']}\n"
        )

        file.write(
            f"RDP Logins        : "
            f"{summary['rdp_logins']}\n"
        )

        file.write(
            f"Network Logins    : "
            f"{summary['network_logins']}\n"
        )

        file.write(
            f"Service Logins    : "
            f"{summary['service_logins']}\n"
        )

        file.write(
            f"Other Logins      : "
            f"{summary['other_logins']}\n"
        )

        file.write("\n")

        file.write(
            "SECURITY ALERTS\n"
        )

        file.write(
            "-" * 60 + "\n"
        )

        if not alerts:

            file.write(
                "No brute-force activity detected.\n"
            )

        else:

            for alert in alerts:

                file.write(
                    "\nPOSSIBLE BRUTE FORCE\n"
                )

                file.write(
                    f"User     : "
                    f"{alert['user']}\n"
                )

                file.write(
                    f"IP       : "
                    f"{alert['ip']}\n"
                )

                file.write(
                    f"Attempts : "
                    f"{alert['attempts']}\n"
                )

                file.write(
                    f"Window   : "
                    f"{alert['window_minutes']} minutes\n"
                )

                file.write(
                    f"Risk     : "
                    f"{alert['risk']}\n"
                )

                file.write(
                    f"First    : "
                    f"{alert['first_seen']}\n"
                )

                file.write(
                    f"Last     : "
                    f"{alert['last_seen']}\n"
                )

        file.write("\n")

        file.write(
            "RECENT EVENTS\n"
        )

        file.write(
            "-" * 60 + "\n"
        )

        for event in events[:50]:

            file.write(
                f"{event['time']} | "
                f"Event {event['event_id']} | "
                f"{event['event_type']} | "
                f"User: "
                f"{event.get('user', 'Unknown')} | "
                f"IP: "
                f"{event.get('ip_address', 'Unknown')}\n"
            )

    return report_file


def generate_json_report(
    summary,
    alerts,
    events
):

    REPORT_DIR.mkdir(
        exist_ok=True
    )

    json_file = (
        REPORT_DIR
        / "security_report.json"
    )

    json_data = {
        "summary": summary,
        "alerts": alerts,
        "recent_events": events[:50]
    }

    with open(
        json_file,
        "w",
        encoding="utf-8"
    ) as file:

        json.dump(
            json_data,
            file,
            indent=4,
            ensure_ascii=False,
            default=str
        )

    return json_file