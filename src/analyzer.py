from datetime import timedelta


def analyze_events(events, threshold=5, window_minutes=5):
    summary = {
        "successful_logins": 0,
        "failed_logins": 0,
        "logoffs": 0,
        "interactive_logins": 0,
        "rdp_logins": 0,
        "network_logins": 0,
        "service_logins": 0,
        "other_logins": 0,
    }

    failed_attempts = []

    for event in events:
        event_id = event["event_id"]

        if event_id == 4624:
            summary["successful_logins"] += 1

            logon_type = event.get(
                "logon_type",
                "Unknown"
            )

            if logon_type == "Interactive":
                summary["interactive_logins"] += 1

            elif logon_type == "RemoteInteractive":
                summary["rdp_logins"] += 1

            elif logon_type == "Network":
                summary["network_logins"] += 1

            elif logon_type == "Service":
                summary["service_logins"] += 1

            else:
                summary["other_logins"] += 1

        elif event_id == 4625:
            summary["failed_logins"] += 1
            failed_attempts.append(event)

        elif event_id in (4634, 4647):
            summary["logoffs"] += 1

    alerts = detect_brute_force(
        failed_attempts,
        threshold=threshold,
        window_minutes=window_minutes
    )

    return summary, alerts


def detect_brute_force(
    failed_events,
    threshold=5,
    window_minutes=5
):
    alerts = []

    grouped = {}

    for event in failed_events:
        user = event.get(
            "user",
            "Unknown"
        )

        ip = event.get(
            "ip_address",
            "Unknown"
        )

        if not ip:
            ip = "Unknown"

        key = (user, ip)

        if key not in grouped:
            grouped[key] = []

        grouped[key].append(event)

    for (user, ip), events in grouped.items():

        events.sort(
            key=lambda x: x["time"]
        )

        for i in range(len(events)):

            start_time = events[i]["time"]

            count = 1
            last_index = i

            for j in range(
                i + 1,
                len(events)
            ):

                difference = (
                    events[j]["time"]
                    - start_time
                )

                if difference <= timedelta(
                    minutes=window_minutes
                ):
                    count += 1
                    last_index = j
                else:
                    break

            if count >= threshold:

                alerts.append(
                    {
                        "type": "Possible Brute Force",
                        "user": user,
                        "ip": ip,
                        "attempts": count,
                        "window_minutes": window_minutes,
                        "risk": "HIGH",
                        "first_seen": start_time,
                        "last_seen": events[last_index]["time"],
                    }
                )

                break

    return alerts