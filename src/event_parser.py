LOGON_TYPES = {
    "2": "Interactive",
    "3": "Network",
    "4": "Batch",
    "5": "Service",
    "7": "Unlock",
    "8": "NetworkCleartext",
    "9": "NewCredentials",
    "10": "RemoteInteractive",
    "11": "CachedInteractive",
}


def get_logon_type(value):

    return LOGON_TYPES.get(
        str(value),
        "Unknown"
    )


def parse_event(event):

    event_id = event["event_id"]
    strings = event.get("strings") or []

    result = {
        "event_id": event_id,
        "event_type": "Other",
        "time": event["time"],
        "source": event["source"],
        "computer": event["computer"],
        "user": "Unknown",
        "domain": "Unknown",
        "logon_type": "Unknown",
        "process": "Unknown",
        "ip_address": "Unknown",
        "ip_port": "Unknown",
    }

    # 4624 - Successful Logon
    if event_id == 4624:

        result["event_type"] = "Successful Login"

        if len(strings) >= 19:

            result["user"] = strings[5]
            result["domain"] = strings[6]

            result["logon_type"] = get_logon_type(
                strings[8]
            )

            result["process"] = strings[17]
            result["ip_address"] = strings[18]

            if len(strings) > 19:
                result["ip_port"] = strings[19]

    # 4625 - Failed Logon
    elif event_id == 4625:

        result["event_type"] = "Failed Login"

        if len(strings) >= 21:

            result["user"] = strings[5]
            result["domain"] = strings[6]

            result["status"] = strings[7]
            result["failure_reason"] = strings[8]

            result["logon_type"] = get_logon_type(
                strings[10]
            )

            result["process"] = strings[18]
            result["ip_address"] = strings[19]
            result["ip_port"] = strings[20]

    # 4634 - Logoff
    elif event_id == 4634:

        result["event_type"] = "Logoff"

    # 4647 - User initiated logoff
    elif event_id == 4647:

        result["event_type"] = "User Initiated Logoff"

    # 4672 - Special privileges
    elif event_id == 4672:

        result["event_type"] = (
            "Special Privileges Assigned"
        )

        # 4672 contains SubjectUserName /
        # SubjectDomainName near the beginning
        if len(strings) >= 3:

            result["user"] = strings[1]
            result["domain"] = strings[2]

    return result