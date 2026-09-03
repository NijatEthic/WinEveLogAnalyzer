import win32evtlog


SECURITY_LOG = "Security"


EVENT_LIMITS = {
    4624: 100,
    4625: 100,
    4634: 50,
    4647: 50,
    4672: 100,
}


def read_events_by_id(event_id, max_events):

    handle = win32evtlog.OpenEventLog(
        None,
        SECURITY_LOG
    )

    flags = (
        win32evtlog.EVENTLOG_BACKWARDS_READ
        | win32evtlog.EVENTLOG_SEQUENTIAL_READ
    )

    events = []

    try:

        while len(events) < max_events:

            records = win32evtlog.ReadEventLog(
                handle,
                flags,
                0
            )

            if not records:
                break

            for event in records:

                current_event_id = (
                    event.EventID & 0xFFFF
                )

                if current_event_id != event_id:
                    continue

                events.append({
                    "event_id": current_event_id,
                    "time": event.TimeGenerated,
                    "source": event.SourceName,
                    "computer": event.ComputerName,
                    "strings": list(
                        event.StringInserts or []
                    ),
                })

                if len(events) >= max_events:
                    break

    finally:

        win32evtlog.CloseEventLog(handle)

    return events


def read_security_events():

    all_events = []

    for event_id, limit in EVENT_LIMITS.items():

        events = read_events_by_id(
            event_id,
            limit
        )

        all_events.extend(events)

    all_events.sort(
        key=lambda x: x["time"],
        reverse=True
    )

    return all_events