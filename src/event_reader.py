from datetime import datetime, timedelta

import win32evtlog


SECURITY_LOG = "Security"

EVENT_LIMITS = {
    4624: 100,
    4625: 100,
    4634: 50,
    4647: 50,
    4672: 100,
}


def read_events_by_id(event_id, max_events=None, since=None):
    handle = win32evtlog.OpenEventLog(None, SECURITY_LOG)

    flags = (
        win32evtlog.EVENTLOG_BACKWARDS_READ
        | win32evtlog.EVENTLOG_SEQUENTIAL_READ
    )

    events = []

    try:
        while True:
            records = win32evtlog.ReadEventLog(
                handle,
                flags,
                0
            )

            if not records:
                break

            for event in records:
                event_time = event.TimeGenerated

                # Eventlər geriyə doğru oxunur.
                # Əgər event artıq istədiyimiz vaxtdan köhnədirsə,
                # daha aşağıya getməyə ehtiyac yoxdur.
                if since is not None and event_time < since:
                    return events

                current_event_id = event.EventID & 0xFFFF

                if current_event_id != event_id:
                    continue

                events.append(
                    {
                        "event_id": current_event_id,
                        "time": event_time,
                        "source": event.SourceName,
                        "computer": event.ComputerName,
                        "strings": list(event.StringInserts or []),
                    }
                )

                if max_events is not None and len(events) >= max_events:
                    return events

    finally:
        win32evtlog.CloseEventLog(handle)

    return events


def read_security_events(hours=None):
    all_events = []

    since = None

    if hours is not None:
        since = datetime.now() - timedelta(hours=hours)

    for event_id, limit in EVENT_LIMITS.items():

        # Əgər --hours istifadə olunubsa,
        # həmin zaman aralığındakı bütün uyğun event-ləri oxuyuruq.
        if hours is not None:
            max_events = None
        else:
            max_events = limit

        events = read_events_by_id(
            event_id,
            max_events=max_events,
            since=since
        )

        all_events.extend(events)

    all_events.sort(
        key=lambda x: x["time"],
        reverse=True
    )

    return all_events