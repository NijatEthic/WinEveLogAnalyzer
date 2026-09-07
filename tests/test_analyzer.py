from datetime import datetime, timedelta

from src.analyzer import analyze_events, detect_brute_force


def create_failed_event(
    user="testuser",
    ip="192.168.1.100",
    minutes_ago=0
):
    return {
        "event_id": 4625,
        "event_type": "Failed Login",
        "time": datetime.now() - timedelta(
            minutes=minutes_ago
        ),
        "user": user,
        "ip_address": ip,
    }


def test_brute_force_detection():
    events = [
        create_failed_event(minutes_ago=4),
        create_failed_event(minutes_ago=3),
        create_failed_event(minutes_ago=2),
        create_failed_event(minutes_ago=1),
        create_failed_event(minutes_ago=0),
    ]

    alerts = detect_brute_force(
        events,
        threshold=5,
        window_minutes=5
    )

    assert len(alerts) == 1
    assert alerts[0]["attempts"] == 5
    assert alerts[0]["risk"] == "HIGH"


def test_no_brute_force_below_threshold():
    events = [
        create_failed_event(minutes_ago=3),
        create_failed_event(minutes_ago=2),
        create_failed_event(minutes_ago=1),
    ]

    alerts = detect_brute_force(
        events,
        threshold=5,
        window_minutes=5
    )

    assert len(alerts) == 0


def test_threshold_is_configurable():
    events = [
        create_failed_event(minutes_ago=2),
        create_failed_event(minutes_ago=1),
        create_failed_event(minutes_ago=0),
    ]

    alerts = detect_brute_force(
        events,
        threshold=3,
        window_minutes=5
    )

    assert len(alerts) == 1
    assert alerts[0]["attempts"] == 3


def test_window_is_respected():
    events = [
        create_failed_event(minutes_ago=10),
        create_failed_event(minutes_ago=8),
        create_failed_event(minutes_ago=6),
        create_failed_event(minutes_ago=4),
        create_failed_event(minutes_ago=0),
    ]

    alerts = detect_brute_force(
        events,
        threshold=5,
        window_minutes=5
    )

    assert len(alerts) == 0


def test_analyze_events_summary():
    from datetime import datetime

    test_time = datetime(2026, 9, 5, 12, 0, 0)

    events = [
        {
            "event_id": 4624,
            "logon_type": "Interactive",
        },
        {
            "event_id": 4624,
            "logon_type": "RemoteInteractive",
        },
        {
            "event_id": 4624,
            "logon_type": "Network",
        },
        {
            "event_id": 4624,
            "logon_type": "Service",
        },
        {
            "event_id": 4625,
            "time": test_time,
            "user": "testuser",
            "ip_address": "192.168.1.10",
        },
        {
            "event_id": 4634,
        },
        {
            "event_id": 4647,
        },
    ]

    summary, alerts = analyze_events(events)

    assert summary["successful_logins"] == 4
    assert summary["failed_logins"] == 1
    assert summary["logoffs"] == 2
    assert summary["interactive_logins"] == 1
    assert summary["rdp_logins"] == 1
    assert summary["network_logins"] == 1
    assert summary["service_logins"] == 1
    assert summary["other_logins"] == 0
    assert alerts == []
    summary, alerts = analyze_events(events)

    assert summary["successful_logins"] == 4
    assert summary["failed_logins"] == 1
    assert summary["logoffs"] == 2
    assert summary["interactive_logins"] == 1
    assert summary["rdp_logins"] == 1
    assert summary["network_logins"] == 1
    assert summary["service_logins"] == 1