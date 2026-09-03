from datetime import datetime, timedelta

from src.analyzer import detect_brute_force


def test_brute_force_detection():

    base_time = datetime(
        2026,
        9,
        2,
        12,
        0,
        0
    )

    failed_events = []

    for i in range(5):

        failed_events.append({
            "event_id": 4625,
            "user": "testuser",
            "ip_address": "192.168.1.100",
            "time": base_time + timedelta(
                seconds=i * 30
            )
        })

    alerts = detect_brute_force(
        failed_events,
        threshold=5,
        window_minutes=5
    )

    assert len(alerts) == 1

    assert alerts[0]["risk"] == "HIGH"

    assert alerts[0]["user"] == "testuser"

    assert alerts[0]["ip"] == "192.168.1.100"

    assert alerts[0]["attempts"] == 5