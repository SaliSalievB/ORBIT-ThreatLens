from orbit.privacy import redact_for_ai


def test_redact_for_ai_masks_sensitive_keys() -> None:
    payload = {
        "target": "example.com",
        "headers": {
            "Authorization": "Bearer secret",
            "X-Request-ID": "abc",
        },
        "findings": [{"title": "Example", "cookie": "sid=secret"}],
    }

    redacted = redact_for_ai(payload)

    assert redacted["headers"]["Authorization"] == "[redacted]"
    assert redacted["headers"]["X-Request-ID"] == "abc"
    assert redacted["findings"][0]["cookie"] == "[redacted]"


def test_redact_for_ai_truncates_long_strings() -> None:
    redacted = redact_for_ai({"body": "a" * 700})

    assert redacted["body"].endswith("[truncated]")
    assert len(redacted["body"]) < 530
