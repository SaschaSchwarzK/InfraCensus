from central.core.scheduling import _parse_labels, parse_job_id


def test_parse_job_id():
    assert parse_job_id("schedule_type:123") == 123
    assert parse_job_id("invalid") is None
    assert parse_job_id("") is None


def test_parse_labels():
    assert _parse_labels("key1=val1,key2=val2") == {
        "key1": "val1",
        "key2": "val2",
    }
    assert _parse_labels({"key": "val"}) == {"key": "val"}
