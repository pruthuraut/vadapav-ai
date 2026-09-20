from bb_harness.core.dorks import generate_dorks


def test_dorks_are_generated_without_network_requests():
    records = generate_dorks("example.com")
    assert records
    assert all("example.com" in record["dork"] for record in records)
    assert all(record["url"].startswith("https://www.google.com/search?") for record in records)
