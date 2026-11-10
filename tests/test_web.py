import json
import threading
import urllib.error
import urllib.request

import pytest

from sherlock_project.result import QueryResult, QueryStatus
from sherlock_project.web import SherlockWebServer, validate_username


def fake_search(username, site_data, query_notify, proxy=None, timeout=60):
    """Stands in for sherlock(): reports every site as claimed, offline."""
    query_notify.start(username)
    for name, info in site_data.items():
        # sherlock() keeps state in the site data. Mimic that to prove that
        # every search gets a copy of its own.
        assert "request_future" not in info
        info["request_future"] = object()
        query_notify.update(QueryResult(username, name, info["url"].format(username), QueryStatus.CLAIMED))
    return {}


def start_server(sites_obj, search=fake_search, **kwargs):
    server = SherlockWebServer(("127.0.0.1", 0), sites_obj, search=search, **kwargs)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


@pytest.fixture()
def server(sites_obj):
    server = start_server(sites_obj)
    yield server
    server.shutdown()
    server.server_close()


def get(server, path, headers=None):
    url = f"http://127.0.0.1:{server.server_address[1]}{path}"
    request = urllib.request.Request(url, headers=headers or {})
    with urllib.request.urlopen(request, timeout=30) as response:
        return response.read().decode()


def events(server, path):
    """Read a whole event stream as a list of (event, data) tuples."""
    parsed = []
    for block in get(server, path).split("\n\n"):
        fields = dict(line.split(": ", 1) for line in block.splitlines() if not line.startswith(":"))
        if fields:
            parsed.append((fields["event"], json.loads(fields["data"])))
    return parsed


def test_index_page(server):
    assert "<title>Sherlock</title>" in get(server, "/")


def test_info(server, sites_obj):
    info = json.loads(get(server, "/api/info"))
    nsfw = sum(1 for site in sites_obj if site.is_nsfw)
    assert nsfw > 0
    assert info["nsfw_sites"] == nsfw
    assert info["sites"] == len(sites_obj) - nsfw


def test_search_stream(server, sites_obj):
    stream = events(server, "/api/search?username=some%20user")
    total = sum(1 for site in sites_obj if not site.is_nsfw)

    assert stream[0] == ("start", {"username": "some user", "total": total})
    assert stream[-1] == ("done", {})

    results = [data for event, data in stream if event == "result"]
    assert len(results) == total
    assert all(result["status"] == "Claimed" for result in results)
    github = next(result for result in results if result["site"] == "GitHub")
    assert github["url"] == "https://www.github.com/some user"


def test_search_twice_and_nsfw(server, sites_obj):
    # A second search fails inside fake_search if site data was shared.
    events(server, "/api/search?username=user")
    stream = events(server, "/api/search?username=user&nsfw=1")
    assert stream[0][1]["total"] == len(sites_obj)
    assert stream[-1][0] == "done"


@pytest.mark.parametrize("query", ["", "username=", "username=%20", "username=" + "a" * 101, "username=a%00b"])
def test_search_rejects_bad_usernames(server, query):
    stream = events(server, f"/api/search?{query}")
    assert len(stream) == 1
    assert stream[0][0] == "fail"


def test_search_failure_is_reported(sites_obj):
    def broken_search(*args, **kwargs):
        raise RuntimeError("boom")

    server = start_server(sites_obj, search=broken_search, max_searches=1)
    try:
        # Run twice: the search slot must be given back after a failure.
        for _ in range(2):
            stream = events(server, "/api/search?username=user")
            assert stream[-1] == ("fail", {"message": "The search failed: boom"})
    finally:
        server.shutdown()
        server.server_close()


def test_search_limit(sites_obj):
    release = threading.Event()

    def slow_search(username, site_data, query_notify, **kwargs):
        release.wait(timeout=30)

    server = start_server(sites_obj, search=slow_search, max_searches=1)
    try:
        first = []
        reader = threading.Thread(target=lambda: first.extend(events(server, "/api/search?username=one")))
        reader.start()
        while server.search_slots._value:
            pass

        stream = events(server, "/api/search?username=two")
        assert [event for event, _ in stream] == ["fail"]
        assert "Too many searches" in stream[0][1]["message"]

        release.set()
        reader.join(timeout=30)
        assert first[-1] == ("done", {})
    finally:
        release.set()
        server.shutdown()
        server.server_close()


@pytest.mark.parametrize("headers", [
    {"Sec-Fetch-Site": "cross-site"},
    {"Sec-Fetch-Site": "same-site"},
    {"Host": "attacker.example:8080"},
])
def test_foreign_requests_are_refused(server, headers):
    with pytest.raises(urllib.error.HTTPError) as error:
        get(server, "/api/search?username=user", headers=headers)
    assert error.value.code == 403


@pytest.mark.parametrize("site", ["cross-site", "same-site", "none"])
def test_page_opens_from_links(server, site):
    # Following a link from another site to the page itself must work.
    assert "<title>Sherlock</title>" in get(server, "/", headers={"Sec-Fetch-Site": site})


def test_page_refuses_foreign_host(server):
    with pytest.raises(urllib.error.HTTPError) as error:
        get(server, "/", headers={"Host": "attacker.example:8080"})
    assert error.value.code == 403


def test_unknown_path(server):
    with pytest.raises(urllib.error.HTTPError) as error:
        get(server, "/nope")
    assert error.value.code == 404


def test_validate_username():
    assert validate_username("user.name-1") is None
    assert validate_username("ユーザー") is None
    assert validate_username("") is not None
    assert validate_username("a\nb") is not None
