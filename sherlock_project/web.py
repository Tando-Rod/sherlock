"""Sherlock Web Module

A small, dependency-free web interface for Sherlock. It serves a single page
where a username can be entered, and streams the results to the browser as
they arrive using Server-Sent Events.

Start it with ``sherlock-web`` or ``python -m sherlock_project.web``.
"""

import copy
import json
import os
import queue
import socket
import sys
import threading
from argparse import ArgumentParser, ArgumentTypeError, RawDescriptionHelpFormatter
from collections.abc import Callable
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

from sherlock_project import __longname__, __version__
from sherlock_project.notify import QueryNotify
from sherlock_project.result import QueryResult
from sherlock_project.sherlock import sherlock
from sherlock_project.sites import SitesInformation

RESOURCES = os.path.join(os.path.dirname(__file__), "resources")
LOCAL_MANIFEST = os.path.join(RESOURCES, "data.json")
INDEX_PAGE = os.path.join(RESOURCES, "web.html")

MAX_USERNAME_LENGTH = 100
KEEP_ALIVE_SECONDS = 15
LOOPBACK_HOSTS = {"localhost", "127.0.0.1", "::1"}

CONTENT_SECURITY_POLICY = (
    "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; "
    "connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
)


class SearchCancelled(Exception):
    """Raised inside a running search once nobody is listening anymore."""


class QueryNotifyQueue(QueryNotify):
    """Query Notify Queue Object.

    Query notify class that puts every result on a queue, so that another
    thread can forward it to the browser.
    """

    def __init__(self, events: queue.Queue, cancelled: threading.Event):
        super().__init__()
        self.events = events
        self.cancelled = cancelled

    def update(self, result: QueryResult):
        self.result = result
        if self.cancelled.is_set():
            # Leaving sherlock() early is the only way to stop a search.
            raise SearchCancelled()

        query_time = result.query_time
        if hasattr(query_time, "total_seconds"):
            query_time = query_time.total_seconds()

        self.events.put(("result", {
            "site": result.site_name,
            "url": result.site_url_user,
            "status": str(result.status.value),
            "ms": round(query_time * 1000) if query_time is not None else None,
            "context": str(result.context) if result.context is not None else None,
        }))


def validate_username(username: str) -> str | None:
    """Return a message describing why a username is unusable, or None."""
    if not username:
        return "Enter a username to search for."
    if len(username) > MAX_USERNAME_LENGTH:
        return f"Usernames are limited to {MAX_USERNAME_LENGTH} characters."
    if any(not char.isprintable() for char in username):
        return "The username contains characters that cannot be searched for."
    return None


class SherlockWebServer(ThreadingHTTPServer):
    """HTTP server holding everything a search needs."""

    daemon_threads = True

    def __init__(
        self,
        address: tuple[str, int],
        sites: SitesInformation,
        timeout: float = 30,
        proxy: str | None = None,
        max_searches: int = 4,
        search: Callable = sherlock,
        verbose: bool = False,
    ):
        self.site_data = {site.name: site.information for site in sites}
        self.nsfw_sites = {site.name for site in sites if site.is_nsfw}
        self.search_timeout = timeout
        self.proxy = proxy
        self.search = search
        self.verbose = verbose
        self.search_slots = threading.BoundedSemaphore(max_searches)
        self.loopback_only = address[0] in LOOPBACK_HOSTS
        if ":" in address[0]:
            self.address_family = socket.AF_INET6
        with open(INDEX_PAGE, "rb") as page:
            self.index_page = page.read()
        super().__init__(address, SherlockRequestHandler)

    def sites_for(self, include_nsfw: bool) -> dict:
        """Build a private copy of the site data for one search.

        sherlock() stores its pending requests inside the site data, so
        searches running at the same time must not share it.
        """
        return copy.deepcopy({
            name: info for name, info in self.site_data.items()
            if include_nsfw or name not in self.nsfw_sites
        })


class SherlockRequestHandler(BaseHTTPRequestHandler):
    server: SherlockWebServer
    server_version = f"SherlockWeb/{__version__}"

    def log_message(self, format, *args):
        # Request lines contain the usernames being searched for, so they are
        # only written out when explicitly asked for.
        if self.server.verbose:
            super().log_message(format, *args)

    def do_GET(self):
        url = urlsplit(self.path)

        if not self.request_is_trusted():
            self.send_json(HTTPStatus.FORBIDDEN, {"error": "Cross-site requests are not allowed."})
        elif url.path in ("/", "/index.html"):
            self.send_body(HTTPStatus.OK, "text/html; charset=utf-8", self.server.index_page)
        elif url.path == "/api/info":
            self.send_json(HTTPStatus.OK, {
                "version": __version__,
                "sites": len(self.server.site_data) - len(self.server.nsfw_sites),
                "nsfw_sites": len(self.server.nsfw_sites),
            })
        elif url.path == "/api/search":
            self.stream_search(parse_qs(url.query))
        else:
            self.send_json(HTTPStatus.NOT_FOUND, {"error": "Not found."})

    def request_is_trusted(self) -> bool:
        """Reject requests another website makes on behalf of the visitor.

        A search sends hundreds of requests from this machine, so a page on
        some other origin must not be able to start one.
        """
        if self.headers.get("Sec-Fetch-Site", "same-origin") not in ("same-origin", "none"):
            return False

        if self.server.loopback_only:
            # Guards against DNS rebinding: a hostile domain resolving to
            # 127.0.0.1 still sends its own name in the Host header.
            host = self.headers.get("Host", "")
            hostname = urlsplit(f"//{host}").hostname
            return hostname in LOOPBACK_HOSTS

        return True

    def send_body(self, status: HTTPStatus, content_type: str, body: bytes):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Content-Security-Policy", CONTENT_SECURITY_POLICY)
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def send_json(self, status: HTTPStatus, payload: dict):
        self.send_body(status, "application/json", json.dumps(payload).encode())

    def send_event(self, event: str, payload: dict):
        self.wfile.write(f"event: {event}\ndata: {json.dumps(payload)}\n\n".encode())
        self.wfile.flush()

    def stream_search(self, params: dict[str, list[str]]):
        username = params.get("username", [""])[0].strip()
        include_nsfw = params.get("nsfw", ["0"])[0] == "1"

        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", "text/event-stream; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Accel-Buffering", "no")
        self.end_headers()

        # Problems are reported as events too: the browser's EventSource
        # cannot read the body of a response that is not a 200.
        problem = validate_username(username)
        if problem is None and not self.server.search_slots.acquire(blocking=False):
            problem = "Too many searches are running. Try again in a moment."
        if problem is not None:
            self.send_event("fail", {"message": problem})
            return

        site_data = self.server.sites_for(include_nsfw)
        events: queue.Queue = queue.Queue()
        cancelled = threading.Event()

        def run_search():
            try:
                self.server.search(
                    username,
                    site_data,
                    QueryNotifyQueue(events, cancelled),
                    proxy=self.server.proxy,
                    timeout=self.server.search_timeout,
                )
                events.put(("done", {}))
            except SearchCancelled:
                pass
            except Exception as error:  # noqa: BLE001 -- any failure must reach the browser
                events.put(("fail", {"message": f"The search failed: {error}"}))
            finally:
                self.server.search_slots.release()

        threading.Thread(target=run_search, daemon=True).start()

        try:
            self.send_event("start", {"username": username, "total": len(site_data)})
            while True:
                try:
                    event, payload = events.get(timeout=KEEP_ALIVE_SECONDS)
                except queue.Empty:
                    # Lets us notice a closed tab while slow sites respond.
                    self.wfile.write(b": keep-alive\n\n")
                    self.wfile.flush()
                    continue
                self.send_event(event, payload)
                if event in ("done", "fail"):
                    break
        except OSError:
            # The browser went away (tab closed, or "Stop" was pressed).
            pass
        finally:
            cancelled.set()


def load_sites(local: bool = False, json_file: str | None = None,
               honor_exclusions: bool = True) -> SitesInformation:
    """Load the site list, preferring the up-to-date online one like the CLI."""
    if local:
        return SitesInformation(LOCAL_MANIFEST, honor_exclusions=False)
    try:
        return SitesInformation(data_file_path=json_file, honor_exclusions=honor_exclusions)
    except Exception as error:
        if json_file:
            raise
        print(f"Warning: {error}\nFalling back to the bundled site list.", file=sys.stderr)
        return SitesInformation(LOCAL_MANIFEST, honor_exclusions=False)


def port_number(value: str) -> int:
    try:
        port = int(value)
    except ValueError:
        raise ArgumentTypeError(f"Invalid port: {value}")
    if not 0 <= port <= 65535:
        raise ArgumentTypeError(f"Invalid port: {value}")
    return port


def positive_seconds(value: str) -> float:
    try:
        seconds = float(value)
    except ValueError:
        raise ArgumentTypeError(f"Invalid timeout: {value}")
    if seconds <= 0:
        raise ArgumentTypeError(f"Invalid timeout: {value}. Must be a positive number.")
    return seconds


def main():
    parser = ArgumentParser(
        prog="sherlock-web",
        formatter_class=RawDescriptionHelpFormatter,
        description=f"{__longname__} - Web Interface (Version {__version__})",
    )
    parser.add_argument("--host", default="127.0.0.1",
                        help="Address to listen on (Default: 127.0.0.1). Anyone who can reach "
                             "the address can run searches from this machine.")
    parser.add_argument("--port", "-P", type=port_number, default=8080,
                        help="Port to listen on (Default: 8080)")
    parser.add_argument("--timeout", type=positive_seconds, default=30,
                        help="Time (in seconds) to wait for response to requests (Default: 30)")
    parser.add_argument("--proxy", "-p", metavar="PROXY_URL", default=None,
                        help="Make requests over a proxy. e.g. socks5://127.0.0.1:1080")
    parser.add_argument("--json", "-j", metavar="JSON_FILE", dest="json_file", default=None,
                        help="Load data from a JSON file or an online, valid, JSON file.")
    parser.add_argument("--local", "-l", action="store_true", default=False,
                        help="Force the use of the local data.json file.")
    parser.add_argument("--ignore-exclusions", action="store_true", default=False,
                        help="Ignore upstream exclusions (may return more false positives)")
    parser.add_argument("--max-searches", type=int, default=4,
                        help="Number of searches allowed to run at the same time (Default: 4)")
    parser.add_argument("--verbose", "-v", action="store_true", default=False,
                        help="Log every request (the log will contain the usernames searched for).")
    args = parser.parse_args()

    if args.max_searches < 1:
        parser.error("--max-searches must be at least 1")

    try:
        sites = load_sites(args.local, args.json_file, not args.ignore_exclusions)
        server = SherlockWebServer(
            (args.host, args.port),
            sites,
            timeout=args.timeout,
            proxy=args.proxy,
            max_searches=args.max_searches,
            verbose=args.verbose,
        )
    except (OSError, ValueError) as error:
        # Site list problems, or the address/port cannot be used.
        print(f"ERROR:  {error}", file=sys.stderr)
        sys.exit(1)

    host, port = server.server_address[:2]
    shown_host = f"[{host}]" if ":" in host else host
    print(f"Sherlock web interface running on http://{shown_host}:{port} (Ctrl+C to stop)")
    if not server.loopback_only:
        print("Warning: listening on a non-local address without any authentication.")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print()
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
