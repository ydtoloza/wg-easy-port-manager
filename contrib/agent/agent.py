#!/usr/bin/env python3
"""wgpm-agent — client-side port receiver for wg-easy-port-manager.

Runs on the box behind CGNAT (the one with the torrent client) and closes
the loop: signed webhook -> set the client's listen port -> reannounce.

Dependency-free Python 3.9+ (stdlib only, no shell-outs, no third-party
HTTP libraries). Configuration is env-only (see README.md). The peer token
never appears in logs, argv or URLs; it is sent as an Authorization: Bearer
header and read from the environment.

Modes:
  daemon (default)  HTTP listener for webhooks + periodic reconcile poll
  --once            reconcile once and exit with the probe verdict
                    (0 ok, 1 unreachable, 2 tunnel-down, 3 rule-missing,
                     4 probe unavailable, 5 adapter failure)
"""

import argparse
import hashlib
import hmac
import http.client
import json
import logging
import os
import ssl
import sys
import threading
import time
import urllib.parse
from collections import deque

log = logging.getLogger("wgpm-agent")

SEEN_EVENTS_CAP = 256
HTTP_TIMEOUT = 10
MAX_WEBHOOK_BODY = 1 << 20
PROBE_EXIT_CODES = {
    "ok": 0,
    "unreachable": 1,
    "tunnel-down": 2,
    "rule-missing": 3,
    # dnat-local means the connect succeeded from the server box itself
    # (hairpin path); treat as success with a caveat in the log.
    "dnat-local": 0,
}
EXIT_PROBE_UNAVAILABLE = 4
EXIT_APPLY_FAILED = 5


class AgentError(Exception):
    """Fatal, operator-visible failure."""


# ── configuration ──────────────────────────────────────────────────────────


class Config:
    def __init__(self, env=None):
        env = os.environ if env is None else env

        def num(name, default):
            raw = env.get(name, "").strip()
            if not raw:
                return default
            try:
                return int(raw)
            except ValueError:
                raise AgentError(f"{name} must be an integer, got {raw!r}")

        self.server_url = env.get("WGPM_SERVER_URL", "").rstrip("/")
        self.token = env.get("WGPM_TOKEN", "")
        self.client = env.get("WGPM_CLIENT", "").lower()
        self.state_file = env.get(
            "WGPM_STATE_FILE",
            os.path.join(os.path.expanduser("~"), ".wgpm-agent.json"),
        )
        self.webhook_tolerance = num("WGPM_WEBHOOK_TOLERANCE", 120)
        self.poll_seconds = num("WGPM_POLL_SECONDS", 300)
        self.listen = env.get("WGPM_LISTEN", "127.0.0.1:8080")
        self.webhook_secret = env.get("WGPM_WEBHOOK_SECRET", "")

        self.qbit_url = env.get("QBIT_URL", "")
        self.qbit_user = env.get("QBIT_USER", "")
        self.qbit_pass = env.get("QBIT_PASS", "")
        self.tr_host = env.get("TR_HOST", "")
        self.tr_user = env.get("TR_USER", "")
        self.tr_pass = env.get("TR_PASS", "")
        self.deluge_host = env.get("DELUGE_HOST", "")
        self.deluge_pass = env.get("DELUGE_PASS", "")

    def validate(self):
        if self.client not in ("qbittorrent", "transmission", "deluge"):
            raise AgentError("WGPM_CLIENT must be qbittorrent, transmission or deluge")
        if not self.server_url or not self.token.startswith("wgpt_"):
            raise AgentError("WGPM_SERVER_URL and a wgpt_... WGPM_TOKEN are required")
        if self.client == "qbittorrent" and not self.qbit_url:
            raise AgentError("QBIT_URL is required for WGPM_CLIENT=qbittorrent")
        if self.client == "transmission" and not self.tr_host:
            raise AgentError("TR_HOST is required for WGPM_CLIENT=transmission")
        if self.client == "deluge" and not self.deluge_host:
            raise AgentError("DELUGE_HOST is required for WGPM_CLIENT=deluge")

    def listener_is_loopback(self):
        host = self.listen.rsplit(":", 1)[0].strip("[]")
        return host in ("127.0.0.1", "::1", "localhost")


# ── state (atomic tmp+rename, chmod 0600) ──────────────────────────────────


class StateStore:
    def __init__(self, path):
        self.path = path

    def load(self):
        try:
            with open(self.path, "r", encoding="utf-8") as handle:
                data = json.load(handle)
        except FileNotFoundError:
            return {"seq": 0, "extPort": None}
        except (OSError, ValueError) as err:
            raise AgentError(f"state file {self.path} is unreadable: {err}")
        if not isinstance(data, dict) or "seq" not in data:
            raise AgentError(f"state file {self.path} has an invalid structure")
        return {
            "seq": int(data.get("seq") or 0),
            "extPort": data.get("extPort"),
        }

    def save(self, state):
        directory = os.path.dirname(os.path.abspath(self.path)) or "."
        tmp = os.path.join(directory, f".{os.path.basename(self.path)}.{os.getpid()}.tmp")
        try:
            with open(tmp, "w", encoding="utf-8") as handle:
                json.dump(state, handle)
                handle.flush()
                os.fsync(handle.fileno())
            os.chmod(tmp, 0o600)
            # The rename is the commit point: a crash before it leaves the
            # previous state fully intact.
            os.replace(tmp, self.path)
        except OSError as err:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise AgentError(f"could not persist state atomically: {err}")


# ── webhook signature ──────────────────────────────────────────────────────


def verify_signature(secret, header, body, now, tolerance):
    """X-WGPM-Signature is 't=<unix>,v1=<hex>' over '<t>.<raw body>'."""
    if not secret or not header:
        return False
    parts = {}
    for chunk in header.split(","):
        if "=" not in chunk:
            continue
        key, _, value = chunk.partition("=")
        parts[key.strip()] = value.strip()
    try:
        timestamp = int(parts["t"])
    except (KeyError, ValueError):
        return False
    signature = parts.get("v1", "")
    if abs(now - timestamp) > tolerance:
        return False
    payload = f"{timestamp}.".encode() + body
    expected = hmac.new(secret.encode(), payload, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature.lower())


# ── tiny HTTP layer (stdlib http.client, injectable for tests) ─────────────


class HttpJson:
    """One-shot requests through http.client; no redirects, no shell-outs.

    Returns (status, headers, body_bytes) where headers is a dict with
    lowercased keys. `data` is JSON-encoded, `form` is urlencoded.
    """

    def __init__(self, base_url, connector=None):
        self.parsed = urllib.parse.urlparse(base_url if "://" in base_url else f"http://{base_url}")
        self.connector = connector

    def request(self, method, path, headers=None, data=None, form=None):
        headers = {str(k).lower(): v for k, v in (headers or {}).items()}
        body = b""
        if data is not None:
            body = json.dumps(data).encode()
            headers.setdefault("content-type", "application/json")
        elif form is not None:
            body = urllib.parse.urlencode(form).encode()
            headers.setdefault("content-type", "application/x-www-form-urlencoded")
        if self.connector is not None:
            return self.connector.request(method, path, headers=headers, body=body)
        return self._request_live(method, path, headers, body)

    def _request_live(self, method, path, headers, body):
        if self.parsed.scheme == "https":
            conn = http.client.HTTPSConnection(
                self.parsed.hostname, self.parsed.port, timeout=HTTP_TIMEOUT,
                context=ssl.create_default_context(),
            )
        else:
            conn = http.client.HTTPConnection(
                self.parsed.hostname, self.parsed.port, timeout=HTTP_TIMEOUT,
            )
        try:
            conn.request(method, path, body=body, headers=headers)
            response = conn.getresponse()
            return response.status, {k.lower(): v for k, v in response.getheaders()}, response.read()
        finally:
            conn.close()

    def json(self, method, path, headers=None, data=None, form=None):
        status, resp_headers, body = self.request(method, path, headers, data, form)
        try:
            parsed = json.loads(body.decode() or "null")
        except ValueError:
            parsed = None
        return status, resp_headers, parsed


# ── wg-easy server API ─────────────────────────────────────────────────────


class ServerApi:
    def __init__(self, http, token):
        self.http = http
        self.token = token

    def _headers(self):
        # Token only ever lives in this header — never in a URL or a log line.
        return {"Authorization": f"Bearer {self.token}"}

    def profile(self):
        status, _, payload = self.http.json("GET", "/api/peer/me", headers=self._headers())
        if status != 200 or not isinstance(payload, dict):
            raise AgentError(f"peer profile request failed (HTTP {status})")
        return payload

    def probe(self, ref):
        status, _, payload = self.http.json(
            "GET", f"/api/peer/me/port-forward/{urllib.parse.quote(str(ref), safe='')}/probe",
            headers=self._headers(),
        )
        if status != 200 or not isinstance(payload, dict):
            raise AgentError(f"probe request failed (HTTP {status})")
        return payload


# ── torrent client adapters ────────────────────────────────────────────────


class QbittorrentAdapter:
    name = "qbittorrent"

    def __init__(self, config, http):
        self.http = http
        self.user = config.qbit_user
        self.password = config.qbit_pass
        self._cookie = None

    def _headers(self):
        return {"cookie": self._cookie} if self._cookie else {}

    def set_listen_port(self, port):
        status, headers, _ = self.http.request(
            "POST", "/api/v2/auth/login",
            form={"username": self.user, "password": self.password},
        )
        if status != 200:
            raise AgentError(f"qbittorrent login failed (HTTP {status})")
        self._cookie = headers.get("set-cookie", "").split(";")[0] or None

        for attempt in (1, 2):
            status, _, _ = self.http.request(
                "POST", "/api/v2/app/setPreferences",
                headers=self._headers(),
                form={"json": json.dumps({"listen_port": port})},
            )
            if status != 200:
                raise AgentError(f"qbittorrent setPreferences failed (HTTP {status})")
            if self._read_back() == port:
                return True
            log.warning("qbittorrent read-back mismatch (attempt %d)", attempt)
        raise AgentError("qbittorrent did not adopt the new listen port after retry")

    def _read_back(self):
        status, _, prefs = self.http.json("GET", "/api/v2/app/preferences", headers=self._headers())
        if status != 200 or not isinstance(prefs, dict):
            raise AgentError("qbittorrent preferences read-back failed")
        return prefs.get("listen_port")

    def reannounce(self):
        status, _, _ = self.http.request(
            "POST", "/api/v2/torrents/reannounce",
            headers=self._headers(),
            form={"hashes": "all"},
        )
        if status != 200:
            raise AgentError(f"qbittorrent reannounce failed (HTTP {status})")


class TransmissionAdapter:
    name = "transmission"

    def __init__(self, config, http):
        self.http = http

    def _call(self, payload, session_id=None):
        headers = {"x-transmission-session-id": session_id} if session_id else {}
        status, resp_headers, body = self.http.request(
            "POST", "/transmission/rpc/", headers=headers, data=payload,
        )
        if status == 409:
            sid = resp_headers.get("x-transmission-session-id")
            if not sid:
                raise AgentError("transmission did not provide a session id")
            return self._call(payload, session_id=sid)
        if status != 200:
            raise AgentError(f"transmission rpc failed (HTTP {status})")
        try:
            return json.loads(body.decode())
        except ValueError:
            raise AgentError("transmission rpc returned invalid JSON")

    def set_listen_port(self, port):
        self._call({"method": "session-get"})
        for attempt in (1, 2):
            self._call({"method": "session-set", "arguments": {"peer-port": port}})
            result = self._call({"method": "session-get"})
            if result.get("arguments", {}).get("peer-port") == port:
                return True
            log.warning("transmission read-back mismatch (attempt %d)", attempt)
        raise AgentError("transmission did not adopt the new listen port after retry")

    def reannounce(self):
        self._call({"method": "torrent-reannounce", "arguments": {"ids": "all"}})


class DelugeAdapter:
    name = "deluge"

    def __init__(self, config, http):
        self.http = http
        self.password = config.deluge_pass
        self._rpc_id = 0
        self._authed = False

    def _rpc(self, method, params):
        self._rpc_id += 1
        status, _, payload = self.http.json(
            "POST", "/json", data={"id": self._rpc_id, "method": method, "params": params},
        )
        if status != 200 or not isinstance(payload, dict):
            raise AgentError(f"deluge rpc {method} failed (HTTP {status})")
        if payload.get("error") is not None:
            raise AgentError(f"deluge rpc {method} returned an error")
        return payload.get("result")

    def _login(self):
        result = self._rpc("auth.login", [self.password])
        if result is not True and result != "AUTH_OK":
            raise AgentError("deluge auth.login failed")
        self._authed = True

    def set_listen_port(self, port):
        if not self._authed:
            self._login()
        for attempt in (1, 2):
            self._rpc("core.set_config", [{"listen_ports": [port, port]}])
            config = self._rpc("core.get_config", [])
            if isinstance(config, dict) and config.get("listen_ports") == [port, port]:
                return True
            log.warning("deluge read-back mismatch (attempt %d)", attempt)
        raise AgentError("deluge did not adopt the new listen port after retry")

    def reannounce(self):
        if not self._authed:
            self._login()
        torrent_ids = self._rpc("core.get_torrents_list", [])
        if not isinstance(torrent_ids, list):
            log.warning("deluge returned no torrent list; skipping reannounce")
            return
        for torrent_id in torrent_ids:
            self._rpc("core.force_reannounce", [torrent_id])


def build_adapter(config, http_factory):
    if config.client == "qbittorrent":
        return QbittorrentAdapter(config, http_factory(config.qbit_url))
    if config.client == "transmission":
        return TransmissionAdapter(config, http_factory(config.tr_host))
    if config.client == "deluge":
        return DelugeAdapter(config, http_factory(config.deluge_host))
    raise AgentError(f"unsupported client {config.client!r}")


# ── agent core ─────────────────────────────────────────────────────────────


class Agent:
    def __init__(self, config, state_store, adapter, server_api, clock=time.time):
        self.config = config
        self.state_store = state_store
        self.adapter = adapter
        self.server = server_api
        self.clock = clock
        self.state = state_store.load()
        self.lock = threading.RLock()
        self._seen = deque()
        self._seen_set = set()
        self.last_verdict = None

    def _remember(self, event_id):
        self._seen.append(event_id)
        self._seen_set.add(event_id)
        if len(self._seen_set) > SEEN_EVENTS_CAP:
            # The deque holds the eviction order; rebuild the set from it.
            self._seen_set = set(self._seen)

    # webhook entry point; returns an HTTP status for the listener
    def handle_webhook(self, body, signature_header):
        if self.config.webhook_secret:
            if not verify_signature(
                self.config.webhook_secret, signature_header, body,
                int(self.clock()), self.config.webhook_tolerance,
            ):
                log.warning("rejected webhook with a bad or stale signature")
                return 400
        elif not self.config.listener_is_loopback():
            # Unsigned operation is only tolerable on a loopback listener.
            log.error("rejected unsigned webhook on a non-loopback listener")
            return 400

        try:
            payload = json.loads(body.decode())
        except (UnicodeDecodeError, ValueError):
            return 400
        if not isinstance(payload, dict):
            return 400
        event = payload.get("event")
        event_id = payload.get("eventId")
        seq = payload.get("seq")
        if event not in ("port.changed", "port.confirmed", "port.deleted") \
                or not isinstance(event_id, str) or not isinstance(seq, int):
            return 400

        with self.lock:
            if event_id in self._seen_set:
                log.info("dropping already-seen event %s", event_id)
                return 200
            self._remember(event_id)

            if seq <= self.state["seq"]:
                log.info("dropping event seq=%d at or below state seq=%d", seq, self.state["seq"])
                return 200
            if seq > self.state["seq"] + 1:
                log.info("seq gap %d -> %d: reconciling before applying", self.state["seq"], seq)
                try:
                    self.reconcile()
                except AgentError as err:
                    log.error("gap reconcile failed: %s", err)

            if event == "port.deleted":
                # Deletions never re-point the client by themselves; polled
                # state decides the next target port.
                self._persist(seq=seq, ext_port=self.state["extPort"])
                if payload.get("extPort") == self.state["extPort"]:
                    try:
                        self.reconcile()
                    except AgentError as err:
                        log.error("post-delete reconcile failed: %s", err)
                return 200

            ext_port = payload.get("extPort")
            if not isinstance(ext_port, int):
                return 400
            self.apply_change(ext_port, seq=seq)
            return 200

    # steps 4-7 of the pipeline; raises AgentError on adapter failure
    def apply_change(self, ext_port, seq=None):
        with self.lock:
            if ext_port == self.state["extPort"]:
                # No client call; trackers penalize gratuitous reannounce.
                log.info("port %d already configured; persisting seq only", ext_port)
                self._persist(seq=self._seq_for(seq), ext_port=ext_port)
                return "no-change"

            log.info("applying new listen port %d", ext_port)
            self.adapter.set_listen_port(ext_port)
            self._probe(ext_port)
            self._persist(seq=self._seq_for(seq), ext_port=ext_port)
            self.adapter.reannounce()
            return "changed"

    def _seq_for(self, seq):
        return self.state["seq"] + 1 if seq is None else seq

    def reconcile(self):
        with self.lock:
            profile = self.server.profile()
            forwards = [rule for rule in (profile.get("portForwards") or [])
                        if isinstance(rule, dict) and isinstance(rule.get("extPort"), int)]
            if not forwards:
                log.info("reconcile: peer has no forwards")
                return
            target = min(rule["extPort"] for rule in forwards)
            if target != self.state["extPort"]:
                self.apply_change(target)
            else:
                log.info("reconcile: port %d already current", target)

    def probe_current(self):
        """Probe the current port (used by --once when no change was needed)."""
        if self.state["extPort"] is not None:
            self._probe(self.state["extPort"])

    def _probe(self, ext_port):
        try:
            profile = self.server.profile()
            ref = None
            for index, rule in enumerate(profile.get("portForwards") or []):
                if isinstance(rule, dict) and rule.get("extPort") == ext_port:
                    # Prefer the stable rule id; the numeric index is legacy.
                    ref = rule.get("id") if rule.get("id") else index
                    break
            if ref is None:
                log.warning("probe: no own forward with extPort %d", ext_port)
                self.last_verdict = None
                return
            result = self.server.probe(ref)
            self.last_verdict = result.get("verdict")
            log.info("probe extPort=%d verdict=%s", ext_port, self.last_verdict)
        except (AgentError, OSError) as err:
            log.warning("probe skipped: %s", err)
            self.last_verdict = None

    def _persist(self, seq, ext_port):
        self.state = {"seq": seq, "extPort": ext_port}
        self.state_store.save(self.state)


# ── listener + poller ──────────────────────────────────────────────────────


def make_handler(agent):
    from http.server import BaseHTTPRequestHandler

    class AgentHandler(BaseHTTPRequestHandler):
        def do_POST(self):  # noqa: N802 (http.server API)
            try:
                length = int(self.headers.get("Content-Length") or 0)
            except ValueError:
                length = 0
            if length <= 0 or length > MAX_WEBHOOK_BODY:
                self.send_response(400)
                self.end_headers()
                return
            body = self.rfile.read(length)
            try:
                status = agent.handle_webhook(body, self.headers.get("X-WGPM-Signature"))
            except AgentError as err:
                log.error("webhook apply failed: %s", err)
                status = 500  # server retries: delivery is at-least-once
            self.send_response(status)
            self.end_headers()

        def log_message(self, fmt, *args):  # route access logs through logging
            log.debug("http: " + fmt, *args)

    return AgentHandler


def serve(config, agent):
    from http.server import ThreadingHTTPServer

    host, _, port = config.listen.rpartition(":")
    host = host.strip("[]") or "127.0.0.1"
    server = ThreadingHTTPServer((host, int(port)), make_handler(agent))
    log.info("listening on %s", config.listen)

    if config.poll_seconds > 0:
        def poller():
            while True:
                time.sleep(config.poll_seconds)
                try:
                    agent.reconcile()
                except AgentError as err:
                    log.error("reconcile poll failed: %s", err)

        threading.Thread(target=poller, daemon=True).start()

    server.serve_forever()


def run_once(agent):
    try:
        agent.reconcile()
        if agent.last_verdict is None:
            agent.probe_current()
    except AgentError as err:
        log.error("reconcile failed: %s", err)
        return EXIT_APPLY_FAILED
    if agent.last_verdict is None:
        return EXIT_PROBE_UNAVAILABLE
    return PROBE_EXIT_CODES.get(agent.last_verdict, EXIT_PROBE_UNAVAILABLE)


def main(argv=None):
    parser = argparse.ArgumentParser(description="wg-easy port manager agent")
    parser.add_argument("--once", action="store_true",
                        help="reconcile once and exit with the probe verdict")
    parser.add_argument("--check", action="store_true",
                        help="validate configuration and exit")
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
    )

    try:
        config = Config()
        config.validate()
    except AgentError as err:
        log.error("%s", err)
        return 2

    if args.check:
        log.info("configuration ok (client=%s)", config.client)
        return 0

    state_store = StateStore(config.state_file)
    server_api = ServerApi(HttpJson(config.server_url), config.token)
    adapter = build_adapter(config, lambda base: HttpJson(base))
    agent = Agent(config, state_store, adapter, server_api)

    if args.once:
        return run_once(agent)
    serve(config, agent)
    return 0


if __name__ == "__main__":
    sys.exit(main())
