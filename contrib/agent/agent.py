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
import base64
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
MAX_HTTP_BODY = 1 << 20
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

        self.server_url = env.get("WGPM_URL", "")
        self.token = env.get("WGPM_TOKEN", "")
        self.peer_id = env.get("WGPM_PEER_ID", "")
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
            raise AgentError("WGPM_URL and a wgpt_... WGPM_TOKEN are required")
        parsed = parse_base_url(self.server_url, ("https",), "WGPM_URL")
        if parsed.scheme != "https":
            raise AgentError("WGPM_URL must use https://")
        if not self.peer_id or len(self.peer_id) > 255 or any(
                char in self.peer_id for char in "\r\n\0"):
            raise AgentError("WGPM_PEER_ID is required and must be a safe peer id")
        if self.webhook_tolerance < 0 or self.poll_seconds < 0:
            raise AgentError("WGPM_WEBHOOK_TOLERANCE and WGPM_POLL_SECONDS must be non-negative")
        if self.client == "qbittorrent" and not self.qbit_url:
            raise AgentError("QBIT_URL is required for WGPM_CLIENT=qbittorrent")
        if self.client == "transmission" and not self.tr_host:
            raise AgentError("TR_HOST is required for WGPM_CLIENT=transmission")
        if self.client == "deluge" and not self.deluge_host:
            raise AgentError("DELUGE_HOST is required for WGPM_CLIENT=deluge")
        client_urls = {
            "qbittorrent": (self.qbit_url, "QBIT_URL"),
            "transmission": (self.tr_host, "TR_HOST"),
            "deluge": (self.deluge_host, "DELUGE_HOST"),
        }
        client_url, label = client_urls[self.client]
        parse_base_url(client_url, label=label)

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
            return {"seq": 0, "extPort": None, "intPort": None, "ruleId": None}
        except (OSError, ValueError) as err:
            raise AgentError(f"state file {self.path} is unreadable: {err}")
        if not isinstance(data, dict) or "seq" not in data:
            raise AgentError(f"state file {self.path} has an invalid structure")
        try:
            loaded = {
                "seq": int(data.get("seq") or 0),
                "extPort": data.get("extPort"),
                "intPort": data.get("intPort"),
                "ruleId": data.get("ruleId"),
            }
        except (TypeError, ValueError) as err:
            raise AgentError(f"state file {self.path} has invalid values: {err}")
        if loaded["seq"] < 0 or any(
                value is not None and (type(value) is not int or not 1 <= value <= 65535)
                for value in (loaded["extPort"], loaded["intPort"])) \
                or (loaded["ruleId"] is not None and not isinstance(loaded["ruleId"], str)):
            raise AgentError(f"state file {self.path} has invalid values")
        return loaded

    def save(self, state):
        directory = os.path.dirname(os.path.abspath(self.path)) or "."
        tmp = os.path.join(directory, f".{os.path.basename(self.path)}.{os.getpid()}.tmp")
        try:
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
            fd = os.open(tmp, flags, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                json.dump(state, handle)
                handle.flush()
                os.fsync(handle.fileno())
            # The rename is the commit point: a crash before it leaves the
            # previous state fully intact.
            os.replace(tmp, self.path)
            flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
            directory_fd = os.open(directory, flags)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
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


def parse_base_url(base_url, allowed_schemes=("http", "https"), label="URL"):
    try:
        parsed = urllib.parse.urlsplit(base_url)
    except ValueError as err:
        raise AgentError(f"{label} is invalid: {err}")
    if parsed.scheme not in allowed_schemes:
        choices = " or ".join(f"{scheme}://" for scheme in allowed_schemes)
        raise AgentError(f"{label} must use {choices}")
    if not parsed.hostname or parsed.username is not None or parsed.password is not None:
        raise AgentError(f"{label} must have a host and must not contain credentials")
    if parsed.query or parsed.fragment:
        raise AgentError(f"{label} must not contain a query or fragment")
    try:
        parsed.port
    except ValueError as err:
        raise AgentError(f"{label} is invalid: {err}")
    return parsed


class HttpJson:
    """One-shot requests through http.client; no redirects, no shell-outs.

    Returns (status, headers, body_bytes) where headers is a dict with
    lowercased keys. `data` is JSON-encoded, `form` is urlencoded.
    """

    def __init__(self, base_url, connector=None):
        self.parsed = parse_base_url(base_url)
        self.connector = connector

    def _full_path(self, path):
        if not isinstance(path, str) or not path.startswith("/"):
            raise AgentError("HTTP request path must start with /")
        base = self.parsed.path.rstrip("/")
        return f"{base}{path}" or "/"

    def request(self, method, path, headers=None, data=None, form=None):
        headers = {str(k).lower(): v for k, v in (headers or {}).items()}
        body = b""
        if data is not None:
            body = json.dumps(data).encode()
            headers.setdefault("content-type", "application/json")
        elif form is not None:
            body = urllib.parse.urlencode(form).encode()
            headers.setdefault("content-type", "application/x-www-form-urlencoded")
        path = self._full_path(path)
        try:
            if self.connector is not None:
                response = self.connector.request(method, path, headers=headers, body=body)
            else:
                response = self._request_live(method, path, headers, body)
        except AgentError:
            raise
        except (OSError, http.client.HTTPException) as err:
            raise AgentError(f"HTTP request failed: {err}")
        status, response_headers, response_body = response
        response_headers = {str(key).lower(): value for key, value in response_headers.items()}
        if not isinstance(response_body, bytes):
            raise AgentError("HTTP response body was not bytes")
        if len(response_body) > MAX_HTTP_BODY:
            raise AgentError("HTTP response exceeded size limit")
        return status, response_headers, response_body

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
            response_body = response.read(MAX_HTTP_BODY + 1)
            if len(response_body) > MAX_HTTP_BODY:
                raise AgentError("HTTP response exceeded size limit")
            return response.status, {k.lower(): v for k, v in response.getheaders()}, response_body
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

    def _login(self):
        status, headers, _ = self.http.request(
            "POST", "/api/v2/auth/login",
            form={"username": self.user, "password": self.password},
        )
        if status != 200:
            raise AgentError(f"qbittorrent login failed (HTTP {status})")
        self._cookie = headers.get("set-cookie", "").split(";")[0] or None

    def _request(self, method, path, **kwargs):
        if not self._cookie:
            self._login()
        for attempt in range(2):
            response = self.http.request(
                method, path, headers=self._headers(), **kwargs,
            )
            if response[0] not in (401, 403) or attempt == 1:
                return response
            self._cookie = None
            self._login()
        raise AssertionError("unreachable")

    def _json(self, method, path):
        status, headers, body = self._request(method, path)
        try:
            payload = json.loads(body.decode() or "null")
        except (UnicodeDecodeError, ValueError):
            payload = None
        return status, headers, payload

    def get_listen_port(self):
        status, _, prefs = self._json("GET", "/api/v2/app/preferences")
        if status != 200 or not isinstance(prefs, dict) or not isinstance(prefs.get("listen_port"), int):
            raise AgentError("qbittorrent preferences read-back failed")
        return prefs["listen_port"]

    def set_listen_port(self, port):
        for attempt in (1, 2):
            status, _, _ = self._request(
                "POST", "/api/v2/app/setPreferences",
                form={"json": json.dumps({"listen_port": port})},
            )
            if status != 200:
                raise AgentError(f"qbittorrent setPreferences failed (HTTP {status})")
            if self.get_listen_port() == port:
                return True
            log.warning("qbittorrent read-back mismatch (attempt %d)", attempt)
        raise AgentError("qbittorrent did not adopt the new listen port after retry")

    def reannounce(self):
        status, _, _ = self._request(
            "POST", "/api/v2/torrents/reannounce",
            form={"hashes": "all"},
        )
        if status != 200:
            raise AgentError(f"qbittorrent reannounce failed (HTTP {status})")


class TransmissionAdapter:
    name = "transmission"

    def __init__(self, config, http):
        self.http = http
        credentials = f"{config.tr_user}:{config.tr_pass}".encode()
        self._authorization = "Basic " + base64.b64encode(credentials).decode("ascii")
        self._session_id = None

    def _call(self, payload):
        for attempt in range(2):
            headers = {"authorization": self._authorization}
            if self._session_id:
                headers["x-transmission-session-id"] = self._session_id
            status, resp_headers, body = self.http.request(
                "POST", "/transmission/rpc/", headers=headers, data=payload,
            )
            if status != 409:
                break
            if attempt == 1:
                raise AgentError("transmission rejected the session id twice")
            self._session_id = resp_headers.get("x-transmission-session-id")
            if not self._session_id:
                raise AgentError("transmission did not provide a session id")
        if status != 200:
            raise AgentError(f"transmission rpc failed (HTTP {status})")
        try:
            result = json.loads(body.decode())
        except (UnicodeDecodeError, ValueError):
            raise AgentError("transmission rpc returned invalid JSON")
        if not isinstance(result, dict) or result.get("result") != "success":
            message = result.get("result") if isinstance(result, dict) else "invalid response"
            raise AgentError(f"transmission rpc returned {message!r}")
        return result

    def get_listen_port(self):
        result = self._call({"method": "session-get"})
        port = result.get("arguments", {}).get("peer-port")
        if not isinstance(port, int):
            raise AgentError("transmission session-get omitted peer-port")
        return port

    def set_listen_port(self, port):
        for attempt in (1, 2):
            self._call({"method": "session-set", "arguments": {"peer-port": port}})
            if self.get_listen_port() == port:
                return True
            log.warning("transmission read-back mismatch (attempt %d)", attempt)
        raise AgentError("transmission did not adopt the new listen port after retry")

    def reannounce(self):
        self._call({"method": "torrent-reannounce"})


class DelugeAdapter:
    name = "deluge"

    def __init__(self, config, http):
        self.http = http
        self.password = config.deluge_pass
        self._rpc_id = 0
        self._authed = False
        self._cookie = None

    @staticmethod
    def _auth_failed(status, payload):
        if status in (401, 403):
            return True
        error = payload.get("error") if isinstance(payload, dict) else None
        if error is None:
            return False
        text = json.dumps(error, sort_keys=True).lower()
        return any(marker in text for marker in (
            "not authenticated", "authentication", "auth level", "session",
        ))

    def _rpc(self, method, params):
        if method != "auth.login" and not self._authed:
            self._login()
        for attempt in range(2):
            self._rpc_id += 1
            headers = {"cookie": self._cookie} if self._cookie else None
            status, response_headers, payload = self.http.json(
                "POST", "/json", headers=headers,
                data={"id": self._rpc_id, "method": method, "params": params},
            )
            cookie = response_headers.get("set-cookie", "").split(";", 1)[0]
            if cookie:
                self._cookie = cookie
            if self._auth_failed(status, payload) and method != "auth.login" and attempt == 0:
                self._authed = False
                self._cookie = None
                self._login()
                continue
            if status != 200 or not isinstance(payload, dict):
                raise AgentError(f"deluge rpc {method} failed (HTTP {status})")
            if payload.get("error") is not None:
                raise AgentError(f"deluge rpc {method} returned an error")
            return payload.get("result")
        raise AssertionError("unreachable")

    def _login(self):
        result = self._rpc("auth.login", [self.password])
        if result is not True and result != "AUTH_OK":
            raise AgentError("deluge auth.login failed")
        self._authed = True

    def set_listen_port(self, port):
        for attempt in (1, 2):
            self._rpc("core.set_config", [{
                "listen_ports": [port, port], "random_port": False,
            }])
            if self._rpc("core.get_listen_port", []) == port:
                return True
            log.warning("deluge read-back mismatch (attempt %d)", attempt)
        raise AgentError("deluge did not adopt the new listen port after retry")

    def get_listen_port(self):
        port = self._rpc("core.get_listen_port", [])
        if not isinstance(port, int):
            raise AgentError("deluge core.get_listen_port omitted the listen port")
        return port

    def reannounce(self):
        torrent_ids = self._rpc("core.get_session_state", [])
        if not isinstance(torrent_ids, list):
            log.warning("deluge returned no session state; skipping reannounce")
            return
        if torrent_ids:
            self._rpc("core.force_reannounce", [torrent_ids])


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
        if len(self._seen) >= SEEN_EVENTS_CAP:
            self._seen_set.discard(self._seen.popleft())
        self._seen.append(event_id)
        self._seen_set.add(event_id)

    def _profile(self):
        profile = self.server.profile()
        peer_id = profile.get("id")
        if not isinstance(peer_id, str) or len(peer_id) > 255 or not hmac.compare_digest(
                peer_id.encode("utf-8"), self.config.peer_id.encode("utf-8")):
            raise AgentError("peer token profile does not match WGPM_PEER_ID")
        return profile

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
        peer_id = payload.get("peerId")
        seq = payload.get("seq")
        if event not in ("port.changed", "port.confirmed", "port.deleted") \
                or not isinstance(event_id, str) or not event_id or len(event_id) > 255 \
                or type(seq) is not int or seq < 1:
            return 400
        if not isinstance(peer_id, str) or len(peer_id) > 255 or not hmac.compare_digest(
                peer_id.encode("utf-8"), self.config.peer_id.encode("utf-8")):
            # The server has one global webhook sink. Foreign peer events are
            # valid deliveries, but they must not affect this agent's seq.
            return 204

        with self.lock:
            if event_id in self._seen_set:
                log.info("dropping already-seen event %s", event_id)
                return 200
            if seq <= self.state["seq"]:
                log.info("dropping event seq=%d at or below state seq=%d", seq, self.state["seq"])
                return 200
            if event != "port.deleted" and (
                    not self._valid_port(payload.get("extPort"))
                    or not self._valid_port(payload.get("intPort"))):
                return 400
            if seq > self.state["seq"] + 1:
                log.info("seq gap %d -> %d: reconciling authoritative profile",
                         self.state["seq"], seq)

            # An event describes a changed rule, not necessarily the selected
            # rule. The profile is authoritative for lowest-extPort selection.
            self.reconcile(commit_seq=seq)
            self._remember(event_id)
            return 200

    @staticmethod
    def _valid_port(port):
        return type(port) is int and 1 <= port <= 65535

    # Set/read-back, probe, reannounce, then durable commit. A failure before
    # commit leaves seq/event dedupe untouched so webhook retries remain useful.
    def apply_rule(self, ext_port, int_port, rule_id=None, seq=None):
        with self.lock:
            effective_rule_id = rule_id
            if effective_rule_id is None and ext_port == self.state["extPort"] \
                    and int_port == self.state["intPort"]:
                effective_rule_id = self.state["ruleId"]
            desired_changed = ext_port != self.state["extPort"] \
                or int_port != self.state["intPort"]
            actual_port = self.adapter.get_listen_port()
            client_changed = actual_port != int_port
            if client_changed:
                log.info("setting listen port %d (external port %d)", int_port, ext_port)
                self.adapter.set_listen_port(int_port)
            if desired_changed or client_changed:
                self._probe(ext_port, int_port, effective_rule_id)
                self.adapter.reannounce()
            next_seq = self.state["seq"] if seq is None else seq
            next_state = {
                "seq": next_seq,
                "extPort": ext_port,
                "intPort": int_port,
                "ruleId": effective_rule_id,
            }
            if next_state != self.state:
                self._persist(next_state)
            return "changed" if desired_changed or client_changed else "no-change"

    def reconcile(self, commit_seq=None):
        with self.lock:
            profile = self._profile()
            forwards = [rule for rule in (profile.get("portForwards") or [])
                        if isinstance(rule, dict)
                        and self._valid_port(rule.get("extPort"))
                        and self._valid_port(rule.get("intPort"))]
            if not forwards:
                log.info("reconcile: peer has no forwards")
                next_state = {
                    "seq": self.state["seq"] if commit_seq is None else commit_seq,
                    "extPort": None, "intPort": None, "ruleId": None,
                }
                if next_state != self.state:
                    self._persist(next_state)
                return
            target = min(forwards, key=lambda rule: (
                rule["extPort"], rule["intPort"], str(rule.get("id") or ""),
            ))
            self.apply_rule(
                target["extPort"], target["intPort"], target.get("id"), seq=commit_seq,
            )

    def probe_current(self):
        """Probe the current port (used by --once when no change was needed)."""
        if self.state["extPort"] is not None and self.state["intPort"] is not None:
            self._probe(
                self.state["extPort"], self.state["intPort"], self.state["ruleId"],
            )

    def _probe(self, ext_port, int_port, rule_id=None):
        try:
            profile = self._profile()
            ref = None
            for index, rule in enumerate(profile.get("portForwards") or []):
                if isinstance(rule, dict) and rule.get("extPort") == ext_port \
                        and rule.get("intPort") == int_port \
                        and (rule_id is None or rule.get("id") == rule_id):
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

    def _persist(self, next_state):
        self.state_store.save(next_state)
        self.state = next_state


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
