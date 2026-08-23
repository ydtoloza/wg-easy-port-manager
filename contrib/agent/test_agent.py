#!/usr/bin/env python3
"""wgpm-agent contract tests — pure unittest, no network.

Run:  python3 -m unittest -v test_agent.py   (from contrib/agent/)
"""

import hashlib
import hmac
import json
import os
import tempfile
import unittest
import uuid
from unittest import mock

import agent
from agent import (
    Agent,
    AgentError,
    Config,
    HttpJson,
    ServerApi,
    StateStore,
    verify_signature,
)

NOW = 1_700_000_000
SECRET = "s3cret"
RULE_ID = "11111111-2222-3333-4444-555555555555"


def sign(secret, timestamp, body):
    mac = hmac.new(secret.encode(), f"{timestamp}.".encode() + body, hashlib.sha256).hexdigest()
    return f"t={timestamp},v1={mac}"


def make_config(**overrides):
    env = {
        "WGPM_SERVER_URL": "https://vpn.example.test",
        "WGPM_TOKEN": "wgpt_" + "a" * 64,
        "WGPM_CLIENT": "qbittorrent",
        "WGPM_STATE_FILE": "/nonexistent/state.json",
        "QBIT_URL": "http://127.0.0.1:8081",
        "QBIT_USER": "user",
        "QBIT_PASS": "pass",
        "WGPM_LISTEN": "127.0.0.1:8080",
    }
    env.update(overrides)
    return Config(env)


def event_body(seq=1, ext_port=20000, event="port.changed", event_id=None):
    return json.dumps({
        "v": 1,
        "event": event,
        "eventId": event_id or str(uuid.uuid4()),
        "peerId": "client1",
        "seq": seq,
        "proto": "both",
        "extPort": ext_port,
        "previousExtPort": None,
        "intPort": 12345,
        "ts": "2026-01-01T00:00:00Z",
    }).encode()


class FakeConnector:
    """Scripts HTTP responses and records every request."""

    def __init__(self):
        self.requests = []
        self.responses = []

    def respond(self, status=200, headers=None, body=b""):
        self.responses.append((status, headers or {}, body))

    def respond_json(self, payload, status=200, headers=None):
        self.respond(status, headers, json.dumps(payload).encode())

    def request(self, method, path, headers=None, body=b""):
        self.requests.append((method, path, headers, body))
        if not self.responses:
            raise AssertionError(f"unexpected HTTP request: {method} {path}")
        return self.responses.pop(0)


class FakeAdapter:
    def __init__(self):
        self.set_calls = []
        self.reannounce_calls = 0

    def set_listen_port(self, port):
        self.set_calls.append(port)
        return True

    def reannounce(self):
        self.reannounce_calls += 1


class MemoryStateStore:
    def __init__(self, state=None):
        self.state = dict(state or {"seq": 0, "extPort": None})
        self.saves = []

    def load(self):
        return dict(self.state)

    def save(self, state):
        self.saves.append(dict(state))
        self.state = dict(state)


class SpyAgent(Agent):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.reconcile_calls = 0

    def reconcile(self):
        self.reconcile_calls += 1


def make_agent(cls=Agent, *, config=None, adapter=None, server_connector=None,
               state=None, clock=None):
    config = config or make_config()
    adapter = adapter if adapter is not None else FakeAdapter()
    store = MemoryStateStore(state)
    server = ServerApi(HttpJson(config.server_url, connector=server_connector), config.token)
    instance = cls(config, store, adapter, server, clock=clock or (lambda: NOW))
    return instance, adapter, store


def script_probe(server_connector, verdict="ok", ext_port=20000, times=1):
    profile = {
        "id": "client1", "name": "client1", "address": "10.8.0.2", "addressV6": None,
        "portForwards": [{"id": RULE_ID, "proto": "both", "extPort": ext_port, "intPort": 12345}],
        "permissions": {"selfManagePorts": True},
    }
    probe = {"rule": {"proto": "both", "extPort": ext_port, "intPort": 12345},
             "rulePresent": True, "tunnelUp": True, "tcpConnectable": True,
             "verdict": verdict}
    for _ in range(times):
        server_connector.respond_json(profile)
        server_connector.respond_json(probe)


class TestHmacVerify(unittest.TestCase):
    def setUp(self):
        self.body = event_body()

    def test_valid_vector(self):
        header = sign(SECRET, NOW, self.body)
        self.assertTrue(verify_signature(SECRET, header, self.body, NOW, 120))

    def test_bad_signature(self):
        header = sign(SECRET, NOW, self.body)
        header = header[:-1] + ("0" if header[-1] != "0" else "1")
        self.assertFalse(verify_signature(SECRET, header, self.body, NOW, 120))

    def test_stale_timestamp_beyond_tolerance(self):
        header = sign(SECRET, NOW - 121, self.body)
        self.assertFalse(verify_signature(SECRET, header, self.body, NOW, 120))

    def test_future_timestamp_within_tolerance(self):
        header = sign(SECRET, NOW + 60, self.body)
        self.assertTrue(verify_signature(SECRET, header, self.body, NOW, 120))

    def test_missing_or_malformed_header(self):
        self.assertFalse(verify_signature(SECRET, None, self.body, NOW, 120))
        self.assertFalse(verify_signature(SECRET, "garbage", self.body, NOW, 120))

    def test_body_tamper_breaks_signature(self):
        header = sign(SECRET, NOW, self.body)
        self.assertFalse(verify_signature(SECRET, header, self.body + b"x", NOW, 120))


class TestSeqIdempotency(unittest.TestCase):
    def _agent(self, **kwargs):
        return make_agent(cls=SpyAgent, **kwargs)

    def test_replay_same_event_id_ignored(self):
        server = FakeConnector()
        agent_, adapter, _ = self._agent(server_connector=server)
        script_probe(server, ext_port=20000)
        body = event_body(seq=2, ext_port=20000, event_id="fixed-id")
        self.assertEqual(agent_.handle_webhook(body, None), 200)
        self.assertEqual(agent_.handle_webhook(body, None), 200)
        self.assertEqual(adapter.set_calls, [20000])

    def test_lower_seq_ignored(self):
        agent_, adapter, _ = self._agent(state={"seq": 5, "extPort": 20000})
        self.assertEqual(agent_.handle_webhook(event_body(seq=4, ext_port=21000), None), 200)
        self.assertEqual(agent_.handle_webhook(event_body(seq=5, ext_port=21000), None), 200)
        self.assertEqual(adapter.set_calls, [])

    def test_seq_gap_triggers_poll_path(self):
        server = FakeConnector()
        agent_, adapter, _ = self._agent(server_connector=server, state={"seq": 2, "extPort": 20000})
        # The event itself will be applied after the gap-triggered reconcile.
        script_probe(server, ext_port=20000)

        self.assertEqual(agent_.handle_webhook(event_body(seq=5, ext_port=20000), None), 200)
        self.assertEqual(agent_.reconcile_calls, 1)

        # A consecutive seq is no gap: reconcile is NOT triggered again.
        script_probe(server, ext_port=20001)
        self.assertEqual(agent_.handle_webhook(event_body(seq=6, ext_port=20001), None), 200)
        self.assertEqual(agent_.reconcile_calls, 1)


class TestChangeOnlyApplication(unittest.TestCase):
    def test_same_ext_port_skips_adapter_and_persists_seq(self):
        server = FakeConnector()
        agent_, adapter, store = make_agent(
            server_connector=server, state={"seq": 3, "extPort": 20000},
        )
        self.assertEqual(agent_.handle_webhook(event_body(seq=4, ext_port=20000), None), 200)
        self.assertEqual(adapter.set_calls, [])
        self.assertEqual(adapter.reannounce_calls, 0)
        self.assertEqual(store.state, {"seq": 4, "extPort": 20000})
        # No probe either: nothing changed.
        self.assertEqual(server.requests, [])

    def test_different_ext_port_applies_and_persists(self):
        server = FakeConnector()
        agent_, adapter, store = make_agent(
            server_connector=server, state={"seq": 3, "extPort": 20000},
        )
        script_probe(server, verdict="ok", ext_port=20001)

        self.assertEqual(agent_.handle_webhook(event_body(seq=4, ext_port=20001), None), 200)
        self.assertEqual(adapter.set_calls, [20001])
        self.assertEqual(adapter.reannounce_calls, 1)
        self.assertEqual(store.state, {"seq": 4, "extPort": 20001})

    def test_unsigned_body_rejected_off_loopback(self):
        config = make_config(WGPM_LISTEN="0.0.0.0:8080")
        agent_, adapter, _ = make_agent(config=config)
        self.assertEqual(agent_.handle_webhook(event_body(seq=1), None), 400)
        self.assertEqual(adapter.set_calls, [])

    def test_bad_signature_rejected(self):
        config = make_config(WGPM_WEBHOOK_SECRET=SECRET)
        agent_, _, _ = make_agent(config=config)
        header = sign("wrong-secret", NOW, event_body(seq=1))
        self.assertEqual(agent_.handle_webhook(event_body(seq=1), header), 400)


class TestAdapters(unittest.TestCase):
    def _config(self, client, **over):
        base = {
            "qbittorrent": {"WGPM_CLIENT": "qbittorrent",
                            "QBIT_URL": "http://127.0.0.1:8081",
                            "QBIT_USER": "user", "QBIT_PASS": "pass"},
            "transmission": {"WGPM_CLIENT": "transmission",
                             "TR_HOST": "127.0.0.1:9091",
                             "TR_USER": "user", "TR_PASS": "pass"},
            "deluge": {"WGPM_CLIENT": "deluge",
                       "DELUGE_HOST": "127.0.0.1:8112",
                       "DELUGE_PASS": "pass"},
        }[client]
        base.update(over)
        return make_config(**base)

    def test_qbittorrent_sequence(self):
        connector = FakeConnector()
        adapter = agent.QbittorrentAdapter(self._config("qbittorrent"),
                                           HttpJson("http://127.0.0.1:8081", connector))
        connector.respond(200, {"set-cookie": "SID=abc; Path=/"}, b"Ok.")
        connector.respond(200)
        connector.respond_json({"listen_port": 9000})
        self.assertTrue(adapter.set_listen_port(9000))
        connector.respond(200)
        adapter.reannounce()

        methods_paths = [(m, p) for m, p, _, _ in connector.requests]
        self.assertEqual(methods_paths, [
            ("POST", "/api/v2/auth/login"),
            ("POST", "/api/v2/app/setPreferences"),
            ("GET", "/api/v2/app/preferences"),
            ("POST", "/api/v2/torrents/reannounce"),
        ])
        login_headers = connector.requests[0][2]
        self.assertEqual(login_headers["content-type"], "application/x-www-form-urlencoded")
        self.assertIn(b"username=user", connector.requests[0][3])
        set_headers = connector.requests[1][2]
        self.assertEqual(set_headers["cookie"], "SID=abc")
        self.assertIn(b"listen_port%22%3A+9000", connector.requests[1][3])
        self.assertIn(b"hashes=all", connector.requests[3][3])

    def test_qbittorrent_readback_failure_retries_then_errors(self):
        connector = FakeConnector()
        adapter = agent.QbittorrentAdapter(self._config("qbittorrent"),
                                           HttpJson("http://x", connector))
        connector.respond(200, {"set-cookie": "SID=abc"}, b"Ok.")
        connector.respond(200)
        connector.respond_json({"listen_port": 8000})       # wrong
        connector.respond(200)
        connector.respond_json({"listen_port": 8000})       # still wrong
        with self.assertRaises(AgentError):
            adapter.set_listen_port(9000)
        methods_paths = [(m, p) for m, p, _, _ in connector.requests]
        self.assertEqual(methods_paths, [
            ("POST", "/api/v2/auth/login"),
            ("POST", "/api/v2/app/setPreferences"),
            ("GET", "/api/v2/app/preferences"),
            ("POST", "/api/v2/app/setPreferences"),
            ("GET", "/api/v2/app/preferences"),
        ])

    def test_transmission_sequence(self):
        connector = FakeConnector()
        adapter = agent.TransmissionAdapter(self._config("transmission"),
                                            HttpJson("http://127.0.0.1:9091", connector))
        connector.respond(409, {"x-transmission-session-id": "SID42"}, b"")
        connector.respond_json({"result": "success", "arguments": {}})
        connector.respond_json({"result": "success"})
        connector.respond_json({"result": "success", "arguments": {"peer-port": 51413}})
        self.assertTrue(adapter.set_listen_port(51413))
        connector.respond_json({"result": "success"})
        adapter.reannounce()

        methods_paths = [(m, p) for m, p, _, _ in connector.requests]
        self.assertEqual(methods_paths, [
            ("POST", "/transmission/rpc/"),   # handshake -> 409
            ("POST", "/transmission/rpc/"),   # handshake retry with session id
            ("POST", "/transmission/rpc/"),   # session-set
            ("POST", "/transmission/rpc/"),   # session-get read-back
            ("POST", "/transmission/rpc/"),   # torrent-reannounce
        ])
        bodies = [json.loads(b[3]) for b in connector.requests]
        self.assertEqual(bodies[2], {"method": "session-set", "arguments": {"peer-port": 51413}})
        self.assertEqual(bodies[4], {"method": "torrent-reannounce", "arguments": {"ids": "all"}})
        self.assertEqual(connector.requests[1][2]["x-transmission-session-id"], "SID42")

    def test_deluge_sequence(self):
        connector = FakeConnector()
        adapter = agent.DelugeAdapter(self._config("deluge"),
                                      HttpJson("http://127.0.0.1:8112", connector))
        connector.respond_json({"id": 1, "result": True, "error": None})
        connector.respond_json({"id": 2, "result": None, "error": None})
        connector.respond_json({"id": 3, "result": {"listen_ports": [7000, 7000]}, "error": None})
        self.assertTrue(adapter.set_listen_port(7000))
        connector.respond_json({"id": 4, "result": ["t1", "t2"], "error": None})
        connector.respond_json({"id": 5, "result": None, "error": None})
        connector.respond_json({"id": 6, "result": None, "error": None})
        adapter.reannounce()

        rpcs = [json.loads(r[3])["method"] for r in connector.requests]
        self.assertEqual(rpcs, [
            "auth.login",
            "core.set_config",
            "core.get_config",
            "core.get_torrents_list",
            "core.force_reannounce",
            "core.force_reannounce",
        ])
        set_config = json.loads(connector.requests[1][3])
        self.assertEqual(set_config["params"], [{"listen_ports": [7000, 7000]}])
        self.assertEqual(json.loads(connector.requests[4][3])["params"], ["t1"])

    def test_deluge_readback_failure_retries_then_errors(self):
        connector = FakeConnector()
        adapter = agent.DelugeAdapter(self._config("deluge"),
                                      HttpJson("http://x", connector))
        connector.respond_json({"id": 1, "result": True, "error": None})
        connector.respond_json({"id": 2, "result": None, "error": None})
        connector.respond_json({"id": 3, "result": {"listen_ports": [6999, 6999]}, "error": None})
        connector.respond_json({"id": 4, "result": None, "error": None})
        connector.respond_json({"id": 5, "result": {"listen_ports": [6999, 6999]}, "error": None})
        with self.assertRaises(AgentError):
            adapter.set_listen_port(7000)
        rpcs = [json.loads(r[3])["method"] for r in connector.requests]
        self.assertEqual(rpcs, [
            "auth.login", "core.set_config", "core.get_config",
            "core.set_config", "core.get_config",
        ])


class TestReconcile(unittest.TestCase):
    def test_reconcile_targets_lowest_forward(self):
        server = FakeConnector()
        agent_, adapter, store = make_agent(server_connector=server,
                                            state={"seq": 0, "extPort": None})
        low_rule_id = "22222222-3333-4444-5555-666666666666"
        profile = {
            "id": "client1", "name": "client1", "address": "10.8.0.2", "addressV6": None,
            "portForwards": [
                {"id": RULE_ID, "proto": "tcp", "extPort": 20500, "intPort": 1},
                {"id": low_rule_id, "proto": "udp", "extPort": 20100, "intPort": 2},
            ],
            "permissions": {"selfManagePorts": True},
        }
        # reconcile -> profile; apply -> probe needs profile + probe
        server.respond_json(profile)
        server.respond_json(profile)
        server.respond_json({"verdict": "ok"})
        agent_.reconcile()
        self.assertEqual(adapter.set_calls, [20100])
        self.assertEqual(store.state, {"seq": 1, "extPort": 20100})
        # probe used the matched rule's stable id, not a positional index
        self.assertTrue(server.requests[-1][1].endswith(f"/{low_rule_id}/probe"))
        # Bearer token in the Authorization header only, never in a path
        self.assertIn("Bearer ", server.requests[-1][2]["authorization"])
        self.assertNotIn("wgpt_", server.requests[-1][1])

    def test_once_exit_code_maps_verdict(self):
        server = FakeConnector()
        agent_, adapter, _ = make_agent(server_connector=server,
                                        state={"seq": 1, "extPort": 20000})
        profile = {
            "id": "client1", "portForwards": [{"id": RULE_ID, "proto": "both",
                                               "extPort": 20000, "intPort": 1}],
        }
        server.respond_json(profile)  # reconcile: no change
        server.respond_json(profile)  # probe_current: profile
        server.respond_json({"verdict": "tunnel-down"})
        self.assertEqual(agent.run_once(agent_), 2)


class TestStateAtomicity(unittest.TestCase):
    def test_crash_between_write_and_rename_leaves_old_state(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "state.json")
            store = StateStore(path)
            store.save({"seq": 1, "extPort": 5000})
            self.assertEqual(os.stat(path).st_mode & 0o777, 0o600)

            with mock.patch("os.replace", side_effect=OSError("simulated crash")):
                with self.assertRaises(AgentError):
                    store.save({"seq": 2, "extPort": 6000})

            self.assertEqual(store.load(), {"seq": 1, "extPort": 5000})
            # no leftovers that a later load could mistake for state
            leftovers = [name for name in os.listdir(tmp) if name != "state.json"]
            self.assertEqual(leftovers, [])

    def test_load_defaults_for_missing_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = StateStore(os.path.join(tmp, "absent.json"))
            self.assertEqual(store.load(), {"seq": 0, "extPort": None})


if __name__ == "__main__":
    unittest.main()
