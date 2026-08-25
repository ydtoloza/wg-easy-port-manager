#!/usr/bin/env python3
"""wgpm-agent contract tests: stdlib unittest with no live network."""

import hashlib
import hmac
import json
import os
import tempfile
import unittest
from unittest import mock

import agent
from agent import Agent, AgentError, Config, HttpJson, ServerApi, StateStore

NOW = 1_700_000_000
SECRET = "secret"
PEER_ID = "client1"
RULE_ID = "11111111-2222-3333-4444-555555555555"


def make_config(**overrides):
    env = {
        "WGPM_URL": "https://vpn.example.test/wgpm",
        "WGPM_TOKEN": "wgpt_" + "a" * 64,
        "WGPM_PEER_ID": PEER_ID,
        "WGPM_CLIENT": "qbittorrent",
        "WGPM_STATE_FILE": "/nonexistent/state.json",
        "WGPM_LISTEN": "127.0.0.1:8080",
        "QBIT_URL": "http://127.0.0.1:8081/qbit",
        "QBIT_USER": "user",
        "QBIT_PASS": "pass",
    }
    env.update(overrides)
    return Config(env)


def state(seq=0, ext_port=None, int_port=None, rule_id=None):
    return {"seq": seq, "extPort": ext_port, "intPort": int_port, "ruleId": rule_id}


def event_body(seq=1, ext_port=20000, int_port=12345, event="port.changed",
               event_id="event-1", peer_id=PEER_ID):
    return json.dumps({
        "v": 1, "event": event, "eventId": event_id, "peerId": peer_id,
        "seq": seq, "proto": "both", "extPort": ext_port,
        "previousExtPort": None, "intPort": int_port,
        "ts": "2026-01-01T00:00:00Z",
    }).encode()


def sign(body, timestamp=NOW, secret=SECRET):
    digest = hmac.new(secret.encode(), f"{timestamp}.".encode() + body,
                      hashlib.sha256).hexdigest()
    return f"t={timestamp},v1={digest}"


def profile(ext_port=20000, int_port=12345, peer_id=PEER_ID, rules=None):
    return {
        "id": peer_id,
        "portForwards": rules if rules is not None else [{
            "id": RULE_ID, "proto": "both", "extPort": ext_port, "intPort": int_port,
        }],
    }


class FakeConnector:
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
        response = self.responses.pop(0)
        if isinstance(response, Exception):
            raise response
        return response


class FakeAdapter:
    def __init__(self, current_port=12345):
        self.current_port = current_port
        self.get_calls = 0
        self.set_calls = []
        self.reannounce_calls = 0
        self.fail_set = 0
        self.fail_reannounce = 0

    def get_listen_port(self):
        self.get_calls += 1
        return self.current_port

    def set_listen_port(self, port):
        self.set_calls.append(port)
        if self.fail_set:
            self.fail_set -= 1
            raise AgentError("set failed")
        self.current_port = port
        return True

    def reannounce(self):
        self.reannounce_calls += 1
        if self.fail_reannounce:
            self.fail_reannounce -= 1
            raise AgentError("reannounce failed")


class MemoryStateStore:
    def __init__(self, initial=None):
        self.state = dict(initial or state())
        self.saves = []
        self.fail_save = 0

    def load(self):
        return dict(self.state)

    def save(self, value):
        if self.fail_save:
            self.fail_save -= 1
            raise AgentError("save failed")
        self.state = dict(value)
        self.saves.append(dict(value))


def make_agent(*, config=None, adapter=None, connector=None, initial=None):
    config = config or make_config()
    adapter = adapter or FakeAdapter()
    store = MemoryStateStore(initial)
    server = ServerApi(HttpJson(config.server_url, connector), config.token)
    return Agent(config, store, adapter, server, clock=lambda: NOW), adapter, store


def script_apply(connector, ext_port=20000, int_port=12345):
    connector.respond_json(profile(ext_port, int_port))
    connector.respond_json({"verdict": "ok"})


class TestConfigAndHttp(unittest.TestCase):
    def test_config_requires_https_server_url_and_peer_id(self):
        for changes in (
                {"WGPM_URL": "http://vpn.example.test"},
                {"WGPM_URL": "ftp://vpn.example.test"},
                {"WGPM_URL": "vpn.example.test"},
                {"WGPM_URL": "https://user:pass@vpn.example.test"},
                {"WGPM_PEER_ID": ""}):
            with self.subTest(changes=changes), self.assertRaises(AgentError):
                make_config(**changes).validate()

    def test_config_accepts_https_base_path_and_explicit_client_urls(self):
        make_config().validate()
        make_config(WGPM_CLIENT="transmission", TR_HOST="http://127.0.0.1:9091/base").validate()
        make_config(WGPM_CLIENT="deluge", DELUGE_HOST="https://deluge.test/ui").validate()

    def test_base_path_is_preserved(self):
        connector = FakeConnector()
        connector.respond_json({"ok": True})
        status, _, _ = HttpJson("https://host.test/base/", connector).json("GET", "/api/test")
        self.assertEqual(status, 200)
        self.assertEqual(connector.requests[0][1], "/base/api/test")

    def test_response_size_is_bounded_for_injected_connections(self):
        connector = FakeConnector()
        connector.respond(body=b"x" * (agent.MAX_HTTP_BODY + 1))
        with self.assertRaisesRegex(AgentError, "size limit"):
            HttpJson("https://host.test", connector).request("GET", "/")

    def test_socket_errors_are_normalized_for_poller_retry(self):
        connector = FakeConnector()
        connector.responses.append(OSError("temporary outage"))
        with self.assertRaisesRegex(AgentError, "temporary outage"):
            HttpJson("https://host.test", connector).request("GET", "/")


class TestSignaturesAndPeerFiltering(unittest.TestCase):
    def test_signature_vectors(self):
        body = event_body()
        self.assertTrue(agent.verify_signature(SECRET, sign(body), body, NOW, 120))
        self.assertFalse(agent.verify_signature(SECRET, sign(body), body + b"x", NOW, 120))
        self.assertFalse(agent.verify_signature(SECRET, sign(body, NOW - 121), body, NOW, 120))
        self.assertFalse(agent.verify_signature(SECRET, None, body, NOW, 120))

    def test_foreign_peer_event_does_not_touch_seq_or_dedupe(self):
        instance, adapter, store = make_agent(initial=state(seq=8, ext_port=20000, int_port=12345))
        body = event_body(seq=99, peer_id="other-peer", event_id="shared")
        self.assertEqual(instance.handle_webhook(body, None), 204)
        self.assertEqual(store.state["seq"], 8)
        self.assertNotIn("shared", instance._seen_set)
        self.assertEqual(adapter.get_calls, 0)

    def test_profile_identity_must_match_configured_peer(self):
        connector = FakeConnector()
        connector.respond_json(profile(peer_id="other-peer"))
        instance, _, store = make_agent(connector=connector)
        with self.assertRaisesRegex(AgentError, "does not match"):
            instance.reconcile()
        self.assertEqual(store.state, state())

    def test_unsigned_non_loopback_listener_is_rejected(self):
        instance, _, _ = make_agent(config=make_config(WGPM_LISTEN="0.0.0.0:8080"))
        self.assertEqual(instance.handle_webhook(event_body(), None), 400)

    def test_signed_event_is_accepted(self):
        connector = FakeConnector()
        script_apply(connector)
        config = make_config(WGPM_WEBHOOK_SECRET=SECRET)
        instance, _, store = make_agent(config=config, connector=connector,
                                        initial=state(ext_port=19000, int_port=12345))
        body = event_body()
        self.assertEqual(instance.handle_webhook(body, sign(body)), 200)
        self.assertEqual(store.state["seq"], 1)


class TestEventTransactions(unittest.TestCase):
    def test_internal_port_is_applied_while_external_semantics_are_persisted(self):
        connector = FakeConnector()
        script_apply(connector, 22000, 12000)
        adapter = FakeAdapter(current_port=9999)
        instance, _, store = make_agent(adapter=adapter, connector=connector)
        self.assertEqual(instance.handle_webhook(event_body(ext_port=22000, int_port=12000), None), 200)
        self.assertEqual(adapter.set_calls, [12000])
        self.assertEqual(store.state, state(seq=1, ext_port=22000, int_port=12000))

    def test_reannounce_failure_leaves_event_retryable(self):
        connector = FakeConnector()
        script_apply(connector)
        script_apply(connector)
        adapter = FakeAdapter(current_port=9999)
        adapter.fail_reannounce = 1
        instance, _, store = make_agent(adapter=adapter, connector=connector)
        body = event_body(event_id="retry-me")
        with self.assertRaises(AgentError):
            instance.handle_webhook(body, None)
        self.assertEqual(store.state, state())
        self.assertNotIn("retry-me", instance._seen_set)
        self.assertEqual(instance.handle_webhook(body, None), 200)
        self.assertEqual(adapter.set_calls, [12345])
        self.assertEqual(adapter.reannounce_calls, 2)

    def test_persistence_failure_does_not_advance_in_memory_state_or_dedupe(self):
        connector = FakeConnector()
        script_apply(connector)
        script_apply(connector)
        instance, adapter, store = make_agent(connector=connector,
                                               initial=state(ext_port=19000, int_port=12345))
        store.fail_save = 1
        body = event_body(event_id="persist-retry")
        with self.assertRaises(AgentError):
            instance.handle_webhook(body, None)
        self.assertEqual(instance.state["seq"], 0)
        self.assertNotIn("persist-retry", instance._seen_set)
        self.assertEqual(instance.handle_webhook(body, None), 200)
        self.assertEqual(adapter.reannounce_calls, 2)

    def test_set_failure_is_retryable(self):
        connector = FakeConnector()
        script_apply(connector)
        adapter = FakeAdapter(current_port=9000)
        adapter.fail_set = 1
        instance, _, store = make_agent(adapter=adapter, connector=connector)
        body = event_body(event_id="set-retry")
        with self.assertRaises(AgentError):
            instance.handle_webhook(body, None)
        self.assertEqual(store.state, state())
        self.assertNotIn("set-retry", instance._seen_set)
        self.assertEqual(instance.handle_webhook(body, None), 200)

    def test_successful_replay_and_stale_sequence_are_ignored(self):
        connector = FakeConnector()
        script_apply(connector)
        instance, adapter, _ = make_agent(connector=connector,
                                           initial=state(ext_port=19000, int_port=12345))
        body = event_body(event_id="once")
        self.assertEqual(instance.handle_webhook(body, None), 200)
        self.assertEqual(instance.handle_webhook(body, None), 200)
        self.assertEqual(instance.handle_webhook(event_body(seq=1, event_id="other"), None), 200)
        self.assertEqual(adapter.reannounce_calls, 1)

    def test_seen_id_structures_are_actually_capped(self):
        instance, _, _ = make_agent()
        for number in range(agent.SEEN_EVENTS_CAP + 50):
            instance._remember(f"event-{number}")
        self.assertEqual(len(instance._seen), agent.SEEN_EVENTS_CAP)
        self.assertEqual(len(instance._seen_set), agent.SEEN_EVENTS_CAP)
        self.assertNotIn("event-0", instance._seen_set)


class TestReconcile(unittest.TestCase):
    def test_repairs_real_client_drift_without_advancing_sequence(self):
        connector = FakeConnector()
        connector.respond_json(profile())
        script_apply(connector)
        adapter = FakeAdapter(current_port=9999)
        initial = state(seq=7, ext_port=20000, int_port=12345, rule_id=RULE_ID)
        instance, _, store = make_agent(adapter=adapter, connector=connector, initial=initial)
        instance.reconcile()
        self.assertEqual(adapter.set_calls, [12345])
        self.assertEqual(adapter.reannounce_calls, 1)
        self.assertEqual(store.state["seq"], 7)

    def test_chooses_lowest_external_rule_but_applies_its_internal_port(self):
        connector = FakeConnector()
        rules = [
            {"id": "high", "extPort": 25000, "intPort": 5000},
            {"id": "low", "extPort": 21000, "intPort": 6000},
        ]
        selected = profile(rules=rules)
        connector.respond_json(selected)
        connector.respond_json(selected)
        connector.respond_json({"verdict": "ok"})
        adapter = FakeAdapter(current_port=9999)
        instance, _, store = make_agent(adapter=adapter, connector=connector, initial=state(seq=4))
        instance.reconcile()
        self.assertEqual(adapter.set_calls, [6000])
        self.assertEqual(store.state, state(seq=4, ext_port=21000, int_port=6000, rule_id="low"))
        self.assertTrue(connector.requests[-1][1].endswith("/low/probe"))

    def test_no_drift_avoids_gratuitous_reannounce_and_keeps_seq(self):
        connector = FakeConnector()
        connector.respond_json(profile())
        initial = state(seq=10, ext_port=20000, int_port=12345, rule_id=RULE_ID)
        instance, adapter, store = make_agent(connector=connector, initial=initial)
        instance.reconcile()
        self.assertEqual(adapter.reannounce_calls, 0)
        self.assertEqual(store.state, initial)

    def test_delete_reconciles_authoritative_replacement_and_commits_event_seq(self):
        connector = FakeConnector()
        connector.respond_json(profile(23000, 13000))
        script_apply(connector, 23000, 13000)
        adapter = FakeAdapter(current_port=12345)
        initial = state(seq=2, ext_port=20000, int_port=12345, rule_id=RULE_ID)
        instance, _, store = make_agent(adapter=adapter, connector=connector, initial=initial)
        body = event_body(seq=3, event="port.deleted", event_id="delete")
        self.assertEqual(instance.handle_webhook(body, None), 200)
        self.assertEqual(adapter.set_calls, [13000])
        self.assertEqual(store.state["seq"], 3)

    def test_empty_profile_clears_desired_rule_without_changing_seq(self):
        connector = FakeConnector()
        connector.respond_json(profile(rules=[]))
        initial = state(seq=6, ext_port=20000, int_port=12345, rule_id=RULE_ID)
        instance, adapter, store = make_agent(connector=connector, initial=initial)
        instance.reconcile()
        self.assertEqual(store.state, state(seq=6))
        self.assertEqual(adapter.set_calls, [])


class TestAdapters(unittest.TestCase):
    def config(self, client):
        values = {
            "qbittorrent": {"WGPM_CLIENT": "qbittorrent"},
            "transmission": {"WGPM_CLIENT": "transmission", "TR_HOST": "http://127.0.0.1:9091/tr",
                             "TR_USER": "alice", "TR_PASS": "secret"},
            "deluge": {"WGPM_CLIENT": "deluge", "DELUGE_HOST": "http://127.0.0.1:8112/deluge",
                       "DELUGE_PASS": "secret"},
        }
        return make_config(**values[client])

    def test_qbittorrent_login_read_set_and_reannounce(self):
        connector = FakeConnector()
        adapter = agent.QbittorrentAdapter(self.config("qbittorrent"),
                                            HttpJson("http://host/qbit", connector))
        connector.respond(200, {"set-cookie": "SID=abc; Path=/"})
        connector.respond_json({"listen_port": 8000})
        self.assertEqual(adapter.get_listen_port(), 8000)
        connector.respond(200)
        connector.respond_json({"listen_port": 9000})
        self.assertTrue(adapter.set_listen_port(9000))
        connector.respond(200)
        adapter.reannounce()
        self.assertEqual(connector.requests[1][2]["cookie"], "SID=abc")
        self.assertIn(b"hashes=all", connector.requests[-1][3])

    def test_transmission_basic_auth_bounded_session_retry_and_all_reannounce(self):
        connector = FakeConnector()
        adapter = agent.TransmissionAdapter(self.config("transmission"),
                                             HttpJson("http://host/tr", connector))
        connector.respond(409, {"x-transmission-session-id": "SID"})
        connector.respond_json({"result": "success", "arguments": {"peer-port": 51413}})
        self.assertEqual(adapter.get_listen_port(), 51413)
        connector.respond_json({"result": "success"})
        adapter.reannounce()
        expected = "Basic " + agent.base64.b64encode(b"alice:secret").decode()
        self.assertTrue(all(request[2]["authorization"] == expected for request in connector.requests))
        self.assertEqual(json.loads(connector.requests[-1][3]), {"method": "torrent-reannounce"})
        self.assertEqual(connector.requests[0][1], "/tr/transmission/rpc/")

    def test_transmission_sets_and_verifies_peer_port(self):
        connector = FakeConnector()
        adapter = agent.TransmissionAdapter(self.config("transmission"),
                                             HttpJson("http://host", connector))
        connector.respond_json({"result": "success"})
        connector.respond_json({"result": "success", "arguments": {"peer-port": 51413}})
        self.assertTrue(adapter.set_listen_port(51413))
        self.assertEqual(json.loads(connector.requests[0][3]), {
            "method": "session-set", "arguments": {"peer-port": 51413},
        })

    def test_transmission_rejects_second_409_and_rpc_failure_result(self):
        connector = FakeConnector()
        adapter = agent.TransmissionAdapter(self.config("transmission"),
                                             HttpJson("http://host", connector))
        connector.respond(409, {"x-transmission-session-id": "one"})
        connector.respond(409, {"x-transmission-session-id": "two"})
        with self.assertRaisesRegex(AgentError, "twice"):
            adapter.get_listen_port()
        connector.respond_json({"result": "permission denied"})
        with self.assertRaisesRegex(AgentError, "permission denied"):
            adapter.reannounce()

    def test_deluge_keeps_login_cookie_and_reannounces_all_ids_in_one_argument(self):
        connector = FakeConnector()
        adapter = agent.DelugeAdapter(self.config("deluge"), HttpJson("http://host/deluge", connector))
        connector.respond_json({"id": 1, "result": True, "error": None},
                               headers={"set-cookie": "_session_id=abc; Path=/"})
        connector.respond_json({"id": 2, "result": {"listen_ports": [7000, 7000]}, "error": None})
        self.assertEqual(adapter.get_listen_port(), 7000)
        connector.respond_json({"id": 3, "result": ["t1", "t2"], "error": None})
        connector.respond_json({"id": 4, "result": None, "error": None})
        adapter.reannounce()
        self.assertEqual(connector.requests[1][2]["cookie"], "_session_id=abc")
        force = json.loads(connector.requests[-1][3])
        self.assertEqual(force["method"], "core.force_reannounce")
        self.assertEqual(force["params"], [["t1", "t2"]])
        self.assertEqual(connector.requests[0][1], "/deluge/json")

    def test_deluge_sets_and_verifies_single_listen_port_range(self):
        connector = FakeConnector()
        adapter = agent.DelugeAdapter(self.config("deluge"), HttpJson("http://host", connector))
        connector.respond_json({"id": 1, "result": True, "error": None},
                               headers={"set-cookie": "_session_id=abc"})
        connector.respond_json({"id": 2, "result": None, "error": None})
        connector.respond_json({"id": 3, "result": {"listen_ports": [7000, 7000]}, "error": None})
        self.assertTrue(adapter.set_listen_port(7000))
        request = json.loads(connector.requests[1][3])
        self.assertEqual(request["method"], "core.set_config")
        self.assertEqual(request["params"], [{"listen_ports": [7000, 7000]}])


class TestStateStore(unittest.TestCase):
    def test_atomic_save_modes_and_fsyncs_file_and_parent(self):
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "state.json")
            store = StateStore(path)
            real_fsync = os.fsync
            calls = []

            def recording_fsync(fd):
                calls.append(fd)
                return real_fsync(fd)

            with mock.patch("os.fsync", side_effect=recording_fsync):
                store.save(state(seq=1, ext_port=5000, int_port=4000))
            self.assertGreaterEqual(len(calls), 2)
            self.assertEqual(os.stat(path).st_mode & 0o777, 0o600)
            self.assertEqual(store.load(), state(seq=1, ext_port=5000, int_port=4000))

    def test_failed_replace_preserves_old_state_and_removes_temp(self):
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "state.json")
            store = StateStore(path)
            store.save(state(seq=1))
            with mock.patch("os.replace", side_effect=OSError("crash")):
                with self.assertRaises(AgentError):
                    store.save(state(seq=2))
            self.assertEqual(store.load(), state(seq=1))
            self.assertEqual(os.listdir(directory), ["state.json"])

    def test_missing_file_has_complete_default_state(self):
        with tempfile.TemporaryDirectory() as directory:
            self.assertEqual(StateStore(os.path.join(directory, "missing")).load(), state())


if __name__ == "__main__":
    unittest.main()
