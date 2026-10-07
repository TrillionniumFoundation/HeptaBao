"""Unseal acknowledgements cannot stand in for active-service readiness."""
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import consistency_headers_live as middleware
import client_consistency_live as client


class SyntheticTrace:
    def __init__(self, profile, endpoint, *, fail_mount=False):
        self.profile, self.endpoint = profile, endpoint
        self.names = []
        self.fail_mount = fail_mount
        self.empty_config_probes = []

    def request(self, name, endpoint, method, path, expected, *args, **kwargs):
        self.names.append(name)
        if name == "initialize":
            return {"root_token": "synthetic", "keys_base64": ["synthetic"]}, {}
        if name in ("unseal", "restart_unseal"):
            endpoint.active = False
            return {}, {}
        if name in ("mount", "write", "restart_retained", "restart_read"):
            if not endpoint.active:
                raise AssertionError("logical request before active readiness")
        if name == "mount" and self.fail_mount:
            raise self.profile.FixtureError("mount")
        if name.startswith("valid_") or name in ("restart_retained", "restart_read"):
            return {"data": {"data": {"fixture": "retained"}}}, {}
        if name.startswith("invalid_"):
            return {"errors": ["synthetic rejection"]}, {}
        if name == "finite_issue":
            return {"auth": {"client_token": "synthetic"}}, {}
        if name == "finite_unchanged":
            return {"data": {"num_uses": 2}}, {}
        if name == "wrap_once":
            return {"wrap_info": {"token": "synthetic"}}, {}
        if name == "unwrap_once":
            return {"data": {"fixture": "single-use"}}, {}
        return {}, {}

    def check(self, name, condition):
        if not condition:
            raise AssertionError(name)

    def invoke(self, endpoint, method, path, token="", body=None, headers=(), timeout=client.REQUEST_TIMEOUT):
        if method == "GET" and path == "client-consistency/config" and body is None and not headers:
            if not endpoint.active:
                raise AssertionError("empty backend probe before active readiness")
            if (type(timeout) not in (int, float) or not 0 < timeout <= 2.0):
                raise AssertionError("empty backend probe changed its original 2s deadline")
            self.empty_config_probes.append((method, path))
            return SimpleNamespace(status=200, body={})
        raise client.BaoError("invalid_consistency_index")


class ActivationBarrierTests(unittest.TestCase):
    def execute(self, profile, *, fail_ready=None, fail_mount=False):
        endpoint = SimpleNamespace(active=False)
        trace = SyntheticTrace(profile, endpoint, fail_mount=fail_mount)
        lifecycle = SimpleNamespace(stop=lambda: None, start=lambda: None)
        readiness = []
        def active(endpoint, status):
            self.assertEqual(status, 200)
            readiness.append(len(trace.names))
            if len(readiness) == fail_ready:
                raise profile.FixtureError("readiness_timeout")
            endpoint.active = True
        with patch.object(profile, "ready", side_effect=active), \
                patch.object(middleware, "call", return_value=(200, {"data": {"num_uses": 2}}, {})):
            error = None
            try:
                profile.common(lifecycle, endpoint, trace)
            except profile.FixtureError as failure:
                error = str(failure)
        return trace.names, readiness, error, trace.empty_config_probes

    def test_initial_and_restart_requests_wait_for_active_health(self):
        for profile in (middleware, client):
            with self.subTest(profile=profile.__name__):
                names, readiness, error, probes = self.execute(profile)
                self.assertIsNone(error)
                self.assertEqual(len(readiness), 2)
                self.assertEqual(names[readiness[0]-1:readiness[0]+1], ["unseal", "mount"])
                self.assertEqual(names[readiness[1]-1], "restart_unseal")
                self.assertEqual(names.count("initialize"), 1)
                self.assertEqual(names.count("mount"), 1)
                self.assertEqual(names.count("write"), 1)
                self.assertEqual(probes, [("GET", "client-consistency/config")] if profile is client else [])

    def test_initial_readiness_failure_never_reaches_mount_or_write(self):
        for profile in (middleware, client):
            with self.subTest(profile=profile.__name__):
                names, readiness, error, probes = self.execute(profile, fail_ready=1)
                self.assertEqual(error, "readiness_timeout")
                self.assertEqual(names, ["initialize", "unseal"])
                self.assertEqual(len(readiness), 1)
                self.assertEqual(probes, [])

    def test_restart_readiness_failure_cannot_release_retained_read(self):
        for profile in (middleware, client):
            with self.subTest(profile=profile.__name__):
                names, readiness, error, probes = self.execute(profile, fail_ready=2)
                self.assertEqual(error, "readiness_timeout")
                self.assertEqual(names[-1], "restart_unseal")
                self.assertEqual(names.count("initialize"), 1)
                self.assertEqual(names.count("mount"), 1)
                self.assertEqual(len(readiness), 2)
                self.assertNotIn("restart_retained", names)
                self.assertNotIn("restart_read", names)
                self.assertEqual(probes, [("GET", "client-consistency/config")] if profile is client else [])

    def test_mount_failure_stays_terminal_without_mutation_retries(self):
        for profile in (middleware, client):
            with self.subTest(profile=profile.__name__):
                names, readiness, error, probes = self.execute(profile, fail_mount=True)
                self.assertEqual(error, "mount")
                self.assertEqual(names, ["initialize", "unseal", "mount"])
                self.assertEqual(len(readiness), 1)
                self.assertEqual(probes, [])
