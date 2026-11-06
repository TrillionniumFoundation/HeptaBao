#!/usr/bin/env python3
"""SOURCE ONLY: four current-record failure classes for raw-status observer c928d.

Run only inside the separately authorized original Python component gate, after
the caller has whole-verified and imported the exact observer source. This module
does not construct an HTTP Client, open a socket, launch a fixture, or execute a
product case. The four classes contain eight deterministic fake-call variants.
"""
from __future__ import annotations

OBSERVER_SOURCE_SHA256 = (
    "1952270dba831b0e21e2291df8178e9557e7ff76fc83a2e8dc70cbf46eb7d4e9"
)


def run_current_record_failure_checks(observer, *, verified_source_sha256):
    if verified_source_sha256 != OBSERVER_SOURCE_SHA256:
        raise AssertionError("exact_observer_source_required")
    results = []
    variants = (
        ("precheck_without_append", (), None),
        ("wrong_case_only", (("pki.other_case", 409),), None),
        ("one_matching_null", (("pki.lease_lookup", None),), None),
        ("one_matching_400", (("pki.lease_lookup", 400),), 400),
        ("one_matching_403", (("pki.lease_lookup", 403),), 403),
        ("one_matching_404", (("pki.lease_lookup", 404),), 404),
        ("one_matching_405", (("pki.lease_lookup", 405),), 405),
        ("multiple_matching", (
            ("pki.lease_lookup", 400), ("pki.lease_lookup", 403)), None),
    )
    for name, appended, expected_status in variants:
        case = "pki.lease_lookup"
        failure = observer.BaoError("fake_current_record_failure")
        original_calls = []

        def original_call(*args, **kwargs):
            original_calls.append((args, kwargs))
            raise AssertionError("original_call_must_not_be_invoked")

        class FakeSuite:
            def __init__(self):
                self.call = original_call
                self.allow_writes = True
                self.run_id = "record-component"
                self.requests = {}
                self.results = {}
                self.pki_cases_calls = 0

            def pki_cases(self):
                self.pki_cases_calls += 1
                self.call(case, "GET", "sys/leases/lookup/record-component")

        class FakeCalls:
            def __init__(self):
                # Stale same-case status must not be borrowed when this call has
                # not appended a uniquely matching observation.
                self.records = [
                    {"case_id": case, "status": 418, "marker": "prior-same-case"},
                    {"case_id": "pki.other_case", "status": 429,
                     "marker": "prior-other-case"},
                ]
                self.invocations = 0
                self.arguments = None

            def call(self, *args, **kwargs):
                self.invocations += 1
                self.arguments = (args, kwargs)
                for new_case, status in appended:
                    self.records.append({"case_id": new_case, "status": status})
                # No append models validation/remaining-time failure before an
                # observation; the other variants model failed response paths.
                raise failure

        suite, calls = FakeSuite(), FakeCalls()
        prior_records = [dict(row) for row in calls.records]
        propagated = False
        try:
            observer.run_original_pki12(suite, calls)
        except observer.BaoError as error:
            if error is not failure:
                raise AssertionError("original_error_identity_changed")
            propagated = True
        finally:
            if suite.call is not original_call:
                raise AssertionError("suite_call_not_restored")
        if not propagated or original_calls or suite.pki_cases_calls != 1:
            raise AssertionError("failure_or_call_routing")
        if calls.invocations != 1 or calls.records[:2] != prior_records:
            raise AssertionError("fake_invocation_or_prior_history_changed")
        if calls.records[2:] != [
                {"case_id": new_case, "status": status}
                for new_case, status in appended]:
            raise AssertionError("unexpected_current_records")
        if calls.arguments[0] != (
                case, "GET", "sys/leases/lookup/record-component", None):
            raise AssertionError("original_observer_argument_binding")
        actual = suite.results.get(case)
        expected = {"result": "failed", "reason": failure.code,
                    "http_status": expected_status, "semantics": {}}
        if actual != expected:
            raise AssertionError(("current_status_mismatch", name, actual))
        if suite.requests.get(case) != {
                "method": "GET", "path_template": "sys/leases/lookup/{run_id}"}:
            raise AssertionError("request_projection_changed")
        results.append({"variant": name, "passed": True,
                        "http_status": actual["http_status"],
                        "suite_call_restored": True})
    return {"component": "raw_observer_current_record_failures",
            "source_sha256": verified_source_sha256,
            "classes": 4, "variants": len(results), "results": results,
            "HTTP_requests": 0, "product_cases": 0,
            "fixture_or_subprocess_launches": 0}


if __name__ == "__main__":
    raise SystemExit("Import through the separately authorized component gate.")
