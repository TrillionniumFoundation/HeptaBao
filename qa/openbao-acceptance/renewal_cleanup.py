"""Close historical renewal fixtures and publish their original safe outcome.

Cleanup errors cannot skip another resource or suppress the comparison report.
An unretired resource keeps its private directory for investigation. This helper
adds no business cases and does not retry an authentication or renewal request.
"""
from __future__ import annotations

import copy
from pathlib import Path
import shutil
import time


def finish_fixture(result, *, instance, oracle, providers, private_root,
                   stop_oracle, validate, publish):
    failures, fatal = [], []

    def attempt(stage, callback):
        try:
            callback()
            return True
        except BaseException as error:
            failures.append({"stage": stage, "exception_class": type(error).__name__})
            if not isinstance(error, Exception):
                fatal.append(error)
            return False

    candidate_stopped = instance is None or attempt("candidate_stop", instance.stop)
    oracle_stopped = oracle is None or attempt("oracle_stop", lambda: stop_oracle(oracle))
    providers_stopped = []
    for index, provider in enumerate(providers):
        providers_stopped.append(attempt("provider_close_" + str(index), provider.close))
    retained = []
    if oracle is not None:
        result["oracle_process_lifecycle"] = copy.deepcopy(oracle.get("process_lifecycle", []))
        if not oracle_stopped or not attempt("oracle_private_root_remove", lambda: shutil.rmtree(oracle["root"])):
            retained.append(str(oracle["root"]))
    if not (candidate_stopped and all(providers_stopped)) or not attempt(
            "candidate_private_root_remove", lambda: shutil.rmtree(private_root)):
        retained.append(str(Path(private_root)))
    result["cleanup_failures"] = failures
    result["retained_private_roots"] = retained
    attempt("final_source_observation", validate)
    if failures:
        result["status"] = "failed"
        result.setdefault("safe_failure_code", "fixture_cleanup_or_final_observation_failed")
    result.setdefault("status", "failed")
    result["finished_at_unix"] = time.time()
    publish(result)
    if fatal:
        raise fatal[0]
