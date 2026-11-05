#!/usr/bin/env python3
"""One fixed xchacha transit profile on fresh independent TLS fixtures only."""
from functools import partial
from pathlib import Path
from core_isolation import main as compare
from transit_derived_live import run_scenarios, run_after_restart


def main():
    selected = "xchacha20-poly1305.convergent"
    return compare(
        scenario_runner=partial(run_scenarios, selected_profile=selected),
        restart_runner=partial(run_after_restart, selected_profile=selected),
        profile="transit-derived270", required_oracle_version="2.7.0",
        scope="selected_xchacha_convergent_transport_observation_with_rotation_and_restart_only",
        runner_path=Path(__file__))


if __name__ == "__main__":
    raise SystemExit(main())
