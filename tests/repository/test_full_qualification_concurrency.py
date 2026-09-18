from pathlib import Path
import unittest


class FullQualificationConcurrencyTests(unittest.TestCase):
    def test_concurrency_is_bound_to_exact_head(self) -> None:
        workflow = Path(".github/workflows/codex-openbao-replacement-ci.yml").read_text()
        self.assertIn(
            "github.event.pull_request.head.sha || github.sha",
            workflow,
            "full replacement qualification must bind concurrency to the immutable source",
        )
        self.assertIn(
            "cancel-in-progress: true",
            workflow,
            "same-source duplicate dispatches should remain collapsible",
        )
        self.assertNotIn(
            "group: ${{ github.workflow }}-${{ github.event.pull_request.number || github.ref }}\n",
            workflow,
            "a PR-number-only group lets a new head cancel old-head terminal evidence",
        )


if __name__ == "__main__":
    unittest.main()
