from __future__ import annotations

import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / ".github/workflows/export-exact-audit-source.yml"


class ExactSourceExportContractTests(unittest.TestCase):
    def test_every_integration_head_is_exportable_without_write_authority(self) -> None:
        source = WORKFLOW.read_text(encoding="utf-8")
        for marker in (
            '      - "codex/plan-v1.3-gap-closure-v2"',
            "  workflow_dispatch:",
            "permissions:\n  contents: read",
            "runs-on: ubuntu-slim",
            "persist-credentials: false",
            "test \"$(git rev-parse HEAD)\" = \"$SOURCE_SHA\"",
            "git archive --format=tar --prefix=HeptaBao/ \"$SOURCE_SHA\"",
            "sha256sum heptabao-exact-source.tar",
            "> heptabao-exact-source.tar.sha256",
            "heptabao-exact-source-${{ github.event.pull_request.head.sha || github.sha }}",
        ):
            self.assertIn(marker, source)

        self.assertNotIn("paths:", source)
        self.assertNotIn("contents: write", source)
        self.assertNotIn("persist-credentials: true", source)
        self.assertNotIn("git push", source)
        self.assertNotIn("git commit", source)
        self.assertNotIn(
            'sha256sum "$RUNNER_TEMP/heptabao-exact-source.tar"', source
        )

    def test_export_is_short_lived_evidence_not_authority(self) -> None:
        source = WORKFLOW.read_text(encoding="utf-8")
        self.assertIn("retention-days: 7", source)
        self.assertNotIn("qualification: true", source)
        self.assertNotIn("authority_effect: GRANT", source)


if __name__ == "__main__":
    unittest.main()
