"""Expected migration schema comes from the immutable build source, not its reply."""
from pathlib import Path
import re
import subprocess

SOURCE_PATH = "crates/heptabao-server/src/service.rs"


def parse_current_schema(source: str) -> int:
    declarations = re.findall(
        r"^\s*(?:pub(?:\([^)]*\))?\s+)?const CURRENT_STATE_SCHEMA:\s*u32\s*=\s*([0-9]+);\s*$",
        source, re.MULTILINE,
    )
    if len(declarations) != 1:
        raise ValueError("candidate_schema_declaration_not_unique")
    value = int(declarations[0])
    if not 1 <= value <= 0xFFFF_FFFF:
        raise ValueError("candidate_schema_out_of_range")
    return value


def expected_schema(root: Path, source_commit: str) -> int:
    if re.fullmatch(r"[0-9a-f]{40}", source_commit) is None:
        raise ValueError("candidate_schema_requires_exact_commit")
    source = subprocess.check_output(
        ["git", "show", source_commit + ":" + SOURCE_PATH], cwd=root, text=True,
    )
    return parse_current_schema(source)
