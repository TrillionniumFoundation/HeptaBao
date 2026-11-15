"""Compare the current provider with the retained forward-upgrade source chain.

These selectors cover the repository's bounded, dollar-quoted provider DDL.
They are source checks; PostgreSQL execution remains the live profiles' job.
"""
from pathlib import Path
import re


HISTORICAL_V4 = "qa/openbao-acceptance/fixtures/postgresql-provider-v4-generation-baseline.sql"
UPGRADES = (
    "upgrade_v2_username_recovery.sql",
    "upgrade_v2_static_credentials.sql",
    "upgrade_v3_statement_templates.sql",
    "upgrade_v4_password_authentication.sql",
    "upgrade_v5_password_policy_username_templates.sql",
    "upgrade_v6_root_rotation_statements.sql",
)
_FUNCTION = re.compile(
    r"^CREATE(?: OR REPLACE)? FUNCTION heptabao_provider\.([a-z_]+)"
    r"(\([\s\S]*?\)) RETURNS [\s\S]*?\bAS \$\$[\s\S]*?\$\$;",
    re.M,
)
_TABLE = re.compile(
    r"^CREATE TABLE heptabao_provider\.([a-z_]+) \([\s\S]*?^\);", re.M,
)
_REVOKE = re.compile(
    r"^REVOKE ALL ON FUNCTION heptabao_provider\.[a-z_]+\([\s\S]*?\) FROM PUBLIC;",
    re.M,
)


def provider_function(source: str, name: str) -> str:
    """Return the effective definition, including SQL-language validators."""
    matches = [match for match in _FUNCTION.finditer(source) if match[1] == name]
    if not matches:
        raise AssertionError("missing provider function: " + name)
    return matches[-1][0].replace("CREATE OR REPLACE FUNCTION", "CREATE FUNCTION", 1)


def _function_map(source: str) -> dict[str, str]:
    return {
        match[1] + re.sub(r"\s+", "", match[2]):
            match[0].replace("CREATE OR REPLACE FUNCTION", "CREATE FUNCTION", 1)
        for match in _FUNCTION.finditer(source)
    }


def current_provider_contract_matches(root: Path) -> bool:
    """Fresh install has one final definition per signature and the same DDL/ACL."""
    current = (root / "bootstrap/postgresql/provider.sql").read_text()
    chain = (root / "qa/openbao-acceptance/fixtures/postgresql-provider-v2-legacy.sql").read_text()
    chain += "\n" + "\n".join(
        (root / "bootstrap/postgresql" / name).read_text() for name in UPGRADES
    )
    functions = _function_map(current)
    return (
        len(functions) == len(list(_FUNCTION.finditer(current)))
        and functions == _function_map(chain)
        and {match[1]: match[0] for match in _TABLE.finditer(current)}
        == {match[1]: match[0] for match in _TABLE.finditer(chain)}
        and {re.sub(r"\s+", "", match[0]) for match in _REVOKE.finditer(current)}
        == {re.sub(r"\s+", "", match[0]) for match in _REVOKE.finditer(chain)}
        and re.search(r"^\s*GRANT\b", current, re.M) is None
    )
