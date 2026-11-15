"""Source/binary-bound, non-authoritative observations for online-auth fixtures."""
from __future__ import annotations
import hashlib
import os
from pathlib import Path
import re
import stat
import owned_process
import subprocess
from bao_http import private_write
from heptabao.private_state import _descriptor_walk_path


def check_numeric_observation(rows, prefix, name, condition, observations, failure_type):
    """Append one bounded numeric observation with the caller's failure policy."""
    if (not isinstance(name, str) or re.fullmatch(r'[a-z0-9_.]{1,140}', name) is None
            or any(type(value) not in (int, bool) for value in observations.values())):
        raise ValueError('unsafe_observation')
    rows.append({'case': prefix + name, 'passed': condition is True, **observations})
    if condition is not True:
        raise failure_type(prefix + name)


def trace_request(self, name, path, fields=None, *, method='POST', bearer=None, status=200, wrap=None):
    response = self.client.request(method, '/v1/' + path, fields, token=bearer, wrap_ttl=wrap)
    self.check(name + '.status', response.status == status, status=response.status)
    return response.body


def trace_auth(self, name, body, *, exact=None, maximum=None, nonexpiring=False):
    auth = body.get('auth') or {}
    self.check(name + '.credentials', all(isinstance(auth.get(k), str) and bool(auth[k])
               for k in ('client_token', 'accessor')))
    self.sensitive.append(auth['client_token'])
    self.lease(name, auth, exact=exact, maximum=maximum, nonexpiring=nonexpiring)
    self.check(name + '.renewable', auth.get('renewable') is (not nonexpiring))
    return auth


def trace_renewal(self, name, auth, *, via='self', increment=None, exact=None, maximum=None, status=200, renewal_shape):
    fields = {} if increment is None else {'increment': increment}
    path = {'self': 'renew-self', 'token': 'renew', 'accessor': 'renew-accessor'}[via]
    if via == 'token':
        fields['token'] = auth['client_token']
    elif via == 'accessor':
        fields['accessor'] = auth['accessor']
    name += '.' + via
    body = self.call(name, 'auth/token/' + path, fields,
                     bearer=auth['client_token'] if via == 'self' else None, status=status)
    if status != 200:
        self.check(name + '.no_credentials', not body.get('auth') and not body.get('wrap_info'))
        return
    renewed = body.get('auth') or {}
    self.lease(name, renewed, exact=exact, maximum=maximum)
    self.check(name + '.shape', renewed.get('renewable') is True
               and renewal_shape(renewed, auth['client_token'], via_accessor=via == 'accessor'))


def admit_output(path: Path) -> tuple[int, int]:
    """Reject existing/linked outputs before allocating a synthetic service."""
    path = _descriptor_walk_path(path.absolute())
    for parent in (path.parent, *path.parent.parents):
        if not stat.S_ISDIR(parent.lstat().st_mode):
            raise ValueError("report_directory_not_regular")
    info = path.parent.lstat()
    if info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700:
        raise ValueError("report_directory_not_private")
    if os.path.lexists(path):
        raise ValueError("report_already_exists")
    return info.st_dev, info.st_ino


def source_identity(root: Path, binary: Path) -> dict:
    def git(*args):
        return owned_process.check_output(["git", *args], cwd=root, stderr=subprocess.DEVNULL, label="online_evidence.29")
    # Commit identity alone does not bind a dirty source tree. Include bytes of
    # tracked and untracked non-ignored source, but never follow source symlinks.
    digest = hashlib.sha256()
    paths = sorted(set(git("ls-files", "-z", "--cached", "--others", "--exclude-standard").split(b"\0")) - {b""})
    for raw in paths:
        path = root / os.fsdecode(raw)
        digest.update(len(raw).to_bytes(8, "big") + raw)
        if not os.path.lexists(path):
            digest.update(b"missing")
            continue
        info = path.lstat()
        if stat.S_ISLNK(info.st_mode):
            data = os.fsencode(os.readlink(path))
        elif stat.S_ISREG(info.st_mode):
            data = path.read_bytes()
        else:
            raise ValueError("source_contains_nonregular_object")
        digest.update(info.st_mode.to_bytes(8, "big") + hashlib.sha256(data).digest())
    with binary.open("rb") as stream:
        binary_hash = hashlib.file_digest(stream, "sha256").hexdigest()
    return {
        "source_commit": git("rev-parse", "HEAD").decode().strip(),
        "source_tree": git("rev-parse", "HEAD^{tree}").decode().strip(),
        "source_dirty": bool(git("status", "--porcelain", "--untracked-files=all")),
        "source_content_sha256": digest.hexdigest(),
        "binary_sha256": binary_hash,
    }


def complete_checks(checks: list[dict], expected_count: int | None = None, *,
                    required_cases: frozenset[str] | None = None) -> bool:
    if not checks or (expected_count is None and not required_cases):
        return False
    if expected_count is not None and len(checks) != expected_count:
        return False
    names = []
    for row in checks:
        if not isinstance(row, dict) or set(row) != {"case", "passed"}:
            return False
        if row["passed"] is not True or not isinstance(row["case"], str) or not re.fullmatch(r"[a-z0-9_]{1,120}", row["case"]):
            return False
        names.append(row["case"])
    return (len(set(names)) == len(names)
            and (required_cases is None or bool(required_cases) and required_cases.issubset(names)))


def publish(output: Path, admitted_parent: tuple[int, int], report: dict,
            before: dict, after: dict, expected_count: int | None = None, *,
            required_cases: frozenset[str] | None = None) -> None:
    if before != after:
        report["failure"] = "source_or_binary_changed_during_execution"
    if not complete_checks(report["checks"], expected_count, required_cases=required_cases):
        report["failure"] = report.get("failure") or "incomplete_or_invalid_observations"
    report["status"] = "passed" if report.get("failure") is None else "failed"
    report.update(before)
    report["source_and_binary_unchanged"] = before == after
    report["independent_qualification"] = False
    report["compatibility_claim"] = False
    report["production_authority"] = False
    # Recheck caller directory identity. This is output admission and metadata
    # protection, not an external signer or a same-UID adversary sandbox.
    if admit_output(output) != admitted_parent:
        raise ValueError("report_parent_changed_during_execution")
    private_write(output, report, replace=False)
