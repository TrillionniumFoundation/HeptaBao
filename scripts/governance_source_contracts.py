"""Source audit of the current descriptor provider and retired CI domains.

These checks do not grant runtime or legacy workflow authority. Historical
workflow bytes are authenticated independently of the current workflow gate.
"""
from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

import yaml

ARCHIVED_WORKFLOWS = {'.github/workflows/export-exact-audit-source.yml': {'SHA256': '5e13898b4ea5c5c5f6f676f3c6eb6663cb995e66b156b4520aeaf5fd5ac4ff7c', 'bytes': 2185, 'commit': '676a3e68af340b2cb7439dbc99c69dee550e5db9', 'fixture': 'tests/fixtures/retired-workflows/export-exact-audit-source.yml', 'git_blob': 'e2f77807e5248ed34d6c3bb5ee8605f1c0b564f2'}, '.github/workflows/plan-v1.3.1-head-and-merge-closure.yml': {'SHA256': '738b38909dc8bc44a8e848252bf7dc30c3a540a7641da8f6002c9a263b39017d', 'bytes': 74825, 'commit': '936cb5599d206cea895de2ae04a1289a0b3a0326', 'fixture': 'tests/fixtures/retired-workflows/plan-v1.3.1-head-and-merge-closure.yml', 'git_blob': '66acfbd8d844109a3a39237d400f33dcffd1d91f'}, '.github/workflows/plan-v1.4.2-anchored-recovery.yml': {'SHA256': '2a8e9e5b1391345fcd51dc58b4c953d815e1e8978c5c584b0e6b59dc9593d9b8', 'bytes': 6258, 'commit': '34e8dc0caceb84288d4ef61f79cd7ca062718b63', 'fixture': 'tests/fixtures/retired-workflows/plan-v1.4.2-anchored-recovery.yml', 'git_blob': 'c516124667116c94f92810f97f5287ffb4f4d0ef'}, '.github/workflows/plan-v1.4.3-descriptor-fencing.yml': {'SHA256': '09033e5ebd8e5ccf393068b112bb64196d57c610cf7b1a57f8045575dd19a199', 'bytes': 6564, 'commit': '676a3e68af340b2cb7439dbc99c69dee550e5db9', 'fixture': 'tests/fixtures/retired-workflows/plan-v1.4.3-descriptor-fencing.yml', 'git_blob': '120189f1e3d3012d51272d8431514e31d3295ffd'}, '.github/workflows/plan-v1.4.4-module-documentation.yml': {'SHA256': 'df7c2a396094efa6b9afc5257e998c651a11ce38824f5f51567548a4858ea6a9', 'bytes': 2021, 'commit': 'a926d10f658c536b12c857658d2b27b7c56a8baa', 'fixture': 'tests/fixtures/retired-workflows/plan-v1.4.4-module-documentation.yml', 'git_blob': '0f47b7535ae813ec26efda610a2b41f235d99f69'}, '.github/workflows/plan-v1.4.6-authoritative-recovery-closure.yml': {'SHA256': '12d2ca16641e08485aefa0ee85c48186f1183e0235f04d258b43ff228d8a9b51', 'bytes': 2924, 'commit': '676a3e68af340b2cb7439dbc99c69dee550e5db9', 'fixture': 'tests/fixtures/retired-workflows/plan-v1.4.6-authoritative-recovery-closure.yml', 'git_blob': 'c2ea49508e039429ba1037093185d3f46bc3759b'}, '.github/workflows/plan-v1.4.7-post-merge-truth-and-external-admission.yml': {'SHA256': 'ae38272ccdd97e412e412339e236ee824214da81c1be072e94b8eb38c8fe6496', 'bytes': 4495, 'commit': 'a926d10f658c536b12c857658d2b27b7c56a8baa', 'fixture': 'tests/fixtures/retired-workflows/plan-v1.4.7-post-merge-truth-and-external-admission.yml', 'git_blob': 'c355f6e3741929c4a89fc18545bae298e10e635e'}}



class Yaml12UniqueLoader(yaml.SafeLoader):
    pass


Yaml12UniqueLoader.yaml_implicit_resolvers = {
    key: [(tag, regex) for tag, regex in values
          if tag != "tag:yaml.org,2002:bool"]
    for key, values in yaml.SafeLoader.yaml_implicit_resolvers.items()
}
Yaml12UniqueLoader.add_implicit_resolver(
    "tag:yaml.org,2002:bool", re.compile(r"^(?:true|false|True|False|TRUE|FALSE)$"),
    list("tTfF"),
)


def _unique_mapping(loader, node, deep=False):
    result = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if key in result:
            raise ValueError(f"duplicate YAML key: {key!r}")
        result[key] = loader.construct_object(value_node, deep=deep)
    return result


Yaml12UniqueLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _unique_mapping
)


def workflow_data(text: str):
    value = yaml.load(text, Loader=Yaml12UniqueLoader)
    if not isinstance(value, dict):
        raise ValueError("workflow is not a mapping")
    return value


def _read_only_errors(text: str, value: dict) -> list[str]:
    errors = []
    if value.get("permissions") != {"contents": "read"}:
        errors.append("workflow gained write permission")
    jobs = value.get("jobs")
    if not isinstance(jobs, dict) or not jobs:
        errors.append("workflow job mapping is missing")
    else:
        for job in jobs.values():
            if not isinstance(job, dict):
                errors.append("workflow job is not a mapping")
            elif "permissions" in job and job["permissions"] != {"contents": "read"}:
                errors.append("workflow job gained write permission")
    if "persist-credentials: false" not in text:
        errors.append("workflow lacks explicit checkout credential erasure")
    for token in ("contents: write", "git push", "git commit", "update-ref",
                  "persist-credentials: true"):
        if token in text:
            errors.append(f"workflow contains write-capable token: {token}")
    return errors


def retired_workflow_errors(root: Path, relative: str) -> list[str]:
    """Only the current, manual-only domain; never select a legacy mode."""
    text = (root / relative).read_text(encoding="utf-8")
    value = workflow_data(text)
    errors = _read_only_errors(text, value)
    triggers = value.get("on")
    if not isinstance(triggers, dict) or set(triggers) != {"workflow_dispatch"}:
        errors.append("retired workflow must remain exactly manual-only")
    return errors


def historical_workflow(root: Path, relative: str) -> str:
    """Authenticate a genuine ancestor blob outside the active workflow tree."""
    record = ARCHIVED_WORKFLOWS[relative]
    path = root / record["fixture"]
    if path.is_symlink() or not path.is_file():
        raise ValueError("historical workflow fixture is missing or redirected")
    data = path.read_bytes()
    if len(data) != record["bytes"] or hashlib.sha256(data).hexdigest() != record["SHA256"]:
        raise ValueError("historical workflow fixture digest differs")
    blob = hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()
    if blob != record["git_blob"]:
        raise ValueError("historical workflow Git blob differs")
    return data.decode("utf-8")


def historical_contract_errors(text: str, branch: str) -> list[str]:
    """Audit historical text only; this cannot configure a current workflow."""
    value = workflow_data(text)
    errors = _read_only_errors(text, value)
    triggers = value.get("on")
    if not isinstance(triggers, dict) or set(triggers) != {"pull_request", "workflow_dispatch"}:
        errors.append("historical workflow trigger set drifted")
    else:
        pull_request = triggers["pull_request"]
        if not isinstance(pull_request, dict) or pull_request.get("branches") != [branch]:
            errors.append("historical workflow base branch drifted")
    return errors


def archived_document_reference(root: Path, relative: str, reference: dict) -> None:
    # Only the actually deleted V1.4.4 workflow has an archived document entry.
    allowed = ".github/workflows/plan-v1.4.4-module-documentation.yml"
    if relative != allowed or reference != ARCHIVED_WORKFLOWS[allowed]:
        raise ValueError("unrecognized historical document reference")
    if (root / relative).exists():
        raise ValueError("retired document workflow regained a current path")
    historical_workflow(root, allowed)


def _rust_code(source: str) -> str:
    # The source audit checks operators/calls, never documentation or literals.
    return re.sub(
        r'"(?:\\.|[^"\\])*"|//[^\n]*|/\*.*?\*/',
        lambda match: '""' if match.group(0).startswith('"') else "",
        source, flags=re.S,
    )


def _function(source: str, name: str) -> str:
    source = _rust_code(source)
    found = list(re.finditer(
        rf"(?m)^[ \t]*(?:pub(?:\([^)]*\))?\s+)?(?:const\s+)?fn\s+{re.escape(name)}\b[^{{}}]*\{{",
        source,
    ))
    if len(found) != 1:
        return ""
    start = found[0].start()
    cursor = found[0].end()
    depth = 1
    while cursor < len(source) and depth:
        depth += (source[cursor] == "{") - (source[cursor] == "}")
        cursor += 1
    if depth:
        return ""
    return re.sub(r"\s+", "", source[start:cursor])


def _need(errors: list[str], body: str, tokens: tuple[str, ...], label: str) -> None:
    for token in tokens:
        if re.sub(r"\s+", "", token) not in body:
            errors.append(f"{label} lost required invariant: {token}")


def descriptor_guard_errors(root: Path) -> list[str]:
    lib = (root / "crates/heptabao-filesystem-guard/src/lib.rs").read_text()
    relative = (root / "crates/heptabao-filesystem-guard/src/relative.rs").read_text()
    errors: list[str] = []
    walk = _function(lib, "open_absolute_directory_no_symlinks")
    _need(errors, walk, (
        "OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC",
        "open(\"\", flags, Mode::empty())", "for component in components",
        "current = openat(&current, name, flags, Mode::empty())",
    ), "filesystem guard source")
    verify = _function(lib, "verify")
    _need(errors, verify, (
        "self.handle.metadata()", "!metadata.is_dir()",
        "identity(&metadata) != self.identity",
    ), "filesystem guard source")
    opened = _function(lib, "open_unix")
    _need(errors, opened, (
        "fs::symlink_metadata(&original_path)", "identity(&opened) != before_identity",
        "identity(&after) != before_identity", "match handle.try_lock()",
        "TryLockError::WouldBlock", "DirectoryGuardError::WriterBusy",
    ), "filesystem guard source")
    leaf = _function(relative, "open_file")
    _need(errors, leaf, (
        "leaf(path.as_ref())?", "FileAccess::CreateNew => OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL,",
        "FileAccess::CreateNewReadWrite => OFlags::RDWR | OFlags::CREATE | OFlags::EXCL,",
        "File::from(openat(&self.handle, name",
        "flags | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK",
        "Mode::RUSR | Mode::WUSR,",
        'if !metadata.is_file() || metadata.nlink() != 1 { return Err(io::Error::other("")); }',
    ), "descriptor leaf source")
    owner_check = "self.verify().map_err(io::Error::other)?;"
    positions = [match.start() for match in re.finditer(re.escape(owner_check), leaf)]
    opening = leaf.find("File::from(openat(")
    inspected = leaf.find("letmetadata=file.metadata()")
    if (len(positions) != 2 or opening < 0 or inspected < 0
            or not positions[0] < opening < inspected < positions[1]):
        errors.append("descriptor leaf source lost pre/post owner verification")
    rename = _function(relative, "rename")
    _need(errors, rename, (
        "leaf(from.as_ref())?", "leaf(to.as_ref())?",
        "self.verify().map_err(io::Error::other)?",
        "rustix::fs::renameat(&self.handle, from, &self.handle, to)?",
    ), "descriptor rename source")
    entries = _function(relative, "entries")
    _need(errors, entries, (
        "self.verify().map_err(io::Error::other)?",
        "rustix::fs::Dir::read_from(&self.handle)?",
    ), "descriptor enumeration source")
    sync = _function(lib, "sync_all")
    _need(errors, sync, (
        "self.verify()?; self.handle.sync_all().map_err(DirectoryGuardError::Io)?; self.verify()",
    ), "descriptor sync source")
    return errors


def descriptor_provider_errors(root: Path, kind: str) -> list[str]:
    if kind not in ("store", "journal"):
        raise ValueError("unknown descriptor provider")
    crate = "heptabao-single-node-" + kind
    source = (root / "crates" / crate / "src/lib.rs").read_text()
    label = "generation store source" if kind == "store" else "durable journal source"
    errors = descriptor_guard_errors(root)
    code = re.sub(r"\s+", "", _rust_code(source))
    _need(errors, code, ("root: ExclusiveDirectory",), label)
    if kind == "journal":
        layout = _function(source, "validate_layout")
        _need(errors, layout, (
            "for entry in self.root.entries().map_err(FileJournalError::Io)?",
            "self.root.open_file(name, FileAccess::Read).map_err(map_guarded_open_error)?",
        ), label)
        if layout.count(".open_file(name,FileAccess::Read)") != 2:
            errors.append("durable journal source lost descriptor-owned entry inspection")
    read = _function(source, "read_regular_file")
    _need(errors, read, (
        ".open_file(leaf_name, FileAccess::Read)", "let metadata = file.metadata()",
        "file.take(take_bound)" if kind == "store" else "file.take(bound)",
    ), label)
    create = _function(source, "write_new_file_and_sync_parent")
    _need(errors, create, (
        "root.verify().map_err(io::Error::other)?",
        "root.open_file(leaf_name, FileAccess::CreateNew)?", "file.write_all(bytes)?",
        "file.flush()?", "file.sync_all()?", "root.sync_all().map_err(io::Error::other)",
    ), label)
    replace = _function(source, "atomic_replace")
    _need(errors, replace, (
        "root.verify()", "root.open_file(&temporary_name, FileAccess::CreateNew)?",
        "file.write_all(bytes)?", "file.flush()?", "file.sync_all()",
        "root.rename(&temporary_name, target_name)", "root.sync_all()",
    ), label)
    if "fnvalidate_root" in code:
        errors.append(f"{label} retained path-reopen root validation")
    if kind == "store" and "ifself.bundle_path(generation).exists()" in code:
        errors.append("generation creation regained a check-then-create race")
    return errors
