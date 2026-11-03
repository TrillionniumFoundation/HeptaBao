#!/usr/bin/env python3
"""Rebuild only public diagnostic source from pinned 8c + actual78a inputs.

No Rust, native controller, subprocess, network, or production action is run.
All generated output goes to one new directory. Previous lost source hashes are
historical references only; this recovery produces and reports its own bytes.
"""
import argparse
import difflib
import gzip
import hashlib
import io
import json
from pathlib import Path
import re
import tarfile

PREFIX = 'crates/heptabao-ha-service/src/'
BASE_COMMIT = '8c56e2adc414f4b0f73e8959ff23632fa19fc629'
BASE_TREE = '16653849d0728a5e838227d70bea265832a80354'
MAP_SHA = '5346a875552b369d39f222207535f276283307c03bd3deca0f9310a9f563a2c4'
PATCH_SHA = '0fc2b1c7f7b7e87337d94789d98574cc1dcbf30769990e7d727a48977e7400c7'
CONTROLLER_SHA = 'f000ca39226c615d3eb396bf6a3a830221b630412e1bdb3994b6eae7228c0793'
ORIGINAL_TAR_SHA = '9246fb38c32c172b64c12c3efa21a4e402e62ba255824a3486d8cbccd29800f0'
BASE_PINS = {
 'closure_phase_diagnostic.rs': (7967, '039344349897ea80d1f1d7ad64c3c439b27d137450c6a21edf927e3d1f62a24e'),
 'v6_closure_quorum.rs': (37554, 'c20512c250be14ce0af47a92dd8021c298f637b45c211757af3245d5d7feced7'),
 'v6_closure_quorum_tests.rs': (59222, 'a1684acf0b3d8aa7fb8d4ec6014fc591851983a9bbdae724e8a3a6f0b753ecca'),
 'v6_closure_batch.rs': (24647, 'd37665919f976016e158413ad736876ff367d47bec536a0ca9226c1b7d349db5'),
 'v6_closure_ingress.rs': (1414, 'e3234ad86fae1de1d1328d157e796cf997598b0b5ff70f4f96b5b6903a67b6ec'),
}
ACTUAL78A_PINS = {
 'closure_phase_diagnostic.rs': (15672, 'd1094cf722f9be4645ec99fe1e9adc58447e2ba52fb9541ba50a2e29489f16cf'),
 'v6_closure_quorum.rs': (39434, 'db7eafb8bcb6621038716791521e2e3dca29f2c3db00d51a0d4b3c4f86ceb219'),
 'v6_closure_quorum_tests.rs': (61292, 'ab3e5c43fc512b635d2dd2e18594a674dd5dcbad4674a4ddc037b09cdd83f2bc'),
 'v6_closure_batch.rs': (25793, 'e97b097285196938ed9bc1f12970d495bb26fac9c26cfc76dd4df01ab0ad58a0'),
}

LIVE_ASSOCIATION = r'''// Test-only association for the original live local receiver. A fresh serve
// slot prevents accept/parse failures from inheriting the previous request.
// Only the existing parsed operation is classified; no frame is parsed twice.
#[cfg(test)]
thread_local! {
    static MISSING_ONLY_LIVE_SERVE: std::cell::Cell<Option<Option<MissingOnlyRequest>>> = const { std::cell::Cell::new(None) };
    static MISSING_ONLY_LIVE_SEQUENCE: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
}

#[cfg(test)]
pub(super) struct MissingOnlyLiveServe(Option<Option<MissingOnlyRequest>>);

#[cfg(test)]
impl MissingOnlyLiveServe {
    pub(super) fn enter() -> Self {
        Self(MISSING_ONLY_LIVE_SERVE.with(|slot| slot.replace(Some(None))))
    }

    pub(super) fn event(&self, event: &'static str, error: Option<crate::HaError>) {
        if let Some(request) = MISSING_ONLY_LIVE_SERVE.with(|slot| slot.get().flatten()) {
            request.event(event, error, None);
        }
    }
}

#[cfg(test)]
impl Drop for MissingOnlyLiveServe {
    fn drop(&mut self) {
        MISSING_ONLY_LIVE_SERVE.with(|slot| slot.set(self.0));
    }
}

#[cfg(test)]
pub(super) fn missing_only_live_parsed(
    operation: &[u8; 32],
    target: u64,
    kind: u8,
) -> Option<MissingOnlyScope> {
    if target != 1
        || MISSING_ONLY_REQUEST.with(|slot| slot.borrow().is_some())
        || !MISSING_ONLY_LIVE_SERVE.with(|slot| matches!(slot.get(), Some(None)))
    {
        return None;
    }
    let mut request = MissingOnlyRequest::new(0, operation, target, kind);
    if request.case == 0 {
        return None;
    }
    request.request = MISSING_ONLY_LIVE_SEQUENCE.with(|slot| {
        let next = slot.get().checked_add(1);
        if let Some(next) = next {
            slot.set(next);
        }
        next.unwrap_or(0)
    });
    // Ordinal zero is only an overflow diagnostic rejected by the parser;
    // it does not replace any original product Result or invoke a new gate.
    MISSING_ONLY_LIVE_SERVE.with(|slot| slot.set(Some(Some(request))));
    request.event("enter", None, None);
    Some(MissingOnlyScope::enter(request))
}

'''

SERVE_BEFORE = '''        serve_one_mtls_authenticated_peer_frame(
            listener,
            server,
            &self.pinned,
            timeout,
            false,
            |frame| self.handle_authenticated(frame),
        )
'''
SERVE_AFTER = '''        #[cfg(test)]
        let missing_only_serve = diagnostic::MissingOnlyLiveServe::enter();
        let result = serve_one_mtls_authenticated_peer_frame(
            listener,
            server,
            &self.pinned,
            timeout,
            false,
            |frame| {
                let result = self.handle_authenticated(frame);
                #[cfg(test)]
                missing_only_serve.event("receiver_result", result.as_ref().err().copied());
                result
            },
        );
        #[cfg(test)]
        missing_only_serve.event("serve_return", result.as_ref().err().copied());
        result
'''
PARSE_BEFORE = '''        let request = wire::parse(bytes)?;
'''
PARSE_AFTER = '''        let request = wire::parse(bytes)?;
        #[cfg(test)]
        let _missing_only_request = diagnostic::missing_only_live_parsed(
            &request.binding.intent.operation_digest,
            request.target,
            request.kind as u8,
        );
'''


def sha(data):
    return hashlib.sha256(data).hexdigest()


def need(value, label):
    if not value:
        raise ValueError(label)


def pinned(path, expected_sha, expected_bytes=None):
    data = path.read_bytes()
    need(sha(data) == expected_sha, 'input_sha:' + path.name)
    need(expected_bytes is None or len(data) == expected_bytes, 'input_size:' + path.name)
    return data


def identity(data):
    return {'bytes': len(data), 'sha256': sha(data)}


def replace_once(text, old, new, label):
    need(text.count(old) == 1, 'unique_anchor:' + label)
    return text.replace(old, new, 1)


def apply_unified(originals, patch):
    """Apply the pinned public Git patch exactly, validating every old line."""
    lines = patch.decode('utf-8').splitlines(keepends=True)
    result = {}
    i = 0
    while i < len(lines):
        need(lines[i].startswith('diff --git a/'), 'diff_header')
        h = re.fullmatch(r'diff --git a/(\S+) b/(\S+)\n', lines[i])
        need(h is not None and h[1] == h[2], 'diff_same_path')
        path = h[1]
        need(path in originals and path not in result, 'diff_known_unique_path')
        i += 1
        while i < len(lines) and not lines[i].startswith('@@ '):
            need(not lines[i].startswith('diff --git '), 'diff_missing_hunk')
            i += 1
        source = originals[path].decode('utf-8').splitlines(keepends=True)
        out = []
        cursor = 0
        while i < len(lines) and lines[i].startswith('@@ '):
            m = re.match(r'@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@', lines[i])
            need(m is not None, 'hunk_header')
            old_start, old_count, new_start, new_count = int(m[1]), int(m[2] or 1), int(m[3]), int(m[4] or 1)
            start = old_start - 1 if old_start else 0
            need(cursor <= start <= len(source), 'hunk_old_offset')
            out.extend(source[cursor:start]); cursor = start
            need(len(out) == (new_start - 1 if new_start else 0), 'hunk_new_offset')
            used = added = 0
            i += 1
            while i < len(lines) and not lines[i].startswith(('@@ ', 'diff --git ')):
                line = lines[i]
                need(line[:1] in (' ', '+', '-'), 'hunk_line_kind')
                if line[0] in (' ', '-'):
                    need(cursor < len(source) and source[cursor] == line[1:], 'hunk_old_content')
                    cursor += 1; used += 1
                if line[0] in (' ', '+'):
                    out.append(line[1:]); added += 1
                i += 1
            need((used, added) == (old_count, new_count), 'hunk_line_counts')
        out.extend(source[cursor:])
        result[path] = ''.join(out).encode('utf-8')
    return result


def unified(old, new):
    chunks = []
    for path in sorted(new):
        if old[path] == new[path]:
            continue
        chunks.append('diff --git a/' + path + ' b/' + path + '\n')
        chunks.extend(difflib.unified_diff(old[path].decode().splitlines(keepends=True), new[path].decode().splitlines(keepends=True), fromfile='a/' + path, tofile='b/' + path))
    return ''.join(chunks).encode()


def write_new(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('xb') as stream:
        stream.write(data)


def json_bytes(value):
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + '\n').encode()


def run(workspace, output):
    workspace = workspace.resolve()
    source_dir = workspace / 'ha_ensure_live_peer_diagnostic_r2/actual-8c-source'
    evidence = workspace / 'recovered-checkpoint/evidence'
    components = workspace / 'recovered-checkpoint/components'
    source_map = json.loads(pinned(evidence / 'linux_8c56_full6_progress_20261026_r1/actual-source/source-map.8c56.json', MAP_SHA))
    originals = {}
    for name, (size, digest) in BASE_PINS.items():
        path = PREFIX + name
        need(source_map.get(path) == digest, 'map_source_pin')
        originals[path] = pinned(source_dir / path, digest, size)
    patch = pinned(evidence / 'ha_ensure_sync_existing_diagnostic_r1/actual-mac-r1/native-fmt-final-diagnostic.patch', PATCH_SHA, 19467)
    actual78a = apply_unified(originals, patch)
    need(set(actual78a) == {PREFIX + name for name in ACTUAL78A_PINS}, 'actual78a_exact_four')
    for name, (size, digest) in ACTUAL78A_PINS.items():
        need(identity(actual78a[PREFIX + name]) == {'bytes': size, 'sha256': digest}, 'actual78a_reconstruction')
    candidate = dict(actual78a)
    diagnostic = candidate[PREFIX + 'closure_phase_diagnostic.rs'].decode()
    diagnostic = replace_once(diagnostic, '#[cfg(test)]\npub(super) fn missing_only_failure_phase', LIVE_ASSOCIATION + '#[cfg(test)]\npub(super) fn missing_only_failure_phase', 'diagnostic_live_slot')
    candidate[PREFIX + 'closure_phase_diagnostic.rs'] = diagnostic.encode()
    quorum = candidate[PREFIX + 'v6_closure_quorum.rs'].decode()
    quorum = replace_once(quorum, SERVE_BEFORE, SERVE_AFTER, 'serve_once')
    quorum = replace_once(quorum, PARSE_BEFORE, PARSE_AFTER, 'original_parse_only')
    candidate[PREFIX + 'v6_closure_quorum.rs'] = quorum.encode()
    for name in ('v6_closure_batch.rs', 'v6_closure_quorum_tests.rs'):
        need(candidate[PREFIX + name] == actual78a[PREFIX + name], 'unchanged_batch_fixture')
    delta = unified(actual78a, candidate)
    total = unified({p: originals[p] for p in candidate}, candidate)
    need(apply_unified(actual78a, delta) == {p: candidate[p] for p in candidate if candidate[p] != actual78a[p]}, 'delta_reapplies')
    need(apply_unified(originals, total) == candidate, 'total_reapplies')
    tar_bytes = pinned(components / 'ha_ensure_sync_existing_diagnostic_r1/ensure-source-controller-r1.tar.gz', ORIGINAL_TAR_SHA, 18492)
    with tarfile.open(fileobj=io.BytesIO(tar_bytes), mode='r:gz') as tf:
        name = 'run_missing_only_ensure_sync_diagnostic.py'
        matches = [m for m in tf.getmembers() if m.name == name and m.isfile()]
        need(len(matches) == 1, 'controller_unique_regular_member')
        controller = tf.extractfile(matches[0]).read()
    need(identity(controller) == {'bytes': 25851, 'sha256': CONTROLLER_SHA}, 'controller_original_bytes')
    manifest = {
        'schema': 'heptabao.missing-only-live-peer-source.recovery2',
        'baseCommit': BASE_COMMIT, 'baseTree': BASE_TREE, 'baseSourceMapSha256': MAP_SHA,
        'recovered78aCommit': '78a1f602d8809cf2a53b8318db95d0822f39368e',
        'recovered78aPatch': identity(patch),
        'before': {p: identity(originals[p]) for p in sorted(candidate)},
        'actual78a': {p: identity(actual78a[p]) for p in sorted(candidate)},
        'candidate': {p: identity(candidate[p]) for p in sorted(candidate)},
        'readOnlyIngress': {PREFIX + 'v6_closure_ingress.rs': identity(originals[PREFIX + 'v6_closure_ingress.rs'])},
        'delta78a': identity(delta), 'total8c': identity(total), 'controller': identity(controller),
        'generator': identity(Path(__file__).read_bytes()),
        'reconstructedLostCandidateBytesClaimed': False,
        'requiredNext': ['root reconciles original unknown stage without replay', 'independent source review', 'actual native format/commit/tree/map identity', 'constant-only strict parser bind', 'one original owned diagnostic execution'],
        'nativeIdentity': None, 'nativeExecution': False, 'productFix': False, 'qualification': False,
        'unchanged': ['original authenticated serve/callback/parse count', 'storage/gate/fsync/witness calls and Result', 'test assertions and fault order', 'f000 controller and all retained owner/guard/target-lock budgets'],
        'sourceDiagnosticsCanAffectScheduling': True,
        'preParseFailureRemainsUnassociated': True,
        'remoteStageStatus': 'unknown', 'remoteStageMayReplay': False,
    }
    output = output.resolve()
    need(not output.exists(), 'fresh_output_required')
    output.mkdir(parents=False)
    for path, data in actual78a.items():
        write_new(output / 'actual78a' / path, data)
    for path, data in candidate.items():
        write_new(output / 'candidate' / path, data)
    for path, data in originals.items():
        write_new(output / 'actual8c' / path, data)
    package = {
        'live-peer-78a-to-recovery2.patch': delta,
        'live-peer-8c-to-recovery2.patch': total,
        'run_missing_only_ensure_sync_diagnostic.py': controller,
        'source-candidate.public.json': json_bytes(manifest),
    }
    for name, data in package.items():
        write_new(output / name, data)
    raw_tar = io.BytesIO()
    with tarfile.open(fileobj=raw_tar, mode='w', format=tarfile.PAX_FORMAT) as tf:
        for name in sorted(package):
            data = package[name]
            info = tarfile.TarInfo(name); info.size = len(data); info.mode = 0o600; info.mtime = 0
            tf.addfile(info, io.BytesIO(data))
    transport = gzip.compress(raw_tar.getvalue(), mtime=0)
    name = 'live-peer-source-controller-recovery2.tar.gz'
    write_new(output / name, transport)
    receipt = {
        'schema': 'heptabao.missing-only-source-rebuild.receipt.recovery2',
        'ok': True, 'inputPinsVerified': True, 'actual78aReconstructedExactly': True,
        'sourceMapPinsVerified': True, 'bothPatchesReappliedExactly': True,
        'controllerUnchanged': True, 'batchAndTestsUnchangedFrom78a': True,
        'tar': {'path': name, **identity(transport), 'members': {k: identity(v) for k, v in sorted(package.items())}},
        'candidate': manifest['candidate'], 'delta78a': identity(delta), 'total8c': identity(total),
        'nativeCompiled': False, 'remoteInvoked': False, 'oldLostBytesClaimedIdentical': False,
    }
    write_new(output / 'rebuild.receipt.public.json', json_bytes(receipt))
    print(json.dumps(receipt, sort_keys=True))


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--workspace', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    run(args.workspace, args.output)
