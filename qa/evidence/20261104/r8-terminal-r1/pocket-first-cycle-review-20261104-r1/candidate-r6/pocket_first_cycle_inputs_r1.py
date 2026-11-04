"""Exact frozen-source and current Pocket input checks for the owned rehearsal."""
from pathlib import Path
import base64, copy, hashlib, json, os, re, sqlite3, stat, time

CACHE_NAMES = ('applied-profiles.json', 'publish-baseline.json', 'bad-refresh-quarantine.json',
               'refresh-backoff.json', 'lease-epochs.json', 'status.json')
SOURCE_PINS = {
    'prepare': 'bb4f2e2c421102f9a0a31c70db7c26457a97a8a5bfac8227a3e372a2f3923228',
    'bundle': 'b38233cb4e0c2838bd26d93afb623c93d984b97930ecc769b4450704343e4957',
    'profile1_proof': '3050622c35bacb53ac47f532d4d5230c7c5c68bd2db243376c3c27385744a878',
    'profile2_core': '3ac84a78cb6f6fb145508adbb6918cf7de40478ec92854eeb4427ec5c04242a7',
}
GENERATIONS = (
    ('bca88c7adde84057871fd63f202e6aba80d453a04f75151df1d29f269dfaa5f1',
     '332c2cdd98cd0650de22a4506f7f67c3cbc69a9154e0cbafa4344f7a691640b9',
     'c40f74bc2c0190ebb30259e25534f78f7048346814d1a02cd99274340add0606'),
    ('48e095587f180413f65274d6d25d88d4ee6f9f99d981575f54bc4fb3399c286e',
     '899445c0e083199d67988e1db5bc7ac6d4d158bf913bb54669e5afc7714f2fb2',
     'c6b074866138e3ed265414016ed7ba4a88bdbe062e3983269c61be8496f22caa'),
)

class Refused(Exception):
    pass

def need(value, code):
    if not value:
        raise Refused(code)

def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()

def sha(raw):
    return hashlib.sha256(raw).hexdigest()

def digest(value):
    return sha(encoded(value))

def identity(s):
    return [str(x) for x in (s.st_dev, s.st_ino, s.st_uid, s.st_gid, s.st_mode,
                            s.st_nlink, s.st_size, s.st_mtime_ns, s.st_ctime_ns)]

def private_file(path):
    path = Path(path)
    need(path.resolve(strict=True) == path, 'private_input_path_no_symlink')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_uid == os.geteuid() and before.st_nlink == 1
             and stat.S_IMODE(before.st_mode) & 0o077 == 0 and before.st_size <= 1024 * 1024,
             'private_input_custody')
        raw = bytearray()
        while len(raw) <= 1024 * 1024:
            part = os.read(fd, min(65536, 1024 * 1024 + 1 - len(raw)))
            if not part:
                break
            raw.extend(part)
        need(len(raw) == before.st_size and identity(before) == identity(os.fstat(fd))
             == identity(path.lstat()), 'private_input_changed')
        return bytes(raw), before
    finally:
        os.close(fd)

def capture_caches(live):
    live = Path(live)
    root = live / 'authbus'
    need(live.resolve(strict=True) == live, 'live_state_no_symlink')
    need(os.statvfs(live).f_flag & os.ST_RDONLY, 'source_cache_parent_not_kernel_readonly')
    try:
        before = root.lstat()
    except FileNotFoundError:
        need(not root.exists() and not root.is_symlink(), 'absent_source_cache_directory_changed')
        return {'schema': 'heptabao.six-authbus-cache-custody.private.v1',
                'directory': {'root': str(root), 'absent': True},
                'files': {name: {'present': False} for name in CACHE_NAMES}}
    need(stat.S_ISDIR(before.st_mode) and before.st_uid == os.geteuid()
         and stat.S_IMODE(before.st_mode) & 0o022 == 0 and root.resolve(strict=True) == root,
         'cache_directory_custody')
    need(os.statvfs(root).f_flag & os.ST_RDONLY, 'source_cache_not_kernel_readonly')
    files = {}
    for name in CACHE_NAMES:
        try:
            raw, info = private_file(root / name)
            files[name] = {'present': True, 'mode': stat.S_IMODE(info.st_mode), 'bytes': len(raw),
                           'sha256': sha(raw), 'base64': base64.b64encode(raw).decode(),
                           'identity': identity(info)}
        except FileNotFoundError:
            files[name] = {'present': False}
    for name, item in files.items():
        try:
            raw, info = private_file(root / name)
        except FileNotFoundError:
            need(not item['present'], 'source_cache_file_disappeared')
        else:
            need(item['present'] and identity(info) == item['identity'] and sha(raw) == item['sha256'],
                 'source_cache_generation_changed')
    need(identity(before) == identity(root.lstat()), 'source_cache_directory_changed')
    return {'schema': 'heptabao.six-authbus-cache-custody.private.v1',
            'directory': {'root': str(root), 'absent': False, 'identity': identity(before)}, 'files': files}

def cache_content_digest(snapshot):
    return digest({'directoryPresent': not snapshot['directory']['absent'], 'files': {
        name: {k: item[k] for k in ('present', 'mode', 'bytes', 'sha256', 'base64')}
        if item['present'] else {'present': False} for name, item in snapshot['files'].items()}})

def materialize_caches(state, snapshot, put):
    if snapshot['directory']['absent']:
        need(not (state / 'authbus').exists(), 'original_cache_directory_absence')
        return
    root = state / 'authbus'; root.mkdir(mode=0o700)
    for name in CACHE_NAMES:
        item = snapshot['files'][name]
        if item['present']:
            raw = base64.b64decode(item['base64'], validate=True)
            need(len(raw) == item['bytes'] and sha(raw) == item['sha256'] and item['mode'] == 0o600,
                 'source_cache_materialization_pin')
            put(root / name, raw)

def trusted_sources(packet_path, packet_sha, projection_path, projection_sha, profiles):
    raw, _ = private_file(packet_path); observed, _ = private_file(projection_path)
    need(sha(raw) == packet_sha and sha(observed) == projection_sha, 'transferred_trusted_input_pins')
    packet, proof = json.loads(raw), json.loads(observed)
    need(packet.get('schema') == 'heptabao.frozen-managed-profile12-private.v1'
         and packet.get('sourcePins') == SOURCE_PINS and proof.get('ok') is True
         and proof.get('packetSha256') == packet_sha
         and proof.get('sourceGeneration') == 'frozen_previously_verified_generation'
         and proof.get('latestActiveGenerationClaimed') is False
         and proof.get('providerCalled') is False and proof.get('refreshCalled') is False
         and proof.get('sourceUnchanged') is True, 'frozen_source_provenance')
    ids = packet.get('targetProfileIds'); credentials = packet.get('credentials')
    need(isinstance(ids, list) and len(set(ids)) == len(ids) == 2
         and set(credentials) == set(ids), 'exact_two_trusted_profile_ids')
    current_ids = list(profiles); target = copy.deepcopy(profiles); public = []
    for ordinal, (pid, pins) in enumerate(zip(ids, GENERATIONS), 1):
        cred = credentials[pid]
        need(pid in profiles and current_ids.index(pid) == ordinal - 1
             and all(profiles[pid].get(k) == cred.get(k)
                     for k in ('provider', 'type', 'email', 'accountId', 'projectId')),
             'central_and_current_pocket_profile_identity_or_id_differs')
        need(digest(cred) == pins[0] and sha(cred['accountId'].encode()) == pins[1]
             and sha(cred['access'].encode()) == pins[2]
             and cred.get('provider') == 'openai' and cred.get('type') == 'oauth',
             'trusted_credential_generation_changed')
        claims = json.loads(base64.urlsafe_b64decode(cred['access'].split('.')[1] + '==='))
        need(claims['https://api.openai.com/auth']['chatgpt_account_id'] == cred['accountId']
             and claims['exp'] > time.time() + 900 and cred['expires'] > time.time() * 1000 + 900000,
             'trusted_generation_identity_or_expiry')
        target[pid] = cred
        public.append({'ordinal': ordinal, 'profileIdSha256': sha(pid.encode()), 'accountIdSha256': pins[1],
                       'credentialSha256': pins[0], 'exactOriginalProfileIdAndIdentity': True,
                       'credentialGenerationChanges': digest(profiles[pid]) != pins[0]})
    return ids, credentials, target, public

def current_registry_matches(live, captured, owned_root, label, prior=None):
    path = live / 'state/openclaw.sqlite'
    need(os.statvfs(path).f_flag & os.ST_RDONLY, 'current_registry_not_kernel_readonly')
    need(path.resolve(strict=True) == path, 'current_registry_no_symlink')
    for directory in (live, live / 'state'):
        info = directory.lstat()
        need(stat.S_ISDIR(info.st_mode) and info.st_uid == os.geteuid()
             and stat.S_IMODE(info.st_mode) & 0o022 == 0 and directory.resolve(strict=True) == directory,
             'current_registry_parent_custody')
    def sidecars():
        result = {}
        for suffix in ('-wal', '-shm'):
            member = Path(str(path) + suffix)
            try:
                info = member.lstat()
            except FileNotFoundError:
                result[suffix] = None
                continue
            need(stat.S_ISREG(info.st_mode) and info.st_uid == os.geteuid() and info.st_nlink == 1
                 and stat.S_IMODE(info.st_mode) & 0o077 == 0, 'current_registry_sidecar_custody')
            result[suffix] = identity(info)
        return result
    def exact_snapshot_file(member, expected_identity=None, destination=None, pinned_fd=None):
        member_fd = pinned_fd if pinned_fd is not None else os.open(member, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            info = os.fstat(member_fd)
            need(stat.S_ISREG(info.st_mode) and info.st_uid == os.geteuid() and info.st_nlink == 1
                 and stat.S_IMODE(info.st_mode) == 0o600 and 0 < info.st_size <= 128 * 1024 * 1024,
                 'registry_snapshot_member_custody_or_bound')
            if expected_identity is not None:
                need(identity(info) == expected_identity, 'registry_snapshot_member_identity_changed')
            os.lseek(member_fd, 0, os.SEEK_SET)
            output_fd = None
            if destination is not None:
                output_fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            h = hashlib.sha256(); count = 0
            try:
                while True:
                    part = os.read(member_fd, 1024 * 1024)
                    if not part:
                        break
                    count += len(part); need(count <= info.st_size, 'registry_snapshot_member_grew')
                    h.update(part)
                    if output_fd is not None:
                        view = memoryview(part)
                        while view:
                            used = os.write(output_fd, view); need(used > 0, 'registry_snapshot_short_write')
                            view = view[used:]
                if output_fd is not None:
                    os.fsync(output_fd)
            finally:
                if output_fd is not None:
                    os.close(output_fd)
            need(count == info.st_size and identity(info) == identity(os.fstat(member_fd))
                 == identity(member.lstat()), 'registry_snapshot_member_changed')
            return {'path': str(member), 'identity': identity(info), 'bytes': count, 'sha256': h.hexdigest()}
        finally:
            if pinned_fd is None:
                os.close(member_fd)
    def query_exact_row(database):
        db = sqlite3.connect(database.as_uri() + '?mode=ro', uri=True, timeout=3)
        try:
            db.execute('PRAGMA query_only=ON'); db.execute('PRAGMA temp_store=MEMORY'); db.execute('BEGIN')
            physical_columns = [x[1] for x in db.execute('PRAGMA table_info(installed_plugin_index)')]
            # The frozen row is projected in its explicit SELECT column order,
            # which is not required to be the physical CREATE TABLE order.
            columns = captured['columns']
            need(isinstance(columns, list) and len(physical_columns) == len(columns) == 13
                 and all(isinstance(c, str) and re.fullmatch('[a-z_]+', c)
                         for c in physical_columns + columns)
                 and len(set(physical_columns)) == len(set(columns)) == 13
                 and set(physical_columns) == set(columns), 'current_registry_schema_changed')
            rows = db.execute('SELECT ' + ','.join('"' + c + '"' for c in columns)
                              + ' FROM installed_plugin_index WHERE index_key=?', ('installed-plugin-index',)).fetchall()
            need(len(rows) == 1 and list(rows[0]) == captured['row'], 'current_registry_generation_changed')
            db.rollback()
        finally:
            db.close()
    def write_public(target, value):
        out = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(out, 'wb') as f:
            f.write(encoded(value)); f.flush(); os.fsync(f.fileno())
        directory_fd = os.open(target.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    # A previous stable snapshot remains valid only while every copied original
    # retains its exact identity and whole SHA, with the same sidecar identities
    # or lstat-confirmed absence before and after the complete verification.
    if prior is not None and prior.get('fallbackUsed') is True:
        need(sidecars() == prior['sidecarIdentities'], 'registry_after_snapshot_sidecar_changed')
        for name, pin in prior['sourceFilePins'].items():
            member = path if name == 'main' else Path(str(path) + '-wal')
            need(exact_snapshot_file(member, pin['identity']) == pin, 'registry_after_snapshot_bytes_changed')
        need(sidecars() == prior['sidecarIdentities'], 'registry_after_snapshot_sidecar_changed')
        return {**prior, 'verification': 'Exact copied originals and sidecar identities or absence rechecked',
                'sourceWritten': False}
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_uid == os.geteuid() and before.st_nlink == 1
             and stat.S_IMODE(before.st_mode) == 0o600, 'current_registry_database_custody')
        before_sidecars = sidecars()
        fallback = None
        try:
            query_exact_row(path)
        except sqlite3.OperationalError as error:
            failure = {'schema': 'heptabao.pocket-registry-readonly-attempt.v1', 'ok': False,
                       'mode': 'ro + query_only + BEGIN', 'errorClass': type(error).__name__,
                       'sqliteErrorCode': getattr(error, 'sqlite_errorcode', None),
                       'sqliteErrorName': getattr(error, 'sqlite_errorname', None),
                       'messageSha256': sha(str(error).encode()), 'sourceWritten': False,
                       'databaseIdentity': identity(before), 'sidecarIdentities': before_sidecars}
            need(re.fullmatch('[a-z0-9-]+', label) is not None
                 and owned_root.resolve(strict=True) == owned_root
                 and not os.statvfs(owned_root).f_flag & os.ST_RDONLY, 'registry_fallback_owned_scope')
            failure_path = owned_root / ('registry-' + label + '-direct-failure.public.json')
            write_public(failure_path, failure)
            code = failure['sqliteErrorCode']
            main_wal_missing_shm = (isinstance(code, int)
                and (code & 255) in (sqlite3.SQLITE_CANTOPEN, sqlite3.SQLITE_READONLY)
                and before_sidecars['-shm'] is None and before_sidecars['-wal'] is not None)
            main_only_no_sidecars = (code == sqlite3.SQLITE_CANTOPEN
                and before_sidecars['-wal'] is None and before_sidecars['-shm'] is None
                and 0 < before.st_size <= 128 * 1024 * 1024)
            need((main_wal_missing_shm or main_only_no_sidecars)
                 and identity(before) == identity(os.fstat(fd)) == identity(path.lstat())
                 and before_sidecars == sidecars(), 'registry_read_failure_not_known_stable_snapshot_case')
            scratch = owned_root / ('registry-' + label + '-snapshot-private')
            scratch.mkdir(mode=0o700)
            source_pins = {}
            wal_path = Path(str(path) + '-wal')
            wal_fd = None
            try:
                # Keep the original main descriptor, and WAL descriptor when it
                # exists, throughout copying and the WAL-aware clone query.
                # Only the owned clone may generate absent WAL/SHM sidecars.
                members = {'main': (path, identity(before), fd)}
                if main_wal_missing_shm:
                    wal_fd = os.open(wal_path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
                    members['wal'] = (wal_path, before_sidecars['-wal'], wal_fd)
                for name, (member, expected, member_fd) in members.items():
                    target = scratch / ('openclaw.sqlite' + ('-wal' if name == 'wal' else ''))
                    source_pins[name] = exact_snapshot_file(member, expected, target, member_fd)
                for directory in (scratch, owned_root):
                    directory_fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
                    try:
                        os.fsync(directory_fd)
                    finally:
                        os.close(directory_fd)
                # Hold the entire copy/query interval to the exact original
                # bytes, identities, timestamps and both sidecar observations.
                for name, (member, expected, member_fd) in members.items():
                    need(exact_snapshot_file(member, expected, pinned_fd=member_fd) == source_pins[name],
                         'registry_snapshot_copy_changed')
                need(before_sidecars == sidecars(), 'registry_snapshot_source_sidecars_changed')
                query_exact_row(scratch / 'openclaw.sqlite')
                for name, (member, expected, member_fd) in members.items():
                    need(exact_snapshot_file(member, expected, pinned_fd=member_fd) == source_pins[name],
                         'registry_snapshot_query_source_changed')
            finally:
                if wal_fd is not None:
                    os.close(wal_fd)
            fallback = {'directReadFailurePath': str(failure_path), 'directReadFailureSha256': sha(encoded(failure)),
                        'sourceFilePins': source_pins, 'snapshotPath': str(scratch),
                         'snapshotMode': 'main-only-no-sidecars' if main_only_no_sidecars else 'main-plus-wal-missing-shm',
                        'fallbackUsed': True, 'onlyOwnedCopyMayCreateShm': True,
                         'onlyOwnedCopyMayCreateSidecars': True,
                         'verification': 'Exact stable copy, WAL-aware read, complete original interval and sidecars rechecked'}
        need(identity(before) == identity(os.fstat(fd)) == identity(path.lstat())
             and before_sidecars == sidecars(), 'current_registry_source_changed_during_read')
    finally:
        os.close(fd)
    return {'mode': 'ro + query_only + BEGIN', 'walHonored': True,
            'oneExactInstalledPluginIndexRow': True, 'currentRowMatchesFrozenCapture': True,
            'databaseIdentity': identity(before), 'sidecarIdentities': before_sidecars,
            'sourceMetadataStable': True, 'sourceWritten': False, 'fallbackUsed': False, **(fallback or {})}

def user_native_identity_matches(native_auth_path, profiles):
    raw, info = private_file(native_auth_path)
    need(sha(raw) == 'd77382ec5c49f90efe35f25c5ae8a86cd82e08294d408164c3a6778f958df173',
         'independent_native4_auth_generation_changed')
    value = json.loads(raw); tokens = value.get('tokens', {})
    fourth = profiles[list(profiles)[3]]
    need(tokens.get('account_id') == fourth.get('accountId'), 'independent_native4_identity_mismatch')
    return {'sha256': sha(raw), 'identity': identity(info), 'matchesLocalOrdinal4': True,
            'accountIdSha256': sha(fourth['accountId'].encode()), 'copiedOrChanged': False,
            'nativeUserScopeProcessStarted': False}
