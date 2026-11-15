class OriginalInitializedFixture:
    """Admit the one closed attempt; retain its original files and directory names.

    Admission has its own finite 20 seconds inside the new 600 second attempt.
    Later checks only recheck the held original names; they do not renew that
    admission budget or reinterpret the old failed attempt as successful.
    """
    JOB = Path('/Users/qianqi/.local/state/hepta-runtime-mac-worker/jobs/1a1b3e976fc-fc05-8575')
    CUSTODY = CLIENT_ROOT / 'custody'
    DIRECTORY_INODES = (72788478, 72788485, 72788480)

    def __init__(self):
        self.admission_until = min(UNTIL, time.monotonic() + 20)
        self.parents = {}
        self.regular = {}
        self.immutable_directories = {}
        self.current_directories = {}
        self.admitted = False
        self.private_init = None

    def _time(self):
        remaining()
        need(time.monotonic() < self.admission_until, 'recovery_original_admission_twenty_seconds')

    def directory(self, path):
        self._time()
        path = Path(path)
        need(path.is_absolute() and '..' not in path.parts, 'recovery_absolute_observed_directory')
        previous = None
        for component in [Path('/'), *list(path.parents)[::-1][1:], path]:
            if component not in self.parents:
                row = open_fd(component if previous is None else component.name,
                    os.O_RDONLY | os.O_DIRECTORY, 'original-evidence-parent',
                    dir_fd=None if previous is None else previous['fd'])
                info = os.fstat(row['fd'])
                need(stat.S_ISDIR(info.st_mode) and full9(info) == full9(component.lstat()),
                     'recovery_same_named_held_directory')
                self.parents[component] = (row, full9(info)[:5])
            row, expected = self.parents[component]
            need(full9(os.fstat(row['fd']))[:5] == full9(component.lstat())[:5] == expected,
                 'recovery_same_original_parent_identity')
            previous = row
        return previous

    def read(self, path, maximum, *, size=None, public_sha=None, metadata_only=False):
        self._time()
        path = Path(path)
        need(path not in self.regular, 'recovery_read_original_file_once')
        parent = self.directory(path.parent)
        row = open_fd(path.name, os.O_RDONLY, 'original-evidence-file', dir_fd=parent['fd'])
        before = os.fstat(row['fd'])
        need(stat.S_ISREG(before.st_mode) and before.st_uid == 501 and before.st_gid == 20
             and before.st_nlink == 1 and stat.S_IMODE(before.st_mode) == 0o600
             and 0 < before.st_size <= maximum and (size is None or before.st_size == size)
             and full9(before) == full9(path.lstat()), 'recovery_original_private_regular_file')
        self.regular[path] = (row, full9(before))
        if metadata_only:
            need(public_sha is None and path in (PKI / 'ca.key', PKI / 'server.key'),
                 'recovery_private_key_metadata_only')
            return None
        raw = bytearray()
        while len(raw) <= before.st_size:
            self._time()
            part = os.read(row['fd'], min(65536, before.st_size + 1 - len(raw)))
            if not part:
                break
            raw.extend(part)
        need(len(raw) == before.st_size and full9(before) == full9(os.fstat(row['fd'])) == full9(path.lstat()),
             'recovery_original_complete_generation_read')
        if public_sha is not None:
            need(hashlib.sha256(raw).hexdigest() == public_sha, 'recovery_original_public_source_pin')
        return bytes(raw)

    def check(self):
        remaining()
        for path, (row, expected) in self.parents.items():
            need(full9(os.fstat(row['fd']))[:5] == full9(path.lstat())[:5] == expected,
                 'recovery_original_held_parent_unchanged')
        for path, (row, expected) in self.regular.items():
            need(full9(os.fstat(row['fd'])) == full9(path.lstat()) == expected,
                 'recovery_original_held_file_unchanged')
        for path, expected in self.immutable_directories.items():
            row = self.parents[path][0]
            need(full9(os.fstat(row['fd'])) == full9(path.lstat()) == expected,
                 'recovery_closed_original_journal_directory_unchanged')
        for path, expected in self.current_directories.items():
            row = self.parents[path][0]
            need(full9(os.fstat(row['fd']))[:5] == full9(path.lstat())[:5] == expected,
                 'recovery_observed_published_data_directory_identity')
        need(not (self.CUSTODY / 'event-0014.private.json').exists()
             and not (self.CUSTODY / 'event-0014.private.json').is_symlink(),
             'recovery_no_later_original_event')

    def admit(self):
        request = json.loads(self.read(self.JOB / 'request.json', 524288, size=248444,
            public_sha='541a526c1aac1a0ab8974cd897421b2e457c079fb01d8b55b7e2d7d28a6b0762'))
        need(request.get('job_id') == self.JOB.name and request.get('job_dir') == str(self.JOB)
             and request.get('executable') == str(PYTHON) and request.get('timeout_seconds') == 630
             and request.get('args', [])[:4] == ['-I', '-S', '-B', '-c'] and len(request['args']) == 5
             and len(request['args'][4].encode()) == 242236
             and hashlib.sha256(request['args'][4].encode()).hexdigest()
                 == '0399270ee35c5c47d3431e263d9a338028393c1b4ebf09babbb23d9fa7923752',
             'recovery_exact_original_request_and_source')
        original = json.loads(self.read(self.JOB / 'stdout.log', 16384, size=10618,
            public_sha='05c2f864b2f6e72a8afacbbe622e55639d39a9850bdf3bffa475674927ff7ded'))
        need(original.get('ok') is False and original.get('errorCode') == 'fixture_original_t5_mutable_directory'
             and original.get('nodePhases') == [] and original.get('nodeBusinessOutcomeUnknown') is False
             and original.get('allOriginalServersClosed') is True
             and original.get('allExplicitDescriptorsClosedOnce') is True
             and original.get('commands', {}).get('allOwnedCommandsStopped') is True
             and original.get('commands', {}).get('unknownCommandCount') == 0
             and original.get('volumeClosure', {}).get('allDescriptorsClosed') is True
             and original.get('volumeClosure', {}).get('lastAnchorCheckPassed') is True
             and len(original.get('apiPhases', [])) == 1, 'recovery_original_failed_closed_attempt')
        requests = original['apiPhases'][0]['requests']
        need(len(requests) == 2 and [r.get('routeCategory') for r in requests] == ['health', 'init']
             and [r.get('status') for r in requests] == [501, 200]
             and all(r.get('dispatched') is True and r.get('responseComplete') is True
                     and r.get('responsePrivatelyDurable') is True and r.get('socketsClosed') is True
                     and r.get('outcomeUnknown') is False for r in requests),
             'recovery_original_once_init_known_complete')
        custody = self.directory(self.CUSTODY)
        self.immutable_directories[self.CUSTODY] = full9(os.fstat(custody['fd']))
        categories = ['crypto-intent', 'crypto-result'] * 4 + ['server-start-intent',
            'api-request-intent', 'api-request-result', 'api-request-intent', 'api-request-result', 'server-stop-result']
        packets = []
        for ordinal, category in enumerate(categories):
            value = json.loads(self.read(self.CUSTODY / ('event-%04d.private.json' % ordinal), 65536))
            need(set(value) == {'category', 'value'} and value['category'] == category,
                 'recovery_original_fourteen_event_sequence')
            packets.append(value['value'])
        need(packets[10] == requests[0] and packets[12] == requests[1]
             and packets[13].get('phase') == 'initial' and packets[13].get('cleanup', {}).get('ok') is True,
             'recovery_original_request_and_retirement_receipts')
        initialized = json.loads(self.read(self.CUSTODY / 'initial-002.response.private.bin', 16384))
        keys = initialized.get('keys_base64')
        need(type(initialized.get('root_token')) is str and 8 <= len(initialized['root_token']) <= 16384
             and type(keys) is list and len(keys) == 1 and type(keys[0]) is str and 8 <= len(keys[0]) <= 16384,
             'recovery_original_private_init_material')
        self.private_init = (initialized['root_token'], keys[0])
        for ordinal, path in enumerate((ROOT, ROOT / 'data', ROOT / 'log')):
            row = self.directory(path)
            info = os.fstat(row['fd'])
            need(info.st_dev == 16777244 and info.st_ino == self.DIRECTORY_INODES[ordinal]
                 and info.st_uid == 501 and info.st_gid == 20 and stat.S_IMODE(info.st_mode) == 0o700,
                 'recovery_preflight_observed_current_directory_identity')
            self.current_directories[path] = full9(info)[:5]
        for path in (INPUT / 'initial-plan.private.json', INPUT / 'cold-plan.private.json',
                     INPUT / 'coordinator-role-id', INPUT / 'coordinator-secret-id',
                     INPUT / 'producer-role-id', INPUT / 'producer-secret-id', RESULTS / 'initial-state.private.json'):
            need(not path.exists() and not path.is_symlink(), 'recovery_no_prior_node_plan_or_role')
        for path in (STATE / 'coordinator', STATE / 'producer', RESULTS):
            row = self.directory(path)
            need(os.listdir(row['fd']) == [], 'recovery_original_undispatched_state_empty')
        self.check(); self._time(); self.admitted = True
        return self.private_init

    def public(self):
        return {'schema': 'heptabao.fixed-slot-original-init-recovery-admission.r2',
            'originalJob': self.JOB.name, 'originalAttemptStillFailed': True,
            'originalRequestAndStdoutWholePinsChecked': self.admitted,
            'originalFourteenEventsChecked': self.admitted,
            'originalOnlyInitKnown200AndPrivatelyDurable': self.admitted,
            'originalNodeAndUnsealNotDispatched': self.admitted,
            'publishedDirectoryIdentityFromKnownReadonlyPreflight': self.admitted,
            'originalPreInitInodeNotClaimed': True, 'newInitializationForbidden': True,
            'oldPrivateValuesOrDigestsPublished': False}
