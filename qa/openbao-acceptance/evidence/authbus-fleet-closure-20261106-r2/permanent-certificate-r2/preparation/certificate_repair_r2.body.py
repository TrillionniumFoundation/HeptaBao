def read_held(parent, name, maximum, *, mode=0o600):
    row = open_fd(name, os.O_RDONLY, 'bounded-existing-input', dir_fd=parent)
    try:
        info = os.fstat(row['fd'])
        need(stat.S_ISREG(info.st_mode) and info.st_uid == 501 and info.st_gid == 20
             and info.st_nlink == 1 and stat.S_IMODE(info.st_mode) == mode
             and 0 <= info.st_size <= maximum, 'certificate_existing_regular_private_file')
        raw = bytearray()
        while True:
            remaining()
            part = os.read(row['fd'], min(65536, maximum + 1 - len(raw)))
            if not part:
                break
            raw.extend(part)
            need(len(raw) <= maximum, 'certificate_input_bound')
        need(len(raw) == info.st_size and full9(info) == full9(os.fstat(row['fd']))
             == full9(os.stat(name, dir_fd=parent, follow_symlinks=False)), 'certificate_same_input_generation')
        return bytes(raw), full9(info)
    finally:
        close(row)

def strict_memory_handshake(ca_pem, certificate):
    """Actual native SSL with no network socket or application bytes."""
    client_context = ssl.create_default_context(cadata=ca_pem.decode('ascii'))
    need(client_context.verify_mode == ssl.CERT_REQUIRED and client_context.check_hostname
         and client_context.verify_flags & ssl.VERIFY_X509_STRICT, 'native_default_strict_context_required')
    server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_context.load_cert_chain(str(certificate), str(ROOT / 'tls/server.key'))
    client_in, client_out, server_in, server_out = (ssl.MemoryBIO() for _ in range(4))
    client = client_context.wrap_bio(client_in, client_out, server_hostname='localhost')
    server = server_context.wrap_bio(server_in, server_out, server_side=True)
    done = [False, False]
    total = 0
    result = {'verifyFlags': int(client_context.verify_flags), 'certificateRequired': True,
              'hostnameChecked': True, 'networkSockets': 0, 'applicationBytes': 0, 'handshakeComplete': False}
    try:
        for _ in range(128):
            remaining()
            for ordinal, connection in enumerate((client, server)):
                if not done[ordinal]:
                    try:
                        connection.do_handshake()
                        done[ordinal] = True
                    except ssl.SSLWantReadError:
                        pass
            for output, target in ((client_out, server_in), (server_out, client_in)):
                block = output.read(65536)
                total += len(block)
                need(total <= 1048576, 'memory_tls_transcript_bound')
                if block:
                    need(target.write(block) == len(block), 'memory_tls_complete_transfer')
            if all(done):
                result.update(handshakeComplete=True, tlsVersion=client.version(),
                    leafDerSha256=hashlib.sha256(client.getpeercert(binary_form=True)).hexdigest())
                return result
        raise Refused('memory_tls_iteration_bound')
    except ssl.SSLCertVerificationError as error:
        result.update(errorType=type(error).__name__, verifyCode=error.verify_code)
        return result
    finally:
        # SSLObject/MemoryBIO own memory only; no socket/FD is opened by this probe.
        client = server = None

def main():
    global CONTROL_SIGNALS
    os.umask(0o077)
    sys.dont_write_bytecode = True
    guard = operations = commands = signals = None
    try:
        need(sys.platform == 'darwin' and os.getuid() == 501 and os.getgid() == 20
             and Path(sys.executable).resolve(strict=True) == PYTHON, 'certificate_exact_native_runtime')
        for name, source in PAYLOAD['sources'].items():
            raw = source.encode()
            need(len(raw) == PAYLOAD['pins'][name]['bytes'] and hashlib.sha256(raw).hexdigest()
                 == PAYLOAD['pins'][name]['sha256'], 'certificate_complete_source_pin')
            module = types.ModuleType(Path(name).stem)
            module.__file__ = str(OPERATIONS / name)
            sys.modules[module.__name__] = module
            exec(compile(source, module.__file__, 'exec'), module.__dict__)
        from mac_owned_commands_r1 import Commands, Signals
        from mac_production_t5_guard_r1 import HeldT5
        from mac_public_code_pin_excerpt_r1 import public_code_pin
        signals = Signals(); signals.install(); commands = Commands(signals)
        CONTROL_SIGNALS = signals
        tool_pins = {}
        for path, expected in TOOL_PINS.items():
            value = public_code_pin(path, remaining=remaining, critical=signals.critical)
            need((value['bytes'], value['sha256']) == expected, 'certificate_exact_native_tool')
            tool_pins[path] = value
        anchor = {'schema': 'heptabao.mac-current-t5-public-anchor.r1',
            'source_inventory_sha256': hashlib.sha256(encoded(PAYLOAD['pins'])).hexdigest(),
            'volumeUUID': 'FB804D1B-24CB-4D6E-AEA7-A9E180807758',
            'expectedVolumeDevice': str(Path('/Volumes/T5').lstat().st_dev),
            'anchors': [{'path': path, 'identity': list(full9(Path(path).lstat()))} for path in ('/', '/Volumes', '/Volumes/T5')]}
        raw = encoded(anchor)
        guard = HeldT5(raw, hashlib.sha256(raw).hexdigest(), remaining, signals.critical)
        row, out, err = commands.run('certificate-t5-volume', ['/usr/sbin/diskutil', 'info', '-plist', '/Volumes/T5'],
            until=min(UNTIL, time.monotonic() + 15), maximum=262144)
        need(row['exitCode'] == 0 and not row['outcomeUnknown'] and not err, 'certificate_known_t5_volume')
        guard.accept_diskutil(out)
        need(not OPERATIONS.exists() and not OPERATIONS.is_symlink(), 'certificate_original_once_slot_absent')
        operations = PrivateOperations()
        custody_fd = next(row['fd'] for path, row, identity in operations.dirs if path == CUSTODY)
        pki = open_fd('pki', os.O_RDONLY | os.O_DIRECTORY, 'original-ca-directory', dir_fd=custody_fd)
        pki_before = full9(os.fstat(pki['fd']))
        need(pki_before == full9((CUSTODY / 'pki').lstat()) and int(pki_before[2]) == 501
             and stat.S_IMODE(int(pki_before[4])) == 0o700, 'original_ca_private_directory')
        old_slot = open_fd('bootstrap-r1', os.O_RDONLY | os.O_DIRECTORY, 'original-failed-bootstrap', dir_fd=custody_fd)
        old_slot_before = full9(os.fstat(old_slot['fd']))
        need(old_slot_before == full9((CUSTODY / 'bootstrap-r1').lstat())
             and int(old_slot_before[2]) == 501 and stat.S_IMODE(int(old_slot_before[4])) == 0o700,
             'original_failed_bootstrap_directory')
        expected_old_names = set(PAYLOAD['sources']) | {'main3_http_complete.py', 'permanent_bootstrap_api_r1.py',
            'source-pins.public.json', 'initial-config.private.json', 'initial.stdout.private.log',
            'initial.stderr.private.log'} | {'event-%04d.private.json' % i for i in range(4)}
        need(set(os.listdir(old_slot['fd'])) == expected_old_names, 'original_bootstrap_exact_pre_init_records')
        records = [json.loads(read_held(old_slot['fd'], 'event-%04d.private.json' % i, 65536)[0]) for i in range(4)]
        need([x['category'] for x in records] == ['server-start-intent', 'api-request-intent', 'api-request-result', 'server-stop-result'],
             'original_bootstrap_no_init_intent')
        first = records[2]['value']; cleanup = records[3]['value']['cleanup']
        need(first['case'] == 'initial.health' and first['dispatched'] is False and first['httpRequestCount'] == 0
             and first['outcomeUnknown'] is False and first['errorType'] == 'SSLCertVerificationError'
             and first['socketsClosed'] is True and first['responseReaderClosed'] is True,
             'original_failed_health_known_not_dispatched')
        need(cleanup['pid'] == 68581 and cleanup['ok'] is True and cleanup['directChildReaped'] is True
             and cleanup['allGroupRowsEmptyAfterReap'] is True and cleanup['outcomeUnknown'] is False,
             'original_bootstrap_server_known_closed')
        REPORT['originalBootstrapKnownNoHttpNoInitAndServerClosed'] = True
        public_pins = {'server.csr': (1086, '78fc22d846323cd48e2a4d258f68ef5f7a3a54423ad692fa88b37161cfaadc53'),
            'server.cnf': (317, '9b747a9d6cc292d8c5e8d14b48d6c0b1f9705fb4da2eeac91d540455b5d796f4')}
        protected = {}
        for name, expected in public_pins.items():
            data = guard.read(ROOT / 'tls' / name, 16384)
            need((len(data), hashlib.sha256(data).hexdigest()) == expected, 'original_public_signing_input_pin')
            protected[ROOT / 'tls' / name] = full9((ROOT / 'tls' / name).lstat())
        ca, ca_identity = read_held(pki['fd'], 'ca.crt', 16384)
        need(hashlib.sha256(ssl.PEM_cert_to_DER_cert(ca.decode('ascii'))).hexdigest() == CA_SHA,
             'original_independent_ca_der_pin')
        protected[CUSTODY / 'pki/ca.crt'] = ca_identity
        for name, expected in (('ca.crt', CA_SHA), ('server.crt', LEAF_SHA)):
            data = guard.read(ROOT / 'tls' / name, 16384)
            need(hashlib.sha256(ssl.PEM_cert_to_DER_cert(data.decode('ascii'))).hexdigest() == expected,
                 'original_public_certificate_der_pin')
            protected[ROOT / 'tls' / name] = full9((ROOT / 'tls' / name).lstat())
        for path in (CUSTODY / 'pki/ca.key', ROOT / 'tls/server.key'):
            info = path.lstat()
            need(stat.S_ISREG(info.st_mode) and info.st_uid == 501 and info.st_gid == 20
                 and info.st_nlink == 1 and stat.S_IMODE(info.st_mode) == 0o600 and 0 < info.st_size <= 16384,
                 'original_private_key_metadata_only')
            protected[path] = full9(info)
        def fence():
            guard.check(); operations.check(); remaining()
            need(full9(os.fstat(pki['fd'])) == full9((CUSTODY / 'pki').lstat()) == pki_before,
                 'original_ca_directory_unchanged')
            need(full9(os.fstat(old_slot['fd'])) == full9((CUSTODY / 'bootstrap-r1').lstat()) == old_slot_before,
                 'original_bootstrap_records_unchanged')
            for path, identity in protected.items():
                need(full9(path.lstat()) == identity, 'original_certificate_inputs_unchanged')
        fence()
        original_tls = strict_memory_handshake(ca, ROOT / 'tls/server.crt')
        REPORT['originalLeafNativeDefaultStrictTls'] = original_tls
        need(original_tls['handshakeComplete'] is False and original_tls.get('verifyCode') == 85,
             'original_missing_authority_key_identifier_reproduced')
        fence()
        extension = b'[server]\nbasicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid:always,issuer\nsubjectAltName=DNS:MacBook-Pro.local,DNS:localhost,IP:192.168.0.8,IP:127.0.0.1,IP:10.77.0.3,IP:100.77.61.24\n'
        guard.write_new(ROOT / 'tls/server-r2.cnf', extension)
        new_leaf = ROOT / 'tls/server-r2.crt'
        need(not new_leaf.exists() and not new_leaf.is_symlink(), 'new_leaf_name_absent')
        serial = '0x' + os.urandom(16).hex()
        argv = ['/usr/bin/openssl', 'x509', '-req', '-in', str(ROOT / 'tls/server.csr'),
            '-CA', str(CUSTODY / 'pki/ca.crt'), '-CAkey', str(CUSTODY / 'pki/ca.key'),
            '-set_serial', serial, '-days', '365', '-sha256', '-extfile', str(ROOT / 'tls/server-r2.cnf'),
            '-extensions', 'server', '-out', str(new_leaf)]
        operations.write('sign-intent.private.json', encoded({'argv': argv, 'state': 'dispatched_or_unknown'}))
        fence()
        row, out, err = commands.run('sign-corrected-public-leaf-once', argv,
            until=min(UNTIL, time.monotonic() + 30), maximum=262144)
        operations.write('sign-completion.private.json', encoded(row))
        need(row['exitCode'] == 0 and not row['outcomeUnknown'], 'corrected_leaf_sign_known_complete')
        with guard.parent(new_leaf) as (parent, name):
            file = open_fd(name, os.O_RDONLY, 'corrected-certificate-sync', dir_fd=parent)
            os.fsync(file['fd']); os.fsync(parent); close(file)
        leaf = guard.read(new_leaf, 16384)
        leaf_sha = hashlib.sha256(ssl.PEM_cert_to_DER_cert(leaf.decode('ascii'))).hexdigest()
        need(leaf_sha != LEAF_SHA, 'new_leaf_distinct_from_original')
        protected[new_leaf] = full9(new_leaf.lstat())
        fence()
        corrected_tls = strict_memory_handshake(ca, new_leaf)
        REPORT['correctedLeafNativeDefaultStrictTls'] = corrected_tls
        need(corrected_tls['handshakeComplete'] is True and corrected_tls['leafDerSha256'] == leaf_sha,
             'corrected_leaf_actual_native_strict_tls_passed')
        fence()
        for filename, expected_address in (('server-bootstrap.json', '127.0.0.1:31080'), ('server.json', '192.168.0.8:31080')):
            old_config = guard.read(ROOT / 'etc' / filename, 16384)
            config = json.loads(old_config)
            expected = {'listen': expected_address, 'data_dir': str(ROOT / 'data'),
                'audit_file': str(ROOT / 'log/audit.jsonl'), 'tls_cert_file': str(ROOT / 'tls/server.crt'),
                'tls_key_file': str(ROOT / 'tls/server.key'), 'max_connections': 64, 'timeout_seconds': 15,
                'rate_limit_per_second': 2000, 'rate_limit_burst': 4000, 'rate_limit_entries': 512,
                'storage': {'native_v6_file': {'path': str(ROOT / 'data')}}}
            need(config == expected, 'original_staged_configuration_exact')
            config['tls_cert_file'] = str(new_leaf)
            guard.write_new(ROOT / 'etc' / filename.replace('.json', '-r2.json'), encoded(config))
        with guard.parent(ROOT / 'data') as (parent, name):
            data_fd = open_fd(name, os.O_RDONLY | os.O_DIRECTORY, 'uninitialized-store-metadata', dir_fd=parent)
            before = full9(os.fstat(data_fd['fd']))
            entries = os.listdir(data_fd['fd'])
            need(len(entries) <= 128 and before == full9(os.fstat(data_fd['fd']))
                 == full9((ROOT / 'data').lstat()), 'uninitialized_store_metadata_stable')
            REPORT['existingDataEntryCount'] = len(entries)
            REPORT['existingDataDirectoryEmpty'] = not entries
            operations.write('existing-data-names.private.json', encoded(entries))
            close(data_fd)
        fence()
        for path, expected in tool_pins.items():
            need(public_code_pin(path, remaining=remaining, critical=signals.critical) == expected,
                 'native_tools_unchanged')
        REPORT.update(ok=True, sameIndependentCaDerSha256=CA_SHA, correctedLeafDerSha256=leaf_sha,
            originalCertificateAndKeysUnchanged=True, correctedPublicCertificateSaved=True,
            twoCorrectedConfigurationsCreated=True, serviceOrDataFilesModified=False)
    except BaseException as error:
        REPORT['errorType'] = type(error).__name__
        REPORT['errorCode'] = str(error) if isinstance(error, Refused) and re.fullmatch(r'[a-z0-9._-]{1,120}', str(error)) else 'certificate_correction_failed_no_replay'
    finally:
        if guard is not None:
            guard.close()
            REPORT['volumeClosure'] = guard.public_state()
        errors = []
        for row in reversed(FDS):
            try:
                close(row)
            except BaseException as error:
                errors.append(type(error).__name__)
        REPORT['descriptorCloseErrors'] = errors
        REPORT['explicitDescriptors'] = len(FDS)
        REPORT['allExplicitDescriptorsClosedOnce'] = all(row['attempts'] == 1 and row['closed'] for row in FDS)
        REPORT['commands'] = commands.public() if commands is not None else {'allOwnedCommandsStopped': True, 'unknownCommandCount': 0, 'commands': []}
        REPORT['deadlineAfterClosure'] = time.monotonic() < UNTIL
        REPORT['cancellationObserved'] = CONTROL_SIGNALS is not None and CONTROL_SIGNALS.pending is not None
        REPORT['ok'] = bool(REPORT['ok'] and not errors and REPORT['allExplicitDescriptorsClosedOnce']
            and REPORT['commands']['allOwnedCommandsStopped'] and REPORT['commands']['unknownCommandCount'] == 0
            and REPORT['deadlineAfterClosure'] and not REPORT['cancellationObserved']
            and REPORT.get('volumeClosure', {}).get('lastAnchorCheckPassed') and REPORT['volumeClosure']['allDescriptorsClosed'])
        REPORT['elapsedSeconds'] = time.monotonic() - START
        print(json.dumps(REPORT, sort_keys=True), flush=True)
    return 0 if REPORT['ok'] else 1

if __name__ == '__main__':
    raise SystemExit(main())
